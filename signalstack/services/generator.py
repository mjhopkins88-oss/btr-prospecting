"""
Message generation pipeline.

Fixes vs. previous version:
  * Generation no longer hard-fails when there are no signals — it works
    from any combination of signals, notes, profile context, or even an
    inline LinkedIn profile paste.
  * Accepts an inline `profile_override` so the user can paste profile
    text without persisting it.
  * Accepts user `instruction` and `strategy` overrides.
  * Returns rich grounding metadata per candidate.
  * Always returns a structured `error` instead of raising.
"""
from typing import Optional

from .. import repo
from ..ai.provider import get_provider
from ..grounding import validate_message, filter_safe_signals
from ..knowledge import repo as knowledge_repo
from ..serialization import to_json_safe
from . import strategy as strategy_engine
from .signal_interpreter import interpret_signals
from .anti_copy import check_message as anti_copy_check, shorten as anti_copy_shorten
from .input_quality_scorer import score_inputs
from .context_expansion import expand_context
from .observation_distiller import distill as distill_observations
from .message_angle_planner import plan as plan_angles
from .anti_generic_validator import validate as anti_generic_validate
from .naturalness_validator import validate as naturalness_validate
from . import playbook_loader
from . import insight_engine
from . import thought_translator
from . import message_critic
from . import reasoning_pipeline


def _classify_message_basis(candidate: dict, distilled: list[dict]) -> str:
    """
    Label a candidate as signal-based, observation-based, or
    hypothesis-based so the UI can communicate how strong the
    grounding is.

    Priority:
      * signal_based       — candidate references at least one real
                             signal ID or note ID
      * observation_based  — anchored on profile / distilled observation
                             drawn from non-hypothesis sources
      * hypothesis_based   — anchored on a context_expansion hypothesis
    """
    if (candidate.get("signal_ids") or []) or (candidate.get("notes_used") or []):
        return "signal_based"
    # If the candidate claims hypothesis basis explicitly, respect it.
    if candidate.get("low_context") or candidate.get("message_basis") == "hypothesis_based":
        # Determine whether the distilled observation pool has any real
        # (non-hypothesis) content. If yes, we prefer the observation
        # label; if not, this really is hypothesis-based.
        any_real = any(
            (o.get("source") or "") != "hypothesis" for o in distilled or []
        )
        return "observation_based" if any_real else "hypothesis_based"
    if candidate.get("profile_fields_used"):
        return "observation_based"
    # Fallback: if we have any non-hypothesis distilled observation,
    # call it observation_based, otherwise hypothesis_based.
    any_real = any(
        (o.get("source") or "") != "hypothesis" for o in distilled or []
    )
    return "observation_based" if any_real else "hypothesis_based"


def _clean_playbook_entry(entry: Optional[dict]) -> dict:
    """Project a raw ``ss_playbook_entries`` row down to the safe fields we
    attach to generator output. Raw rows may contain Postgres-typed
    values (datetime, Decimal, memoryview); ``to_json_safe`` normalizes
    the remaining primitives defensively.

    Used for the TOP-LEVEL ``playbook.entries`` block where full detail
    is needed for the playbook inspection UI. For per-candidate refs
    use ``_ref_playbook_entry`` instead — it drops the heavy text
    fields so we don't duplicate the same entries across every
    candidate.
    """
    if not entry:
        return {}
    return to_json_safe({
        "id": entry.get("id"),
        "category": entry.get("category"),
        "title": entry.get("title"),
        "description": entry.get("description"),
        "when_to_use": entry.get("when_to_use"),
        "message_angles": entry.get("message_angles") or [],
        "confidence": entry.get("confidence"),
    })


def _ref_playbook_entry(entry: Optional[dict]) -> dict:
    """Compact per-candidate reference for a playbook entry.

    The UI only needs ``{category, title}`` per candidate to render
    the "Playbook entries used" trail, plus ``id`` so the full row
    can be resolved from the top-level ``playbook.entries`` block.
    Dropping description/when_to_use/message_angles shrinks each
    per-candidate entry from ~500 bytes to ~100 bytes, which matters
    once we ship n candidates × N playbook entries.
    """
    if not entry:
        return {}
    return to_json_safe({
        "id": entry.get("id"),
        "category": entry.get("category"),
        "title": entry.get("title"),
    })


def _clean_knowledge_entry(entry: Optional[dict]) -> dict:
    """Project a raw ``ss_knowledge_entries`` row down to the safe fields
    we attach to generator output.

    Used for the TOP-LEVEL ``knowledge.entries`` block. For
    per-candidate refs use ``_ref_knowledge_entry``.
    """
    if not entry:
        return {}
    return to_json_safe({
        "id": entry.get("id"),
        "source_id": entry.get("source_id"),
        "category": entry.get("category"),
        "principle_name": entry.get("principle_name"),
        "confidence": entry.get("confidence"),
    })


def _ref_knowledge_entry(entry: Optional[dict]) -> dict:
    """Compact per-candidate reference for a knowledge entry.

    The UI renders ``[category] principle_name`` for the first four
    per candidate; we keep just those fields plus ``id`` so the full
    entry can be resolved from the top-level ``knowledge.entries``
    block. Drops ``source_id`` and ``confidence`` to keep the
    per-candidate payload small when 20+ entries are active.
    """
    if not entry:
        return {}
    return to_json_safe({
        "id": entry.get("id"),
        "category": entry.get("category"),
        "principle_name": entry.get("principle_name"),
    })


def _merge_profile(stored: Optional[dict], override: Optional[dict]) -> dict:
    """Inline overrides take precedence over stored profile context."""
    out = dict(stored or {})
    for k, v in (override or {}).items():
        if v not in (None, ""):
            out[k] = v
    return out


def build_context(
    prospect_id: str,
    profile_override: Optional[dict] = None,
    minimal: bool = False,
) -> Optional[dict]:
    prospect = repo.get_prospect(prospect_id)
    if not prospect:
        return None

    signals = filter_safe_signals(repo.list_signals_for_prospect(prospect_id))

    company = None
    if prospect.get("company_id"):
        company = repo.get_company(prospect["company_id"])
        signals += filter_safe_signals(
            repo.list_signals_for_company(prospect["company_id"])
        )

    notes = repo.list_notes_for_prospect(prospect_id)
    stored_profile = repo.get_profile_context(prospect_id)
    profile = _merge_profile(stored_profile, profile_override)

    # Minimal mode: skip all optional/strategy-layer loads. The base
    # pipeline needs to be proven stable before these layers go back
    # in front of it.
    if minimal:
        principles = []
        knowledge_entries = []
    else:
        # Pull a small set of active principles for the provider to consult.
        try:
            principles = repo.list_principles(active_only=True)
        except Exception:
            principles = []

        # Pull active knowledge entries from the dataset layer. These are
        # strategy/style guidance — NOT prospect personalization. The
        # generator surfaces them as tone/framing input only.
        try:
            knowledge_entries = knowledge_repo.list_active_entries_for_generator(limit=25)
        except Exception:
            knowledge_entries = []

    # Compress every raw signal into a short observation BEFORE the
    # generator sees it. This is the key fix for the bug where long
    # listing/post bodies were being pasted directly into messages.
    observations = interpret_signals(signals)

    ctx: dict = {
        "prospect": prospect,
        "company": company,
        "signals": signals,
        "observations": observations,
        "notes": notes,
        "profile": profile,
        "principles": principles,
        # Knowledge dataset entries — strategy/style guidance only.
        # Tracked separately so we can attribute usage in metadata.
        "knowledge_entries": knowledge_entries,
    }

    # Context expansion: infer a likely operating context and produce
    # 3-5 hypotheses. This is the FIRST reasoning step in the new
    # graded pipeline — the rest of the stages read it off the
    # context. Never raises; always returns a usable dict.
    try:
        ctx["context_expansion"] = expand_context(ctx)
    except Exception as e:
        print(
            f"[SignalStack] build_context: context_expansion FAILED — "
            f"continuing without: {type(e).__name__}: {e}"
        )
        ctx["context_expansion"] = {
            "hypotheses": [],
            "confidence_level": "low",
            "confidence_score": 0.0,
            "inferred_role_family": "unknown",
            "inferred_market": "unknown",
            "inferred_activity": "unknown",
            "basis_counts": {},
        }

    return ctx


def _has_any_grounding(context: dict) -> bool:
    return bool(
        (context.get("signals") or [])
        or (context.get("notes") or [])
        or (context.get("profile") or {})
        or (context.get("prospect") or {}).get("notes")
    )


def generate(
    prospect_id: str,
    n: int = 4,
    instruction: Optional[str] = None,
    strategy_override: Optional[dict] = None,
    profile_override: Optional[dict] = None,
    minimal: bool = False,
) -> dict:
    # Stage tracker: tells the route / UI / logs which pipeline steps
    # actually ran, which were skipped (e.g. by minimal mode), and which
    # failed. Consumed by routes.py and surfaced in the response so
    # Step-2/3 stability testing can see the exact pipeline shape
    # without reading logs. Values are short status strings; a single
    # ``candidate_validation_summary`` sub-dict is also appended by the
    # candidate validation stage so the caller can see raw/accepted/
    # low_context/rejected counts without parsing the arrays.
    stages: dict = {}

    def _stage(name: str, status: str) -> None:
        stages[name] = status
        print(f"[SignalStack] generator: stage {name}={status}")

    _stage("build_context", "running")
    context = build_context(
        prospect_id,
        profile_override=profile_override,
        minimal=minimal,
    )
    if context is None:
        _stage("build_context", "prospect_not_found")
        return {
            "error": "prospect_not_found",
            "stages": stages,
            "minimal_mode": minimal,
        }
    _stage("build_context", "ok")

    # NOTE: we no longer hard-block generation when context is thin.
    # The pipeline is graded: HIGH confidence → strong specific
    # messages, MEDIUM → pattern-based, LOW → hypothesis-based. The
    # grounding_check stage is still recorded so the UI/logs can see
    # which bucket this request fell into, but it never short-circuits.
    if _has_any_grounding(context):
        _stage("grounding_check", "ok")
    else:
        _stage("grounding_check", "no_stored_grounding_running_hypothesis_path")

    # 1) Score input quality. This is now a GRADING step (confidence
    #    high/medium/low), not a gate — the generator keeps going in
    #    all cases and tags each candidate with the appropriate
    #    message_basis.
    _stage("input_quality", "running")
    quality = score_inputs(context)
    # Reflect the context_expansion confidence level onto the quality
    # dict when context is thin — expansion has more information about
    # the inferred role/market, so we prefer its judgement when the
    # scorer says "low".
    exp = context.get("context_expansion") or {}
    exp_level = (exp.get("confidence_level") or "").lower()
    if exp_level and quality.get("confidence_level") == "low" and exp_level == "medium":
        quality["confidence_level"] = "medium"
        quality.setdefault("reasons", []).append("raised_by_context_expansion")
    # Expose the quality dict on the context so the critic can read
    # confidence_level when it wasn't attached via the anti_generic
    # verdict (e.g. in tests or direct calls).
    context["input_quality"] = quality
    _stage("input_quality", f"ok:{quality.get('confidence_level')}")

    # 2) Distill 1–3 sharp observations from the raw material. The
    #    generator reasons about these — not the raw source blobs.
    _stage("observation_distill", "running")
    distilled = distill_observations(context)
    context["distilled_observations"] = distilled
    _stage("observation_distill", "ok")

    # 2.5) Load industry playbook intelligence (BTR/CRE today). This
    #      shapes angle selection, anti-pattern avoidance, and the
    #      "why this angle" trail returned to the UI. Playbook entries
    #      are NEVER copy-pasted into messages as personalization.
    #
    #      Minimal mode: skip this entire branch. The base pipeline
    #      must be provably stable before the playbook layer is put
    #      back in front of it.
    if minimal:
        _stage("playbook_load", "skipped_minimal")
        playbook_bundle = {
            "playbook": None,
            "entries": [],
            "categories": [],
            "reasoning": "skipped (minimal mode)",
        }
        pb_entries = []
        pb_preferred = []
        pb_anti_patterns = []
    else:
        _stage("playbook_load", "running")
        try:
            playbook_bundle = playbook_loader.load_relevant_entries(
                context, instruction=instruction
            )
            pb_entries = playbook_bundle.get("entries") or []
            pb_preferred = playbook_loader.preferred_angles(pb_entries)
            pb_anti_patterns = playbook_loader.collect_anti_patterns(pb_entries)
            _stage("playbook_load", "ok")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[SignalStack] generator: playbook_load FAILED — continuing without: {type(e).__name__}: {e}")
            playbook_bundle = {
                "playbook": None,
                "entries": [],
                "categories": [],
                "reasoning": f"playbook load failed ({type(e).__name__})",
            }
            pb_entries, pb_preferred, pb_anti_patterns = [], [], []
            _stage("playbook_load", "failed_soft")
    context["playbook"] = playbook_bundle
    context["playbook_anti_patterns"] = pb_anti_patterns

    # Resolve the provider up-front so the insight engine, message
    # generator, and critic all share the same instance and its
    # failure surfaces are funneled through the same error paths.
    provider = get_provider()
    provider_name = type(provider).__name__

    # 2.75) Insight Engine. Converts observations into sharpened
    #       interpretations (market patterns, timing effects, second-order
    #       effects, peer POV). This is what makes the message NOT
    #       sound like a topic-list restatement.
    #
    #       Minimal mode skips this layer entirely so the base
    #       pipeline stays provably stable. We still attach an empty
    #       insights array so downstream code has a consistent shape.
    insight_source: Optional[str] = None
    insight_error: Optional[str] = None
    if minimal:
        _stage("insight_engine", "skipped_minimal")
        context["insights"] = []
        insight_source = "skipped"
    else:
        _stage("insight_engine", "running")
        try:
            insight_result = insight_engine.generate_insights(
                context, provider=provider,
            )
            context["insights"] = insight_result.get("insights") or []
            insight_source = insight_result.get("source")
            insight_error = insight_result.get("error")
            _stage("insight_engine", insight_source or "heuristic")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(
                f"[SignalStack] generator: insight_engine FAILED — continuing "
                f"without insights: {type(e).__name__}: {e}"
            )
            context["insights"] = []
            insight_source = "heuristic"
            insight_error = f"insight_engine_failed:{type(e).__name__}"
            _stage("insight_engine", "failed_soft")

    # 2.8) Thought Translation Layer. Converts each insight into a
    #      plain-language peer-voice "internal thought" before the
    #      generator is allowed to see it. This is the last-mile fix
    #      for the failure mode where messages stitched profile
    #      keywords / CRM tags into the final output even when the
    #      upstream insights were correct. The generator is then told
    #      (via generate_user.txt) to write ONLY from the internal
    #      thought and never to reuse raw input keywords.
    thought_source: Optional[str] = None
    thought_error: Optional[str] = None
    if minimal:
        _stage("thought_translation", "skipped_minimal")
        context["internal_thoughts"] = []
        thought_source = "skipped"
    else:
        _stage("thought_translation", "running")
        try:
            translation_result = thought_translator.translate_insights(
                context, provider=provider,
            )
            context["internal_thoughts"] = (
                translation_result.get("thoughts") or []
            )
            thought_source = translation_result.get("source")
            thought_error = translation_result.get("error")
            _stage("thought_translation", thought_source or "heuristic")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(
                f"[SignalStack] generator: thought_translator FAILED — "
                f"continuing without thoughts: {type(e).__name__}: {e}"
            )
            context["internal_thoughts"] = []
            thought_source = "heuristic"
            thought_error = f"thought_translator_failed:{type(e).__name__}"
            _stage("thought_translation", "failed_soft")

    # 3) Plan distinct angles for the options. Weak-input cases get
    #    restricted to low-pressure / networking angles only. The
    #    reasoning_pipeline wraps plan_angles and annotates each
    #    strategy with a short "why this angle" trail driven by the
    #    strongest signal type + top insight type.
    strategies = reasoning_pipeline.run_strategy_selection(
        context,
        quality=quality,
        n=n,
        strategy_override=strategy_override,
        playbook_preferred_angles=pb_preferred or None,
        stage_recorder=_stage,
    )
    print(
        f"[SignalStack] generator: calling provider={provider_name} "
        f"n={n} strategies={len(strategies or [])} "
        f"signals={len(context.get('signals') or [])} "
        f"has_instruction={bool(instruction)} minimal={minimal}"
    )
    _stage("provider_call", "running")
    raw = None
    try:
        try:
            raw = provider.generate_messages(
                context, n=n,
                strategies=strategies,
                instruction=instruction,
            )
        except TypeError:
            # Backwards compat with older provider signatures.
            raw = provider.generate_messages(context, n=n)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(
            f"[SignalStack] generator: provider={provider_name} "
            f"call FAILED at stage=provider_call err={type(e).__name__}: {e}"
        )
        _stage("provider_call", "failed")
        return {
            "candidates": [],
            "rejected": [],
            "error": "provider_failed",
            "stage": "provider_call",
            "provider": provider_name,
            "message": f"AI provider error ({type(e).__name__}): {e}",
            "stages": stages,
            "minimal_mode": minimal,
        }
    _stage("provider_call", "ok")
    print(
        f"[SignalStack] generator: provider={provider_name} returned "
        f"{len(raw or [])} raw candidates"
    )

    # The provider may return a JSON string (Claude) or a pre-parsed list
    # (mock). Normalize to a list[dict] here so downstream code is safe.
    # Both stages are logged and wrapped so a parse failure returns a
    # structured error instead of a hard 500.
    if isinstance(raw, (str, bytes, bytearray)):
        _stage("provider_response_parse", "running")
        print("[SignalStack] generator: parsing provider JSON response")
        try:
            import json as _json
            raw = _json.loads(raw)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(
                f"[SignalStack] generator: JSON parse FAILED at "
                f"stage=provider_response_parse err={type(e).__name__}: {e}"
            )
            _stage("provider_response_parse", "failed")
            return {
                "candidates": [],
                "rejected": [],
                "error": "provider_response_parse_failed",
                "stage": "provider_response_parse",
                "provider": provider_name,
                "message": f"Could not parse provider JSON response ({type(e).__name__}): {e}",
                "stages": stages,
                "minimal_mode": minimal,
            }
        _stage("provider_response_parse", "ok")
        print("[SignalStack] generator: parsed provider JSON response OK")
    else:
        _stage("provider_response_parse", "skipped_not_string")

    # Claude may return `{"messages": [...]}` instead of a bare list.
    # Unwrap that here before the type check.
    if isinstance(raw, dict) and isinstance(raw.get("messages"), list):
        raw = raw["messages"]

    if raw is not None and not isinstance(raw, list):
        print(
            f"[SignalStack] generator: provider returned unexpected type "
            f"{type(raw).__name__}; coercing to empty list"
        )
        _stage("provider_response_shape", "failed")
        return {
            "candidates": [],
            "rejected": [],
            "error": "provider_response_invalid",
            "stage": "provider_response_shape",
            "provider": provider_name,
            "message": (
                f"Provider returned {type(raw).__name__}, expected list of candidates."
            ),
            "stages": stages,
            "minimal_mode": minimal,
        }
    _stage("provider_response_shape", "ok")

    # Build the raw source corpus the anti-copy validator compares
    # messages against. We include every raw signal body, note body,
    # and pasted profile blob — these are the texts the generator is
    # *forbidden* from copying into the final output.
    raw_sources: list[str] = []
    for s in context.get("signals") or []:
        if s.get("text"):
            raw_sources.append(s["text"])
    for note in context.get("notes") or []:
        if note.get("body"):
            raw_sources.append(note["body"])
    prof = context.get("profile") or {}
    for k in ("about_text", "headline", "featured_topics"):
        if prof.get(k):
            raw_sources.append(prof[k])

    # Pre-compute the active knowledge entries used as strategy guidance
    # for this generation run. Every candidate inherits the same set
    # because knowledge is generation-context, not personalization.
    #
    # IMPORTANT: we deliberately project each raw DB row down to a small
    # set of primitives. Raw rows coming back from Postgres can contain
    # datetime/Decimal/memoryview values that are not JSON-serializable
    # and previously crashed the response path with a 500.
    #
    # Two projections:
    #  * ``knowledge_entry_summaries`` — full-ish fields for the
    #    top-level ``knowledge.entries`` block (UI detail view).
    #  * ``knowledge_entry_refs`` — compact per-candidate refs (just
    #    id/category/principle_name). This is the list that gets
    #    duplicated across every candidate, so it must stay small.
    knowledge_entries = context.get("knowledge_entries") or []
    knowledge_entry_summaries = [
        _clean_knowledge_entry(e) for e in knowledge_entries
    ]
    knowledge_entry_refs = [
        _ref_knowledge_entry(e) for e in knowledge_entries
    ]
    knowledge_source_ids_used = sorted({
        str(e.get("source_id")) for e in knowledge_entries if e.get("source_id")
    })
    knowledge_entry_ids_used = [
        str(e.get("id")) for e in knowledge_entries if e.get("id")
    ]

    _stage("candidate_validation", "running")
    candidates, rejected, low_context_candidates = [], [], []
    # Fallback "facts" list we can attach to hypothesis-based candidates
    # so the grounding validator has something non-empty to count. This
    # is purely metadata — the actual message body never references
    # these fields as if they were personalization.
    fallback_facts: list[str] = []
    pros = context.get("prospect") or {}
    for f in ("title", "company_name", "location", "industry"):
        if pros.get(f):
            fallback_facts.append(f)
    for cand in raw or []:
        body = cand.get("body", "") or ""

        # 1) Anti-copy: auto-shorten, then check for raw-source overlap.
        if len(body) > 450:
            body = anti_copy_shorten(body, target=320)
            cand["body"] = body
        anti = anti_copy_check(body, raw_sources)
        cand["anti_copy"] = anti

        # If this is a hypothesis-based candidate with no grounding
        # hooks, backfill ``facts_used`` with the prospect-level facts
        # that are already known. This is NOT personalization — it
        # just lets the downstream grounding validator see that the
        # message is tied to a real prospect record.
        is_hyp = (
            cand.get("message_basis") == "hypothesis_based"
            or cand.get("low_context")
        )
        if is_hyp and not (
            cand.get("signal_ids") or cand.get("notes_used")
            or cand.get("profile_fields_used") or cand.get("facts_used")
        ):
            cand["facts_used"] = list(fallback_facts)

        # 2) Grounding: banned phrases, fake familiarity, etc.
        verdict = validate_message(
            body=body,
            signals_used=cand.get("signal_ids") or [],
            facts_used=cand.get("facts_used") or [],
            profile_fields_used=cand.get("profile_fields_used") or [],
        )
        cand["grounding"] = verdict

        # 3) Anti-generic validator: kills weak-fact / template openers.
        ag = anti_generic_validate(
            body=body,
            facts_used=cand.get("facts_used") or [],
            signal_ids=cand.get("signal_ids") or [],
            notes_used=cand.get("notes_used") or [],
            profile_fields_used=cand.get("profile_fields_used") or [],
            quality=quality,
        )
        cand["anti_generic"] = ag

        # 3.5) Naturalness validator. This is the last-mile gate that
        #      catches messages which stitched profile keywords / CRM
        #      tags into the final prose even when the upstream
        #      reasoning was correct. A hard comma-stack violation
        #      always fails the candidate — the generator was told to
        #      write from an internal thought, not from the profile.
        naturalness = naturalness_validate(
            body=body,
            profile=context.get("profile") or {},
        )
        cand["naturalness"] = naturalness
        cand["selected_angle"] = cand.get("angle")

        # Attach the playbook entries that informed this angle so the
        # UI can show the "why" trail. We match by angle membership.
        # Rows are projected via ``_ref_playbook_entry`` (NOT
        # ``_clean_playbook_entry``) so we only attach
        # ``{id, category, title}`` per candidate — the full row is
        # available via the top-level ``playbook.entries`` block and
        # can be resolved by id. This avoids duplicating every entry's
        # description/when_to_use across every candidate.
        angle = cand.get("angle")
        used_pb_refs: list[dict] = []
        seen_ids: set = set()
        for e in pb_entries:
            if angle and angle in (e.get("message_angles") or []):
                ref = _ref_playbook_entry(e)
                if ref.get("id") not in seen_ids:
                    used_pb_refs.append(ref)
                    seen_ids.add(ref.get("id"))
        # Always include the active anti-pattern entries — they shaped
        # what the message is *not* allowed to say.
        for e in pb_entries:
            if e.get("category") == "anti_patterns":
                ref = _ref_playbook_entry(e)
                if ref.get("id") not in seen_ids:
                    used_pb_refs.append(ref)
                    seen_ids.add(ref.get("id"))
        cand["playbook_entries_used"] = used_pb_refs
        cand["playbook_reasoning"] = (
            f"Angle '{angle}' was prioritized by the "
            f"{(playbook_bundle.get('playbook') or {}).get('name') or 'industry'} "
            f"playbook based on the loaded categories: "
            f"{', '.join((playbook_bundle.get('categories') or [])[:4])}."
            if angle else playbook_bundle.get("reasoning")
        )

        # Reject the candidate if it leaks any playbook anti-pattern phrase.
        body_low = body.lower()
        leaked = [p for p in pb_anti_patterns
                  if p and "{" not in p and p.lower() in body_low]
        if leaked:
            cand.setdefault("grounding", {}).setdefault("violations", []).extend(
                [f"playbook_anti_pattern:{p}" for p in leaked]
            )
        cand["strongest_observation_used"] = (
            (distilled[0]["text"] if distilled else None)
        )

        # Attribute knowledge usage. Knowledge entries are NOT prospect
        # personalization — they shape tone, framing, and angle choice.
        # Per-candidate we attach the COMPACT refs (id/category/
        # principle_name), NOT the full summaries. The full summaries
        # live in the top-level ``knowledge.entries`` block and the UI
        # can resolve by id when it needs more detail.
        cand["knowledge_entries_used"] = knowledge_entry_refs
        cand["knowledge_source_ids_used"] = knowledge_source_ids_used
        cand["knowledge_entry_ids_used"] = knowledge_entry_ids_used

        playbook_clean = not leaked
        # Naturalness hard-fail: a message that stacks CRM tags
        # ("X, Y, Z" style) is a hard reject — the generator was
        # explicitly told to write from an internal thought rather
        # than the profile. Soft violations (profile-summary phrases,
        # low naturalness score) are surfaced to the critic instead.
        has_comma_stack = any(
            v.startswith("comma_stack:") or v.startswith("keyword_stacking:")
            for v in (naturalness.get("violations") or [])
        )
        ok = (
            verdict["ok"]
            and anti["passes_anti_copy_check"]
            and playbook_clean
            and not has_comma_stack
        )
        if not anti["passes_anti_copy_check"]:
            verdict.setdefault("violations", []).extend(anti["violations"])
        if has_comma_stack:
            verdict.setdefault("violations", []).extend(
                [v for v in naturalness.get("violations") or []
                 if v.startswith("comma_stack:")
                 or v.startswith("keyword_stacking:")]
            )

        # Label this candidate with a confidence level and a
        # message_basis so the UI can communicate how strong the
        # grounding is. This replaces the old binary "low_context"
        # bucket — we no longer demote thoughtful pattern-based
        # messages just because the confidence level is low.
        cand_confidence = (
            quality.get("confidence_level")
            or ("low" if cand.get("low_context") else "high")
        )
        cand["confidence_level"] = cand_confidence
        cand["message_basis"] = _classify_message_basis(cand, distilled)

        # Only demote to the low-context bucket when the anti-generic
        # validator actually fails — and even then, only at HIGH
        # confidence where the user expected real specificity. At
        # MEDIUM/LOW confidence a broad-but-thoughtful message is
        # fine and should land in the main candidates list.
        demote_for_validator = (
            not ag["passes_quality_threshold"] and cand_confidence == "high"
        )

        if not ok:
            rejected.append(cand)
        elif demote_for_validator:
            low_context_candidates.append(cand)
        else:
            candidates.append(cand)
    # Record a short sub-summary so the response clearly shows whether
    # candidate_validation degraded (all-rejected / all-low-context)
    # without the caller having to inspect the candidate arrays. This
    # is the signal we watch for when stepping complexity up in
    # Step 3+. We also record whether any accepted candidate actually
    # *referenced* playbook or knowledge entries so Step 4 can tell
    # whether the enrichment layer is reaching the output or not.
    raw_count = len(raw or [])
    accepted_with_pb = sum(
        1 for c in candidates if (c.get("playbook_entries_used") or [])
    )
    accepted_with_kn = sum(
        1 for c in candidates if (c.get("knowledge_entries_used") or [])
    )
    rejected_for_comma_stack = sum(
        1 for c in rejected
        if any(
            v.startswith("comma_stack:") or v.startswith("keyword_stacking:")
            for v in ((c.get("grounding") or {}).get("violations") or [])
        )
    )
    validation_summary = {
        "raw": raw_count,
        "accepted": len(candidates),
        "low_context": len(low_context_candidates),
        "rejected": len(rejected),
        "rejected_for_comma_stack": rejected_for_comma_stack,
        "accepted_with_playbook": accepted_with_pb,
        "accepted_with_knowledge": accepted_with_kn,
        "playbook_entries_loaded": len(pb_entries),
        "knowledge_entries_loaded": len(knowledge_entries),
        "internal_thoughts_used": len(context.get("internal_thoughts") or []),
    }
    if raw_count and len(candidates) == 0:
        # Every candidate was demoted or rejected — this is a real
        # degradation even though the stage itself did not crash.
        _stage("candidate_validation", "degraded_all_demoted")
    else:
        _stage("candidate_validation", "ok")
    stages["candidate_validation_summary"] = validation_summary

    # Message Critic. The critic runs over every surviving candidate
    # (accepted + low_context) and attaches a structured ``critique``
    # block with scores + verdict. Candidates whose verdict is
    # ``reject`` get demoted to rejected, candidates whose verdict is
    # ``rewrite`` get moved to a new ``rewrite`` bucket (the UI can
    # show them as "needs work"). The critic never touches already-
    # rejected candidates and never crashes the pipeline.
    if minimal:
        _stage("message_critic", "skipped_minimal")
        rewrite_candidates: list[dict] = []
        critic_summary = {"accepted": len(candidates), "rewrite": 0, "rejected": 0}
    else:
        _stage("message_critic", "running")
        rewrite_candidates = []
        try:
            combined = candidates + low_context_candidates
            message_critic.critique_all(
                combined,
                context,
                insights=context.get("insights") or [],
                provider=provider,
            )
            promoted: list[dict] = []
            demoted_low: list[dict] = []
            critic_rejected: list[dict] = []
            for c in combined:
                verdict = (c.get("critique") or {}).get("verdict", "accept")
                if verdict == "reject":
                    critic_rejected.append(c)
                elif verdict == "rewrite":
                    rewrite_candidates.append(c)
                else:
                    if c in low_context_candidates:
                        demoted_low.append(c)
                    else:
                        promoted.append(c)
            candidates = promoted
            low_context_candidates = demoted_low
            rejected = rejected + critic_rejected
            critic_summary = {
                "accepted": len(candidates),
                "rewrite": len(rewrite_candidates),
                "rejected": len(critic_rejected),
                "low_context": len(low_context_candidates),
            }
            if not candidates and not rewrite_candidates:
                _stage("message_critic", "degraded_all_rejected")
            else:
                _stage("message_critic", "ok")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(
                f"[SignalStack] generator: message_critic FAILED — "
                f"continuing without critique: {type(e).__name__}: {e}"
            )
            critic_summary = {"error": f"{type(e).__name__}"}
            _stage("message_critic", "failed_soft")
    stages["message_critic_summary"] = critic_summary

    # Note: we deliberately do NOT return the full `context` here. It can
    # contain DB rows whose types (datetime, Decimal, bytes from Postgres)
    # are not always JSON-serializable, which previously caused the route
    # to 500 and the UI to hang on "Generating…".
    warning = None
    confidence_level = quality.get("confidence_level") or ("low" if quality.get("weak_only") else "high")
    if confidence_level == "low":
        warning = (
            "Running in low-confidence mode — messages are anchored on "
            "market and role patterns rather than specific situational "
            "signals. Add a note, signal, or richer profile context for "
            "sharper, more specific outreach."
        )
    elif confidence_level == "medium":
        warning = (
            "Running in medium-confidence mode — messages use pattern and "
            "profile-based framing. Add a specific signal or note for the "
            "strongest personalization."
        )

    return {
        "ok": True,
        "minimal_mode": minimal,
        "provider": provider_name,
        "stages": stages,
        "context_summary": {
            "signal_count": len(context.get("signals") or []),
            "note_count": len(context.get("notes") or []),
            "has_profile": bool(context.get("profile")),
            "principle_count": len(context.get("principles") or []),
            "knowledge_entry_count": len(knowledge_entries),
            "knowledge_source_count": len(knowledge_source_ids_used),
            "insight_count": len(context.get("insights") or []),
            "internal_thought_count": len(context.get("internal_thoughts") or []),
            "hypothesis_count": len(
                (context.get("context_expansion") or {}).get("hypotheses") or []
            ),
        },
        "knowledge": {
            "entries": knowledge_entry_summaries,
            "source_ids_used": knowledge_source_ids_used,
            "entry_ids_used": knowledge_entry_ids_used,
        },
        "context_expansion": context.get("context_expansion") or {},
        "confidence_level": confidence_level,
        "input_quality": {
            "input_quality_score": quality["input_quality_score"],
            "tier": quality["tier"],
            "confidence_level": confidence_level,
            "enough_specificity_for_high_quality_message":
                quality["enough_specificity_for_high_quality_message"],
            "reasons": quality["reasons"],
            "strongest_signal_type": (
                (quality.get("strongest_available_signal") or {}).get("type")
            ),
            "strongest_observation": (
                (quality.get("strongest_available_observation") or {}).get("summary")
            ),
        },
        "distilled_observations": distilled,
        "insights": context.get("insights") or [],
        "insight_source": insight_source,
        "insight_error": insight_error,
        "internal_thoughts": context.get("internal_thoughts") or [],
        "thought_source": thought_source,
        "thought_error": thought_error,
        "playbook": {
            "name": (playbook_bundle.get("playbook") or {}).get("name"),
            "description": (playbook_bundle.get("playbook") or {}).get("description"),
            "categories": playbook_bundle.get("categories") or [],
            "preferred_angles": pb_preferred,
            "entries": [_clean_playbook_entry(e) for e in pb_entries],
            "reasoning": playbook_bundle.get("reasoning"),
        },
        "strategies": strategies,
        "instruction": instruction,
        "candidates": candidates,
        "rewrite_candidates": rewrite_candidates if not minimal else [],
        "low_context_candidates": low_context_candidates,
        "rejected": rejected,
        "warning": warning,
    }


def save_draft(prospect_id: str, candidate: dict) -> dict:
    """Persist a generated candidate as a draft message + grounding metadata."""
    msg = repo.create_message(
        {
            "prospect_id": prospect_id,
            "body": candidate["body"],
            "rationale": candidate.get("rationale"),
            "message_type": candidate.get("message_type"),
            "primary_trigger": candidate.get("primary_trigger"),
            "communication_style": candidate.get("communication_style"),
            "outreach_goal": candidate.get("outreach_goal"),
            "channel": candidate.get("channel", "linkedin_dm"),
            "status": "draft",
            "grounding_score": (candidate.get("grounding") or {}).get("score"),
        },
        signal_ids=candidate.get("signal_ids") or [],
    )
    try:
        repo.save_message_metadata(msg["id"], {
            "facts_used": candidate.get("facts_used") or [],
            "signals_used": candidate.get("signal_ids") or [],
            "notes_used": candidate.get("notes_used") or [],
            "profile_fields_used": candidate.get("profile_fields_used") or [],
            "grounding_score": (candidate.get("grounding") or {}).get("score"),
            "unsafe_claims": (candidate.get("grounding") or {}).get("violations") or [],
            "validator_notes": (candidate.get("grounding") or {}).get("notes"),
            "strategy": {
                "message_type": candidate.get("message_type"),
                "primary_trigger": candidate.get("primary_trigger"),
                "communication_style": candidate.get("communication_style"),
                "outreach_goal": candidate.get("outreach_goal"),
                "angle": candidate.get("angle"),
                "playbook_entries_used": candidate.get("playbook_entries_used") or [],
                "playbook_reasoning": candidate.get("playbook_reasoning"),
                "knowledge_entries_used": candidate.get("knowledge_entries_used") or [],
                "knowledge_source_ids_used": candidate.get("knowledge_source_ids_used") or [],
                "knowledge_entry_ids_used": candidate.get("knowledge_entry_ids_used") or [],
            },
        })
    except Exception as e:
        print(f"[SignalStack] metadata save skipped: {e}")
    return msg
