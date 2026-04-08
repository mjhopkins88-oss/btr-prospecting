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
from .observation_distiller import distill as distill_observations
from .message_angle_planner import plan as plan_angles
from .anti_generic_validator import validate as anti_generic_validate
from . import playbook_loader


def _clean_playbook_entry(entry: Optional[dict]) -> dict:
    """Project a raw ``ss_playbook_entries`` row down to the safe fields we
    attach to generator output. Raw rows may contain Postgres-typed
    values (datetime, Decimal, memoryview); ``to_json_safe`` normalizes
    the remaining primitives defensively.
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


def _clean_knowledge_entry(entry: Optional[dict]) -> dict:
    """Project a raw ``ss_knowledge_entries`` row down to the safe fields
    we attach to generator output.
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

    return {
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
    # Step-2 stability testing can see the exact pipeline shape without
    # reading logs.
    stages: dict[str, str] = {}

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

    if not _has_any_grounding(context):
        _stage("grounding_check", "no_grounding")
        return {
            "candidates": [],
            "rejected": [],
            "error": "no_grounding",
            "message": (
                "No signals, notes, or profile context stored for this prospect. "
                "Add at least one observation, paste profile context, or write a "
                "note before generating outreach."
            ),
            "stages": stages,
            "minimal_mode": minimal,
        }
    _stage("grounding_check", "ok")

    # 1) Score input quality. This decides whether we allow high-quality
    #    personalized outreach or only a low-context fallback.
    _stage("input_quality", "running")
    quality = score_inputs(context)
    _stage("input_quality", "ok")

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

    # 3) Plan distinct angles for the options. Weak-input cases get
    #    restricted to low-pressure / networking angles only.
    _stage("strategy_plan", "running")
    strategies = plan_angles(
        quality, n=n,
        override=strategy_override,
        playbook_preferred_angles=pb_preferred or None,
    )
    _stage("strategy_plan", "ok")

    provider = get_provider()
    provider_name = type(provider).__name__
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
    # set of primitives via ``_clean_knowledge_entry``. Raw rows coming
    # back from Postgres can contain datetime/Decimal/memoryview values
    # that are not JSON-serializable and previously crashed the response
    # path with a 500.
    knowledge_entries = context.get("knowledge_entries") or []
    knowledge_entry_summaries = [
        _clean_knowledge_entry(e) for e in knowledge_entries
    ]
    knowledge_source_ids_used = sorted({
        str(e.get("source_id")) for e in knowledge_entries if e.get("source_id")
    })
    knowledge_entry_ids_used = [
        str(e.get("id")) for e in knowledge_entries if e.get("id")
    ]

    _stage("candidate_validation", "running")
    candidates, rejected, low_context_candidates = [], [], []
    for cand in raw or []:
        body = cand.get("body", "") or ""

        # 1) Anti-copy: auto-shorten, then check for raw-source overlap.
        if len(body) > 450:
            body = anti_copy_shorten(body, target=320)
            cand["body"] = body
        anti = anti_copy_check(body, raw_sources)
        cand["anti_copy"] = anti

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
        cand["selected_angle"] = cand.get("angle")

        # Attach the playbook entries that informed this angle so the
        # UI can show the "why" trail. We match by angle membership.
        # Rows are projected via ``_clean_playbook_entry`` so we never
        # attach raw DB row objects to candidate payloads.
        angle = cand.get("angle")
        used_pb_entries: list[dict] = []
        for e in pb_entries:
            if angle and angle in (e.get("message_angles") or []):
                used_pb_entries.append(_clean_playbook_entry(e))
        # Always include the active anti-pattern entries — they shaped
        # what the message is *not* allowed to say.
        for e in pb_entries:
            if e.get("category") == "anti_patterns":
                summary = _clean_playbook_entry(e)
                if summary not in used_pb_entries:
                    used_pb_entries.append(summary)
        cand["playbook_entries_used"] = used_pb_entries
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
        cand["knowledge_entries_used"] = knowledge_entry_summaries
        cand["knowledge_source_ids_used"] = knowledge_source_ids_used
        cand["knowledge_entry_ids_used"] = knowledge_entry_ids_used

        playbook_clean = not leaked
        ok = verdict["ok"] and anti["passes_anti_copy_check"] and playbook_clean
        if not anti["passes_anti_copy_check"]:
            verdict.setdefault("violations", []).extend(anti["violations"])

        is_low_context = bool(cand.get("low_context")) or quality.get("weak_only")

        if not ok:
            rejected.append(cand)
        elif is_low_context or not ag["passes_quality_threshold"]:
            # Demote to the clearly-labeled low-context bucket. We do not
            # present these as high-quality personalized messages.
            low_context_candidates.append(cand)
        else:
            candidates.append(cand)
    _stage("candidate_validation", "ok")

    # Note: we deliberately do NOT return the full `context` here. It can
    # contain DB rows whose types (datetime, Decimal, bytes from Postgres)
    # are not always JSON-serializable, which previously caused the route
    # to 500 and the UI to hang on "Generating…".
    warning = None
    if quality.get("weak_only"):
        warning = (
            "Not enough specificity for strong personalized outreach. "
            "Add a signal, note, recent activity, or profile context."
        )

    return {
        "ok": True,
        "minimal_mode": minimal,
        "stages": stages,
        "context_summary": {
            "signal_count": len(context.get("signals") or []),
            "note_count": len(context.get("notes") or []),
            "has_profile": bool(context.get("profile")),
            "principle_count": len(context.get("principles") or []),
            "knowledge_entry_count": len(knowledge_entries),
            "knowledge_source_count": len(knowledge_source_ids_used),
        },
        "knowledge": {
            "entries": knowledge_entry_summaries,
            "source_ids_used": knowledge_source_ids_used,
            "entry_ids_used": knowledge_entry_ids_used,
        },
        "input_quality": {
            "input_quality_score": quality["input_quality_score"],
            "tier": quality["tier"],
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
