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
from . import strategy as strategy_engine
from .signal_interpreter import interpret_signals
from .anti_copy import check_message as anti_copy_check, shorten as anti_copy_shorten
from .input_quality_scorer import score_inputs
from .observation_distiller import distill as distill_observations
from .message_angle_planner import plan as plan_angles
from .anti_generic_validator import validate as anti_generic_validate
from . import playbook_loader


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

    # Pull a small set of active principles for the provider to consult.
    try:
        principles = repo.list_principles(active_only=True)
    except Exception:
        principles = []

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
) -> dict:
    context = build_context(prospect_id, profile_override=profile_override)
    if context is None:
        return {"error": "prospect_not_found"}

    if not _has_any_grounding(context):
        return {
            "candidates": [],
            "rejected": [],
            "error": "no_grounding",
            "message": (
                "No signals, notes, or profile context stored for this prospect. "
                "Add at least one observation, paste profile context, or write a "
                "note before generating outreach."
            ),
        }

    # 1) Score input quality. This decides whether we allow high-quality
    #    personalized outreach or only a low-context fallback.
    quality = score_inputs(context)

    # 2) Distill 1–3 sharp observations from the raw material. The
    #    generator reasons about these — not the raw source blobs.
    distilled = distill_observations(context)
    context["distilled_observations"] = distilled

    # 2.5) Load industry playbook intelligence (BTR/CRE today). This
    #      shapes angle selection, anti-pattern avoidance, and the
    #      "why this angle" trail returned to the UI. Playbook entries
    #      are NEVER copy-pasted into messages as personalization.
    playbook_bundle = playbook_loader.load_relevant_entries(
        context, instruction=instruction
    )
    pb_entries = playbook_bundle.get("entries") or []
    pb_preferred = playbook_loader.preferred_angles(pb_entries)
    pb_anti_patterns = playbook_loader.collect_anti_patterns(pb_entries)
    context["playbook"] = playbook_bundle
    context["playbook_anti_patterns"] = pb_anti_patterns

    # 3) Plan distinct angles for the options. Weak-input cases get
    #    restricted to low-pressure / networking angles only.
    strategies = plan_angles(
        quality, n=n,
        override=strategy_override,
        playbook_preferred_angles=pb_preferred or None,
    )

    provider = get_provider()
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
        return {
            "candidates": [],
            "rejected": [],
            "error": "provider_failed",
            "message": f"AI provider error: {e}",
        }

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
        angle = cand.get("angle")
        used_pb_entries = [
            {
                "id": e.get("id"),
                "category": e.get("category"),
                "title": e.get("title"),
                "confidence": e.get("confidence"),
            }
            for e in pb_entries
            if angle and angle in (e.get("message_angles") or [])
        ]
        # Always include the active anti-pattern entries — they shaped
        # what the message is *not* allowed to say.
        for e in pb_entries:
            if e.get("category") == "anti_patterns":
                summary = {
                    "id": e.get("id"),
                    "category": e.get("category"),
                    "title": e.get("title"),
                    "confidence": e.get("confidence"),
                }
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
        "context_summary": {
            "signal_count": len(context.get("signals") or []),
            "note_count": len(context.get("notes") or []),
            "has_profile": bool(context.get("profile")),
            "principle_count": len(context.get("principles") or []),
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
            "entries": [
                {
                    "id": e.get("id"),
                    "category": e.get("category"),
                    "title": e.get("title"),
                    "description": e.get("description"),
                    "when_to_use": e.get("when_to_use"),
                    "message_angles": e.get("message_angles") or [],
                    "confidence": e.get("confidence"),
                }
                for e in pb_entries
            ],
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
            },
        })
    except Exception as e:
        print(f"[SignalStack] metadata save skipped: {e}")
    return msg
