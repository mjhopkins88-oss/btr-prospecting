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

    strategies = strategy_engine.recommend(context, override=strategy_override, n=n)

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

    candidates, rejected = [], []
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

        ok = verdict["ok"] and anti["passes_anti_copy_check"]
        if not anti["passes_anti_copy_check"]:
            verdict.setdefault("violations", []).extend(anti["violations"])
        (candidates if ok else rejected).append(cand)

    # Note: we deliberately do NOT return the full `context` here. It can
    # contain DB rows whose types (datetime, Decimal, bytes from Postgres)
    # are not always JSON-serializable, which previously caused the route
    # to 500 and the UI to hang on "Generating…".
    return {
        "context_summary": {
            "signal_count": len(context.get("signals") or []),
            "note_count": len(context.get("notes") or []),
            "has_profile": bool(context.get("profile")),
            "principle_count": len(context.get("principles") or []),
        },
        "strategies": strategies,
        "instruction": instruction,
        "candidates": candidates,
        "rejected": rejected,
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
            },
        })
    except Exception as e:
        print(f"[SignalStack] metadata save skipped: {e}")
    return msg
