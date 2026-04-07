"""
Message generation service.

Pulls a prospect + safe signals + company context, asks the configured
AI provider for candidates, runs each candidate through the grounding
validator, and returns only validated options. The validated options
are NOT auto-saved — the user reviews and saves explicitly.
"""
from typing import Optional

from .. import repo
from ..ai.provider import get_provider
from ..grounding import validate_message, filter_safe_signals


def build_context(prospect_id: str) -> Optional[dict]:
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

    return {
        "prospect": prospect,
        "company": company,
        "signals": signals,
    }


def generate(prospect_id: str, n: int = 4) -> dict:
    """
    Returns:
      {
        "context": {...},
        "candidates": [
            {body, rationale, message_type, ..., signal_ids, facts_used,
             grounding: {ok, score, violations}}
        ],
        "rejected": [ same shape, but failed validation ],
      }
    """
    context = build_context(prospect_id)
    if context is None:
        return {"error": "prospect_not_found"}

    if not context["signals"]:
        return {
            "context": context,
            "candidates": [],
            "rejected": [],
            "error": "no_safe_signals",
            "message": (
                "No safe-to-reference signals stored for this prospect. "
                "Add at least one observation before generating outreach."
            ),
        }

    provider = get_provider()
    raw = provider.generate_messages(context, n=n)

    candidates, rejected = [], []
    for cand in raw:
        verdict = validate_message(
            body=cand["body"],
            signals_used=cand.get("signal_ids") or [],
            facts_used=cand.get("facts_used") or [],
        )
        cand["grounding"] = verdict
        (candidates if verdict["ok"] else rejected).append(cand)

    return {
        "context": context,
        "candidates": candidates,
        "rejected": rejected,
    }


def save_draft(prospect_id: str, candidate: dict) -> dict:
    """Persist a generated candidate as a draft message."""
    return repo.create_message(
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
