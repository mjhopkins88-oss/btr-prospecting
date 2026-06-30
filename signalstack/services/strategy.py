"""
Strategy engine — picks message type / trigger / style / goal / modifiers.

The strategy engine is intentionally rule-based and deterministic so the
generator stays predictable and easy to audit. The user can override any
field at request time; the engine only fills in what's missing.
"""
from typing import Optional


# Distinct angles the generator should diversify across.
ANGLES = (
    {"angle": "curiosity",       "message_type": "curiosity", "primary_trigger": "curiosity",
     "communication_style": "conversational", "outreach_goal": "start_conversation"},
    {"angle": "observation",     "message_type": "casual",    "primary_trigger": "liking",
     "communication_style": "conversational", "outreach_goal": "build_familiarity"},
    {"angle": "insight",         "message_type": "insight",   "primary_trigger": "self_relevance",
     "communication_style": "analytical",     "outreach_goal": "offer_insight"},
    {"angle": "point_of_view",   "message_type": "insight",   "primary_trigger": "authority",
     "communication_style": "analytical",     "outreach_goal": "offer_insight"},
    {"angle": "relevant_challenge", "message_type": "direct", "primary_trigger": "loss_aversion",
     "communication_style": "direct",         "outreach_goal": "get_routed"},
    {"angle": "timing_context",  "message_type": "casual",    "primary_trigger": "social_proof",
     "communication_style": "conversational", "outreach_goal": "start_conversation"},
)


def recommend(context: dict, override: Optional[dict] = None, n: int = 4) -> list[dict]:
    """
    Build n distinct strategy specs. Override is merged into each spec
    so the user can pin e.g. communication_style="direct" while still
    diversifying the angle.
    """
    override = override or {}
    signals = context.get("signals") or []
    has_post = any(s.get("type") == "post_topic" for s in signals)
    has_company_event = any(
        s.get("type") in ("company_expansion", "company_news", "hiring_activity")
        for s in signals
    )

    # Bias the ordering of angles based on what evidence we actually have.
    ordered = list(ANGLES)
    if has_post:
        ordered.sort(key=lambda a: 0 if a["angle"] in ("curiosity", "point_of_view") else 1)
    elif has_company_event:
        ordered.sort(key=lambda a: 0 if a["angle"] in ("observation", "timing_context") else 1)

    out = []
    for spec in ordered[: max(1, n)]:
        merged = {**spec, **{k: v for k, v in override.items() if v}}
        merged["modifiers"] = override.get("modifiers") or []
        out.append(merged)
    return out
