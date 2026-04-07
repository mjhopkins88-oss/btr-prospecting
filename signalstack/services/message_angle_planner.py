"""
Message Angle Planner.

Selects 3–5 *distinct* angles for a single generation request. Each
generated message option must use a different angle so we stop shipping
"3 minor rewrites of the same line".

This sits on top of the older strategy engine but is the canonical
source of truth for angle selection going forward.
"""
from __future__ import annotations

from typing import Optional

ANGLES = [
    {
        "angle": "curiosity",
        "description": "Open with a specific question about something observable.",
        "message_type": "curiosity",
        "primary_trigger": "curiosity",
        "communication_style": "conversational",
        "outreach_goal": "start_conversation",
    },
    {
        "angle": "timely_observation",
        "description": "Reference something that just happened. Make it feel timely.",
        "message_type": "casual",
        "primary_trigger": "social_proof",
        "communication_style": "conversational",
        "outreach_goal": "start_conversation",
    },
    {
        "angle": "market_pattern",
        "description": "Name a pattern you're seeing across similar firms.",
        "message_type": "insight",
        "primary_trigger": "self_relevance",
        "communication_style": "analytical",
        "outreach_goal": "offer_insight",
    },
    {
        "angle": "point_of_view",
        "description": "Share a short, falsifiable point of view. Invite pushback.",
        "message_type": "insight",
        "primary_trigger": "authority",
        "communication_style": "analytical",
        "outreach_goal": "offer_insight",
    },
    {
        "angle": "relevant_challenge",
        "description": "Name a downstream challenge implied by the situation.",
        "message_type": "direct",
        "primary_trigger": "loss_aversion",
        "communication_style": "direct",
        "outreach_goal": "get_routed",
    },
    {
        "angle": "light_insight",
        "description": "Offer one concrete, low-pressure data point or framing.",
        "message_type": "insight",
        "primary_trigger": "reciprocity",
        "communication_style": "conversational",
        "outreach_goal": "offer_insight",
    },
    {
        "angle": "low_pressure_starter",
        "description": "A short, no-ask conversation opener. Networking only.",
        "message_type": "casual",
        "primary_trigger": "liking",
        "communication_style": "conversational",
        "outreach_goal": "build_familiarity",
    },
]


def plan(
    quality: dict,
    n: int = 4,
    override: Optional[dict] = None,
    playbook_preferred_angles: Optional[list[str]] = None,
) -> list[dict]:
    """
    Select n distinct angles. When the input quality is weak (tier 3),
    we restrict to low-pressure / low-context-safe angles only.
    """
    override = override or {}
    n = max(1, min(n, 5))

    if quality.get("weak_only"):
        # Only safe in a low-context world: don't fake insight or POV.
        candidates = [a for a in ANGLES if a["angle"] in (
            "low_pressure_starter", "curiosity",
        )]
    else:
        candidates = list(ANGLES)
        # Bias ordering by what kind of evidence exists.
        sig = quality.get("strongest_available_signal") or {}
        stype = (sig.get("type") or "").lower()
        if stype == "post_topic":
            preferred = ("curiosity", "point_of_view", "light_insight", "market_pattern")
        elif stype in ("company_expansion", "hiring_activity"):
            preferred = ("timely_observation", "relevant_challenge", "curiosity", "market_pattern")
        elif stype in ("listing_activity", "deal_activity"):
            preferred = ("timely_observation", "relevant_challenge", "point_of_view", "curiosity")
        else:
            preferred = ("curiosity", "timely_observation", "light_insight", "point_of_view")
        candidates.sort(key=lambda a: preferred.index(a["angle"]) if a["angle"] in preferred else 99)

    # Playbook bias: if the industry playbook tells us which angles tend
    # to land for this kind of prospect, push those toward the top.
    if playbook_preferred_angles:
        order = {a: i for i, a in enumerate(playbook_preferred_angles)}
        candidates.sort(key=lambda a: order.get(a["angle"], 99))

    out: list[dict] = []
    seen = set()
    for spec in candidates:
        if spec["angle"] in seen:
            continue
        merged = {**spec, **{k: v for k, v in override.items() if v}}
        merged["modifiers"] = override.get("modifiers") or []
        out.append(merged)
        seen.add(spec["angle"])
        if len(out) >= n:
            break
    return out
