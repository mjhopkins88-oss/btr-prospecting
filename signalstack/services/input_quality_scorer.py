"""
Input Quality Scorer.

Classifies the available inputs for a prospect into tiers and decides
whether there is enough specificity to justify high-quality personalized
outreach. The generator consults this service BEFORE producing strong
messages — if the answer is "no", we either refuse or fall back to a
clearly labeled low-context option set.

This is the layer that prevents SignalStack from anchoring outreach on
weak profile facts (title / company / location) and pretending it is
"personalization".
"""
from __future__ import annotations

from typing import Optional

# Tier 1: strong, situation-specific signals worth referencing.
TIER1_SIGNAL_TYPES = {
    "post_topic", "company_news", "company_expansion", "hiring_activity",
    "listing_activity", "deal_activity", "role_change", "job_change",
    "manual_observation", "safe_signal",
}

# Tier 2: moderately specific — function/role/industry/market.
TIER2_PROFILE_FIELDS = {
    "function", "industry", "market", "company_type", "current_role",
    "featured_topics", "shared_context",
}

# Tier 3: weak — name, title, company, location.
TIER3_PROSPECT_FIELDS = {"full_name", "title", "company_name", "location"}


def _has_real_text(v) -> bool:
    return isinstance(v, str) and len(v.strip()) >= 8


def score_inputs(context: dict) -> dict:
    """
    Inspect a generator context and return a quality verdict.

    Returns:
        {
          "input_quality_score": 0..100,
          "tier": 1|2|3,
          "strongest_available_signal": dict|None,
          "strongest_available_observation": dict|None,
          "enough_specificity_for_high_quality_message": bool,
          "weak_only": bool,
          "reasons": [str, ...],
        }
    """
    signals = context.get("signals") or []
    notes = context.get("notes") or []
    profile = context.get("profile") or {}
    observations = context.get("observations") or []
    prospect = context.get("prospect") or {}

    reasons: list[str] = []
    tier1_hits = 0
    strongest_signal = None
    for s in signals:
        stype = (s.get("type") or "").lower()
        if stype in TIER1_SIGNAL_TYPES:
            tier1_hits += 1
            if strongest_signal is None:
                strongest_signal = s

    # A note with real specificity counts as Tier 1.
    specific_notes = [n for n in notes if _has_real_text(n.get("body"))]
    if specific_notes:
        tier1_hits += 1
        reasons.append("specific_note")

    # A pasted profile blob with real about_text / featured_topics also Tier 1.
    if _has_real_text(profile.get("about_text")) or _has_real_text(profile.get("featured_topics")):
        tier1_hits += 1
        reasons.append("rich_profile_context")

    tier2_hits = sum(1 for f in TIER2_PROFILE_FIELDS if profile.get(f))

    tier3_hits = sum(
        1 for f in TIER3_PROSPECT_FIELDS
        if (prospect.get(f) if f != "company_name" else prospect.get("company_name"))
    )

    if tier1_hits:
        tier = 1
        score = min(100, 60 + 15 * tier1_hits)
    elif tier2_hits:
        tier = 2
        score = min(60, 25 + 10 * tier2_hits)
    else:
        tier = 3
        score = min(25, 5 * tier3_hits)

    strongest_observation = None
    if observations:
        # Prefer the observation tied to the strongest signal.
        if strongest_signal is not None:
            sid = strongest_signal.get("id")
            strongest_observation = next(
                (o for o in observations if o.get("signal_id") == sid), None
            )
        if strongest_observation is None:
            strongest_observation = observations[0]

    enough = tier == 1
    weak_only = tier == 3

    if tier1_hits:
        reasons.append(f"tier1_signals:{tier1_hits}")
    if tier2_hits:
        reasons.append(f"tier2_profile_fields:{tier2_hits}")
    if weak_only:
        reasons.append("only_weak_profile_facts")

    return {
        "input_quality_score": score,
        "tier": tier,
        "strongest_available_signal": strongest_signal,
        "strongest_available_observation": strongest_observation,
        "enough_specificity_for_high_quality_message": enough,
        "weak_only": weak_only,
        "reasons": reasons,
    }
