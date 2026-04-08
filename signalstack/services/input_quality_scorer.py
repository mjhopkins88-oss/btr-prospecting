"""
Input Quality Scorer.

Classifies the available inputs for a prospect into tiers and emits a
graded ``confidence_level`` (``low|medium|high``). The generator uses
this to shape the downstream pipeline — NOT as a hard block.

Before the context-expansion refactor, the scorer's ``weak_only`` flag
was effectively a kill switch: weak inputs → no strong messages, no
real reasoning, pure "low-context fallback". That made the product
feel broken whenever the user only had a LinkedIn profile to paste in.

New behaviour:

  * HIGH confidence → generator produces sharp, specific, signal-driven
    messages.
  * MEDIUM confidence → generator produces pattern-based, semi-specific
    messages anchored in profile context.
  * LOW confidence → generator produces thoughtful, pattern-based,
    non-specific but intelligent messages grounded in context_expansion
    hypotheses.

The scorer still classifies inputs into tiers and still prevents fake
specificity from weak facts — it just no longer hard-fails.
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

    # Graded confidence level. This is the new primary signal the
    # downstream pipeline reads — tier / weak_only are kept for
    # backwards compatibility with the angle planner and for the UI
    # summary, but we no longer hard-block on them.
    if tier == 1:
        confidence_level = "high"
    elif tier == 2:
        confidence_level = "medium"
    else:
        confidence_level = "low"

    if tier1_hits:
        reasons.append(f"tier1_signals:{tier1_hits}")
    if tier2_hits:
        reasons.append(f"tier2_profile_fields:{tier2_hits}")
    if weak_only:
        reasons.append("only_weak_profile_facts")
    reasons.append(f"confidence_level:{confidence_level}")

    return {
        "input_quality_score": score,
        "tier": tier,
        "confidence_level": confidence_level,
        "strongest_available_signal": strongest_signal,
        "strongest_available_observation": strongest_observation,
        "enough_specificity_for_high_quality_message": enough,
        "weak_only": weak_only,
        "reasons": reasons,
    }
