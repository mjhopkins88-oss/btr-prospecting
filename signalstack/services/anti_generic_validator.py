"""
Anti-Generic Validator.

Rejects or penalizes outreach that:
  * leans only on title / company / location
  * opens with template phrases like "noticed your work as..."
  * could plausibly be sent to hundreds of prospects with tiny edits
  * contains empty praise or vague business buzzwords

Returns a structured verdict the generator and the UI can both consume.
"""
from __future__ import annotations

import re

# Phrases that immediately disqualify a message as "fake personalized".
BANNED_OPENERS = [
    r"\bnoticed your work as\b",
    r"\bsaw your work as\b",
    r"\bpicked up on your work as\b",
    r"\bsaw your profile\b",
    r"\bcame across your profile\b",
    r"\bwould love to connect\b",
    r"\bhope this finds you well\b",
    r"\bI help companies like yours\b",
    r"\bI work with (companies|firms) like\b",
    r"\bquick (call|chat)\b",
    r"\bcircle back\b",
]

# Empty praise / buzzword phrases.
BUZZWORDS = [
    "synergy", "leverage", "best-in-class", "world-class", "thought leader",
    "game-changer", "move the needle", "ecosystem", "unlock value",
    "impressive work", "amazing work", "incredible journey",
]

# Token-level indicators of weak-fact-only anchoring.
WEAK_FACT_TOKENS = ("title", "company", "company_name", "location", "full_name")

PASS_THRESHOLD = 0.6


def _contains_any(body_lo: str, patterns: list[str]) -> list[str]:
    hits = []
    for p in patterns:
        if re.search(p, body_lo):
            hits.append(p)
    return hits


def validate(
    body: str,
    facts_used: list[str] | None = None,
    signal_ids: list[str] | None = None,
    notes_used: list[str] | None = None,
    profile_fields_used: list[str] | None = None,
    quality: dict | None = None,
) -> dict:
    body = body or ""
    body_lo = body.lower()
    facts_used = facts_used or []
    signal_ids = signal_ids or []
    notes_used = notes_used or []
    profile_fields_used = profile_fields_used or []
    quality = quality or {}

    violations: list[str] = []

    banned_hits = _contains_any(body_lo, BANNED_OPENERS)
    for h in banned_hits:
        violations.append(f"banned_opener:{h}")

    buzz_hits = [w for w in BUZZWORDS if w in body_lo]
    for w in buzz_hits:
        violations.append(f"buzzword:{w}")

    # Anchored only on weak facts?
    weak_fact_only = (
        not signal_ids
        and not notes_used
        and not profile_fields_used
        and any(any(t in (f or "").lower() for t in WEAK_FACT_TOKENS) for f in facts_used)
    )
    if weak_fact_only:
        violations.append("weak_facts_only")

    # Specificity heuristics: messages that name no concrete topic /
    # location / event tend to read as boilerplate.
    has_place = bool(re.search(r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b", body)) and any(
        kw in body_lo for kw in (
            "charlotte", "raleigh", "atlanta", "nashville", "phoenix",
            "dallas", "houston", "austin", "tampa", "denver", "miami",
            "btr", "townhome", "sfr", "multifamily", "fund", "listing",
            "hiring", "expansion", "raise", "deal", "portfolio",
        )
    )
    specificity_score = 0.0
    if signal_ids:
        specificity_score += 0.5
    if notes_used:
        specificity_score += 0.3
    if profile_fields_used:
        specificity_score += 0.2
    if has_place:
        specificity_score += 0.2
    specificity_score = min(1.0, specificity_score)

    genericity_score = 0.0
    genericity_score += 0.5 * len(banned_hits)
    genericity_score += 0.2 * len(buzz_hits)
    if weak_fact_only:
        genericity_score += 0.6
    if not signal_ids and not notes_used and not profile_fields_used:
        genericity_score += 0.3
    genericity_score = min(1.0, genericity_score)

    situation_relevance_score = 0.0
    if quality.get("enough_specificity_for_high_quality_message"):
        situation_relevance_score = 0.7 + 0.3 * specificity_score
    elif quality.get("tier") == 2:
        situation_relevance_score = 0.4 + 0.2 * specificity_score
    else:
        situation_relevance_score = 0.1 + 0.1 * specificity_score

    passes = (
        not violations
        and specificity_score >= PASS_THRESHOLD
        and genericity_score < 0.4
    )

    return {
        "passes_quality_threshold": passes,
        "specificity_score": round(specificity_score, 3),
        "genericity_score": round(genericity_score, 3),
        "situation_relevance_score": round(situation_relevance_score, 3),
        "violations": violations,
    }
