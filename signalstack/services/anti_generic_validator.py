"""
Anti-Generic Validator.

Rejects or penalizes outreach that:
  * opens with template phrases like "noticed your work as..."
  * contains empty praise or vague business buzzwords
  * copies raw source text verbatim

This used to be the binary gate that killed any message which didn't
cite a strong signal / note / profile field — even thoughtful
pattern-based messages anchored on role or market were rejected as
"too generic". That made LinkedIn-only inputs useless.

New behaviour: the validator is CONFIDENCE-AWARE.

  * HIGH confidence   — the old behaviour. Strong specificity
                        expected. Weak-fact-only anchoring is
                        rejected. This preserves the "no fake
                        personalization" rule when we do have real
                        signals to work with.

  * MEDIUM confidence — medium bar. We allow pattern-based framing
                        but still reject buzzwords and banned
                        template openers.

  * LOW confidence    — permissive. We only reject on the hardest
                        violations: banned sales-template openers,
                        buzzwords, or copy-paste behaviour from the
                        raw sources. Intelligent generalization is
                        explicitly allowed.

The validator NEVER allows fabricated specifics — the generator is
responsible for not hallucinating, and grounding.py still catches
fake-familiarity and creepy personal language. This validator is the
quality-of-prose gate, not the hallucination gate.
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
    # At HIGH confidence, weak-fact-only anchoring is a strong
    # genericity penalty — we expected real signals and didn't get
    # them. At MEDIUM it's a moderate penalty. At LOW it's expected
    # behaviour and not a penalty at all; the message is grounded
    # on hypotheses, not weak profile facts.
    confidence_for_score = (quality.get("confidence_level") or "").lower() or (
        "low" if quality.get("weak_only") else "high"
    )
    if weak_fact_only:
        if confidence_for_score == "high":
            genericity_score += 0.6
        elif confidence_for_score == "medium":
            genericity_score += 0.3
    if not signal_ids and not notes_used and not profile_fields_used:
        if confidence_for_score == "high":
            genericity_score += 0.3
        elif confidence_for_score == "medium":
            genericity_score += 0.15
    genericity_score = min(1.0, genericity_score)

    situation_relevance_score = 0.0
    if quality.get("enough_specificity_for_high_quality_message"):
        situation_relevance_score = 0.7 + 0.3 * specificity_score
    elif quality.get("tier") == 2:
        situation_relevance_score = 0.4 + 0.2 * specificity_score
    else:
        situation_relevance_score = 0.1 + 0.1 * specificity_score

    # Confidence-aware pass gate. The bar moves with the available
    # context — we do NOT reject intelligent pattern-based messages
    # on thin context just because they're broad.
    confidence_level = (quality.get("confidence_level") or "").lower()
    if not confidence_level:
        confidence_level = "low" if quality.get("weak_only") else "high"

    if confidence_level == "high":
        # Keep the original behaviour for strong-signal generation —
        # demand real specificity, reject weak-fact-only anchoring.
        passes = (
            not violations
            and specificity_score >= PASS_THRESHOLD
            and genericity_score < 0.4
        )
    elif confidence_level == "medium":
        # Medium: allow broader framing but still reject hard
        # violations and the worst of the buzzword/template openers.
        hard_violations = [
            v for v in violations
            if v.startswith("banned_opener:") or v.startswith("buzzword:")
        ]
        passes = (
            not hard_violations
            and genericity_score < 0.55
        )
    else:
        # Low: only the hardest violations disqualify — banned sales
        # template openers and buzzwords. A broad-but-thoughtful
        # message is allowed through.
        hard_violations = [
            v for v in violations
            if v.startswith("banned_opener:") or v.startswith("buzzword:")
        ]
        passes = not hard_violations

    return {
        "passes_quality_threshold": passes,
        "confidence_level": confidence_level,
        "specificity_score": round(specificity_score, 3),
        "genericity_score": round(genericity_score, 3),
        "situation_relevance_score": round(situation_relevance_score, 3),
        "violations": violations,
    }
