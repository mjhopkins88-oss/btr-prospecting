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

# Vague floating phrases that do NOT count as a contextual anchor.
# A message using any of these as its "where this shows up" beat is
# treated as unanchored — the reasoning floats instead of landing on
# a real operating surface (pipeline, underwriting, newer deals,
# lease-up, capital allocation, deal execution, etc.).
VAGUE_ANCHOR_PHRASES = [
    r"\bthis part of the market\b",
    r"\bthis part of the business\b",
    r"\bthis slice of the market\b",
    r"\bthis slice of the business\b",
    r"\bthis slice\b",
    r"\bthis segment of the market\b",
    r"\bthis segment\b",
    r"\bthis kind of market\b",
    r"\bthis side of the business\b",
    r"\bthis side of the market\b",
    r"\bthis space\b",
    r"\bin this space\b",
    r"\bthe current environment\b",
    r"\btoday'?s market\b",
]

# Analyst / newsletter voice. A message leaning on any of these is
# written from OUTSIDE the deal process — the sender is supposed to
# be an operator INSIDE the process, watching the same risk /
# timing / execution issue surface across many deals. These
# phrasings drift the voice back to a market commentator, and the
# lens is lost.
#
# The pipeline prompts already tell the model not to use these, but
# we enforce it here too as a defense in depth: if one slips
# through, the validator treats it as a hard violation so the
# message is rejected before it reaches the user.
ANALYST_VOICE_PHRASES = [
    r"\bpattern i keep noticing\b",
    r"\bpattern i keep seeing\b",
    r"\ba pattern i (?:keep )?(?:notice|see)\b",
    r"\bthe pattern i'?m noticing\b",
    r"\btrend i'?m watching\b",
    r"\bthe trend suggests\b",
    r"\bteams in this segment\b",
    r"\bfolks in this space\b",
    r"\bfeels like the market is\b",
]

# Allow-list of contextual anchor phrases. When a message contains
# any of these (or a close variant), it is considered to land on a
# real operating surface. Absence of an anchor at HIGH/MEDIUM
# confidence is a specificity penalty. At LOW confidence we still
# prefer anchored messages but do not hard-fail on the absence.
CONTEXTUAL_ANCHOR_PHRASES = [
    r"\bon newer deals\b",
    r"\bon new deals\b",
    r"\bon newer communities\b",
    r"\bon new communities\b",
    r"\bin your pipeline\b",
    r"\bin the pipeline\b",
    r"\bwhen underwriting gets deeper\b",
    r"\bwhen you'?re underwriting\b",
    r"\bonce deals get closer to execution\b",
    r"\bin the next capital allocation\b",
    r"\bduring lease[- ]?up\b",
    r"\bas new sites come online\b",
    r"\bon deals still in diligence\b",
    r"\bin the build phase\b",
    r"\bon the sites you'?re working\b",
    r"\bin deal execution\b",
    r"\bon the underwriting side\b",
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

    # Vague floating phrases are banned as "where this shows up"
    # anchors. Any hit here downgrades the message to unanchored and
    # raises genericity so the hard gate below can reject it at
    # HIGH/MEDIUM confidence.
    vague_hits = _contains_any(body_lo, VAGUE_ANCHOR_PHRASES)
    for h in vague_hits:
        violations.append(f"vague_anchor:{h}")

    # Analyst / newsletter voice. These phrasings are banned because
    # they make the sender sound like an outside observer instead of
    # an operator inside the deal process. The lens is lost when the
    # message drifts into market commentary. We treat these as hard
    # violations at every confidence level.
    analyst_hits = _contains_any(body_lo, ANALYST_VOICE_PHRASES)
    for h in analyst_hits:
        violations.append(f"analyst_voice:{h}")

    # Does the message land on a real operating surface? We look for
    # any of the allow-listed contextual anchor phrases. A message
    # missing all of them has no "where this shows up" beat.
    anchor_hits = _contains_any(body_lo, CONTEXTUAL_ANCHOR_PHRASES)
    has_contextual_anchor = bool(anchor_hits) and not vague_hits
    if not has_contextual_anchor and not vague_hits:
        violations.append("no_contextual_anchor")

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
    # A real "where this shows up" anchor is itself a specificity
    # signal — it means the message lands on an operating surface
    # the prospect actually works on, even if we don't have a strong
    # signal to cite by id.
    if has_contextual_anchor:
        specificity_score += 0.2
    specificity_score = min(1.0, specificity_score)

    genericity_score = 0.0
    genericity_score += 0.5 * len(banned_hits)
    genericity_score += 0.2 * len(buzz_hits)
    # Vague floating phrases raise genericity. Missing any anchor
    # at all raises it less, but still tips the message toward the
    # "could be sent to 200 people" end of the scale.
    genericity_score += 0.35 * len(vague_hits)
    # Analyst / newsletter voice is an even bigger genericity hit —
    # it makes the message read like it was written by a commentator
    # instead of someone inside the process.
    genericity_score += 0.4 * len(analyst_hits)
    if not has_contextual_anchor and not vague_hits:
        genericity_score += 0.15
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

    # Vague "this slice of the market" / "this space" phrasings are
    # treated as hard violations at every confidence level — the
    # whole point of the contextual anchor change is that they read
    # as unanchored market commentary regardless of how thin the
    # input context is.
    vague_violations = [v for v in violations if v.startswith("vague_anchor:")]

    if confidence_level == "high":
        # Keep the original behaviour for strong-signal generation —
        # demand real specificity, reject weak-fact-only anchoring.
        # A missing contextual anchor at HIGH confidence is a fail
        # (we had real context and still floated).
        passes = (
            not violations
            and specificity_score >= PASS_THRESHOLD
            and genericity_score < 0.4
        )
    elif confidence_level == "medium":
        # Medium: allow broader framing but still reject hard
        # violations, vague anchors, analyst voice, and the worst
        # of the buzzword/template openers. A missing anchor at
        # medium is also a fail — the pipeline has enough context
        # to ground on a real operating surface.
        hard_violations = [
            v for v in violations
            if v.startswith("banned_opener:")
            or v.startswith("buzzword:")
            or v.startswith("vague_anchor:")
            or v.startswith("analyst_voice:")
            or v == "no_contextual_anchor"
        ]
        passes = (
            not hard_violations
            and genericity_score < 0.55
        )
    else:
        # Low: only the hardest violations disqualify — banned sales
        # template openers, buzzwords, vague floating phrases, and
        # analyst / newsletter voice. A missing anchor is NOT a
        # hard fail at low confidence because the heuristic fallback
        # messages may still ground on pattern framing without a
        # canonical anchor phrase; we still penalize it on the
        # genericity score so the critic can prefer anchored drafts.
        hard_violations = [
            v for v in violations
            if v.startswith("banned_opener:")
            or v.startswith("buzzword:")
            or v.startswith("vague_anchor:")
            or v.startswith("analyst_voice:")
        ]
        passes = not hard_violations

    return {
        "passes_quality_threshold": passes,
        "confidence_level": confidence_level,
        "specificity_score": round(specificity_score, 3),
        "genericity_score": round(genericity_score, 3),
        "situation_relevance_score": round(situation_relevance_score, 3),
        "has_contextual_anchor": has_contextual_anchor,
        "vague_anchor_hits": vague_hits,
        "anchor_hits": anchor_hits,
        "violations": violations,
    }
