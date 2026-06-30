"""
Naturalness Validator.

A post-generation gate that rejects messages whose surface form
reveals they were stitched together from input keywords rather than
written from a single peer-voice thought.

This validator catches the exact failure mode the thought-translator
layer was introduced to prevent: messages that stacked profile
keywords ("build to rent, commercial real estate, insurance") even
when the upstream reasoning pipeline was correct.

It does NOT re-check anything already covered by:
  * anti_copy_validator   — raw source overlap
  * grounding             — fake familiarity, banned sales language
  * anti_generic_validator — template openers, weak-fact anchoring
  * message_critic        — specificity / peer credibility

Instead it is narrowly scoped to:
  1. Comma-separated topic lists.
  2. Keyword stacking ("X, Y, and Z" where 2+ items are CRM tags).
  3. Profile-summary prose (messages that read like a bullet list
     flattened into a sentence).
  4. Input-phrase regurgitation — messages that directly reuse
     the prospect's ``featured_topics`` or ``headline`` as prose.

The validator returns a structured verdict. The generator pipeline
demotes failing candidates to the ``low_context`` bucket (or flags
them in ``rejected`` depending on severity) and the critic attaches
the verdict to the candidate metadata so the UI can surface "why".
"""
from __future__ import annotations

import re
from typing import Optional

# CRM-tag / industry terms that should NEVER appear in a comma-
# separated list inside a peer-voice message. If at least two of
# these show up in a comma-separated run, the message is a keyword
# stack and we reject it.
_TAG_TERMS = (
    "build to rent", "build-to-rent", "btr",
    "commercial real estate", "cre",
    "multifamily", "sfr", "townhomes", "townhome",
    "capital markets", "asset management",
    "insurance", "wealth management", "private credit",
    "fintech", "proptech", "saas",
    "real estate", "portfolio management",
)

# Phrases that are telltale profile-summary prose.
_PROFILE_SUMMARY_PHRASES = (
    "your focus on",
    "your experience in",
    "your background in",
    "your work across",
    "your work in",
    "given your experience",
    "given your background",
    "with your focus on",
)

# Words that frame a message as a profile restatement rather than a
# thought. Triggers a soft penalty, not an automatic reject.
_RESTATEMENT_MARKERS = (
    "based on your profile",
    "looking at your profile",
    "your linkedin",
)

# Naturalness floor below which the verdict flips to reject/demote.
NATURALNESS_FLOOR = 0.45


def _find_comma_stacks(body: str) -> list[str]:
    """Return a list of detected comma-stack runs in ``body``.

    A "stack" is a run of three-or-more comma-separated items in a
    single sentence where at least two items are in ``_TAG_TERMS``,
    OR any run where two consecutive items are both tag terms.

    We deliberately allow a harmless "A, B, and C" sentence when none
    of A/B/C is a tag term — peer voice still uses commas.
    """
    if not body:
        return []
    lo = body.lower()
    # Fast path: no tag terms at all.
    if not any(t in lo for t in _TAG_TERMS):
        return []

    hits: list[str] = []
    # Split on sentence boundaries so we don't stitch a stack across
    # two sentences.
    for sentence in re.split(r"(?<=[.!?])\s+", body):
        s_lo = sentence.lower()
        # Walk comma groups.
        pieces = [p.strip() for p in re.split(r",\s*", sentence) if p.strip()]
        if len(pieces) < 2:
            continue
        tag_hits = 0
        tag_words: list[str] = []
        for p in pieces:
            p_lo = p.lower().strip(" .?!")
            # Also strip a trailing "and X" when the last piece starts
            # with "and ".
            p_lo = re.sub(r"^and\s+", "", p_lo)
            for t in _TAG_TERMS:
                if p_lo == t or (len(p_lo) < 40 and t in p_lo):
                    tag_hits += 1
                    tag_words.append(t)
                    break
        if tag_hits >= 2:
            hits.append(sentence.strip())
    return hits


def _find_profile_summary_phrases(body: str) -> list[str]:
    if not body:
        return []
    lo = body.lower()
    return [p for p in _PROFILE_SUMMARY_PHRASES if p in lo]


def _find_restatement_markers(body: str) -> list[str]:
    if not body:
        return []
    lo = body.lower()
    return [m for m in _RESTATEMENT_MARKERS if m in lo]


def _find_profile_copy(body: str, profile: Optional[dict]) -> list[str]:
    """Detect near-verbatim reuse of featured_topics/headline as prose.

    We tokenize the profile field and check whether a 4-word window
    from the body matches a 4-word window from the field. If yes,
    that's a copy — the message is just regurgitating the profile
    blob as text.
    """
    if not profile or not body:
        return []
    hits: list[str] = []
    body_lo = body.lower()
    for key in ("featured_topics", "headline", "about_text"):
        val = (profile.get(key) or "").strip()
        if not val or len(val) < 12:
            continue
        val_lo = val.lower()
        toks = re.findall(r"[a-z0-9]+", val_lo)
        if len(toks) < 4:
            # Very short field — match whole-phrase only.
            if val_lo in body_lo:
                hits.append(f"{key}:verbatim")
            continue
        # Slide a 4-gram over the field and look for any matching
        # 4-gram in the body. Skip generic bigrams like "real estate"
        # by requiring 4 tokens.
        body_toks = re.findall(r"[a-z0-9]+", body_lo)
        body_ngrams = {
            " ".join(body_toks[i:i + 4])
            for i in range(len(body_toks) - 3)
        }
        for i in range(len(toks) - 3):
            window = " ".join(toks[i:i + 4])
            if window in body_ngrams:
                hits.append(f"{key}:4gram:{window}")
                break
    return hits


def _count_tag_terms(body: str) -> int:
    if not body:
        return 0
    lo = body.lower()
    return sum(1 for t in _TAG_TERMS if t in lo)


def _naturalness_score(
    body: str,
    comma_stacks: list,
    profile_phrases: list,
    restatement_markers: list,
    profile_copy_hits: list,
    tag_count: int,
) -> float:
    """Return a [0,1] score — higher = more natural."""
    if not body or not body.strip():
        return 0.0
    score = 0.85
    score -= 0.45 * len(comma_stacks)
    score -= 0.20 * len(profile_phrases)
    score -= 0.20 * len(restatement_markers)
    score -= 0.20 * len(profile_copy_hits)
    # Tag term density — any single tag term is fine; 3+ in one
    # short message is a summary.
    if tag_count >= 3:
        score -= 0.25
    elif tag_count == 2:
        score -= 0.1
    return max(0.0, min(1.0, score))


def validate(
    body: str,
    profile: Optional[dict] = None,
) -> dict:
    """Score a candidate for naturalness. Never raises.

    Returns:
        {
          "passes_naturalness": bool,
          "naturalness_score": float,   # 0..1 higher = more natural
          "violations": [str, ...],
          "notes": [str, ...],
        }
    """
    body = body or ""

    comma_stacks = _find_comma_stacks(body)
    profile_phrases = _find_profile_summary_phrases(body)
    restatement_markers = _find_restatement_markers(body)
    profile_copy_hits = _find_profile_copy(body, profile)
    tag_count = _count_tag_terms(body)

    score = _naturalness_score(
        body,
        comma_stacks,
        profile_phrases,
        restatement_markers,
        profile_copy_hits,
        tag_count,
    )

    violations: list[str] = []
    notes: list[str] = []

    for s in comma_stacks:
        violations.append(f"comma_stack:{s[:60]}")
    for p in profile_phrases:
        violations.append(f"profile_summary:{p}")
    for m in restatement_markers:
        violations.append(f"profile_restatement:{m}")
    for h in profile_copy_hits:
        violations.append(f"profile_copy:{h}")
    if tag_count >= 3:
        violations.append(f"keyword_stacking:{tag_count}_terms")
        notes.append("message reads as a list of input tags rather than a thought")

    # A single comma stack is an automatic fail — it's the exact
    # degradation this validator exists to catch. Other violations
    # fall through to the naturalness floor.
    passes = (not comma_stacks) and score >= NATURALNESS_FLOOR

    return {
        "passes_naturalness": passes,
        "naturalness_score": round(score, 3),
        "violations": violations,
        "notes": notes,
    }
