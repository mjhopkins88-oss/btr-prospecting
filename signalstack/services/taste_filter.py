"""
Taste Filter.

The final "would a sharp human actually send this?" gate in the
message engine pipeline. Sits AFTER the purely mechanical validators
(``anti_copy``, ``grounding``, ``anti_generic_validator``,
``naturalness_validator``) and BEFORE the message critic.

Where those validators answer narrow, mechanical questions
("does this copy the source?" / "does this stack CRM tags?"),
the taste filter answers a single judgement question: does this
read like a real human with a real point of view, or does it read
like a tuned-up SDR bot?

It rejects any candidate that:

  * sounds like a template,
  * reads like CRM tags turned into a sentence,
  * restates profile categories,
  * sounds like an SDR bot,
  * feels over-optimized,
  * contains keyword stacks.

The filter deliberately DOES NOT care about:
  * accuracy (grounding handles that),
  * confidence level (the pipeline grades that upstream),
  * formatting (the length gate handles that).

It cares ONLY about voice.

Design notes
------------
* Never raises. Returns a structured verdict for every candidate.
* Takes every lexical / structural verdict that is already attached
  to the candidate as input, and adds a small set of taste-specific
  heuristics on top. This is the ONLY place taste-level judgements
  are made so we can tune them in one file.
* When the filter rejects, the verdict includes a short
  ``human_reason`` string that can be rendered in the UI to explain
  why — e.g. "reads like three CRM tags stitched into a sentence".
"""
from __future__ import annotations

import re
from typing import Optional


# ----- Fingerprints the filter watches for -------------------------

# Opener shapes that are the default of every SDR sequence on the
# planet. Any of these in the first sentence is a hard fail.
_TEMPLATE_OPENERS = (
    "hope this finds you well",
    "hope you're doing well",
    "i came across your profile",
    "i saw your profile",
    "noticed your work as",
    "picked up on your work as",
    "i wanted to reach out",
    "reaching out because",
    "i'm reaching out because",
    "my name is",
    "i help companies like yours",
    "i work with companies like",
    "i work with firms like",
    "i help firms like",
    "we help teams",
    "quick question for you",
    "quick intro",
    "got a quick question",
    "would love to connect",
    "wanted to connect",
    "looking to connect with",
    "thought it might be worth connecting",
    "open to a quick chat",
    "worth a quick chat",
    "worth a quick call",
    "grab a quick call",
    "15 minutes on your calendar",
)

# Phrases the pipeline was told never to produce. These indicate
# the generator fell back into profile-summary prose instead of
# writing from a single internal thought.
_PROFILE_RESTATEMENT = (
    "given your focus on",
    "given your experience in",
    "given your experience with",
    "with your experience in",
    "your work across",
    "your work in",
    "with your background in",
    "based on your profile",
    "looking at your profile",
    "your linkedin",
    "your background in",
)

# SDR-bot tells. Language every outbound sequence gravitates toward
# when there's no real point of view in the message.
_SDR_BOT_TELLS = (
    "circle back",
    "touch base",
    "synergy",
    "leverage our",
    "unlock value",
    "move the needle",
    "value-add",
    "at the end of the day",
    "best-in-class",
    "world-class",
    "thought leader",
    "ecosystem",
    "cutting edge",
    "game-changer",
    "moving forward",
    "appreciate your time",
    "let's hop on",
    "let's jump on",
    "let me know if",
    "happy to set something up",
    "pencil me in",
)

# Phrases that signal "over-optimized" — language that was clearly
# tuned to maximize a click or reply but no longer sounds like a
# human DM. Scored not banned — one hit is OK, two is a fail.
_OVER_OPTIMIZED_HINTS = (
    "just a quick note",
    "short and sweet",
    "no hard sell",
    "promise this isn't a pitch",
    "not a pitch",
    "not selling anything",
    "no agenda, just",  # the 'just' tail is the tell
    "bear with me",
    "hear me out",
    "bold claim",
    "hot take",
    "tldr",
    "tl;dr",
)

# CRM tag tokens. Same list as naturalness_validator's tag terms,
# kept locally so this module has zero coupling to that one. Two or
# more of these inside a single sentence is a keyword stack.
_CRM_TAG_TOKENS = (
    "build to rent", "build-to-rent", "btr",
    "commercial real estate", "cre",
    "multifamily", "sfr", "townhomes", "townhome",
    "capital markets", "asset management",
    "insurance", "wealth management", "private credit",
    "fintech", "proptech", "saas",
    "real estate",
)

# Word-count floor / ceiling. A message that is absurdly short or
# long is never in good taste.
MIN_BODY_WORDS = 8
MAX_BODY_WORDS = 90


def _lo(text: str) -> str:
    return (text or "").strip().lower()


def _first_sentence(body: str) -> str:
    if not body:
        return ""
    m = re.split(r"[.!?]\s", body.strip(), maxsplit=1)
    return (m[0] if m else body).strip()


def _contains_any(lo: str, needles: tuple[str, ...]) -> list[str]:
    return [n for n in needles if n in lo]


def _sounds_like_template(body: str) -> list[str]:
    """
    Template opener detection.

    A message is "template-y" when its first sentence matches any
    of the universal SDR-sequence opening shapes, or when the body
    anywhere contains one of the hardcoded SDR-bot tells.
    """
    hits: list[str] = []
    first = _lo(_first_sentence(body))
    for opener in _TEMPLATE_OPENERS:
        if opener in first:
            hits.append(f"template_opener:{opener}")
    lo = _lo(body)
    for tell in _SDR_BOT_TELLS:
        if tell in lo:
            hits.append(f"sdr_tell:{tell}")
    return hits


def _reads_like_crm_tags(body: str) -> list[str]:
    """
    CRM tag stack detection.

    Returns a non-empty list if the body contains a sentence with
    two or more CRM tag tokens, OR three or more CRM tag tokens
    across the whole body.
    """
    lo = _lo(body)
    if not lo:
        return []
    total_tokens = sum(1 for t in _CRM_TAG_TOKENS if t in lo)
    hits: list[str] = []
    if total_tokens >= 3:
        hits.append(f"total_tag_count:{total_tokens}")
    for sentence in re.split(r"(?<=[.!?])\s+", body):
        s_lo = sentence.lower()
        in_sentence = sum(1 for t in _CRM_TAG_TOKENS if t in s_lo)
        if in_sentence >= 2:
            hits.append(f"sentence_tag_stack:{in_sentence}")
    return hits


def _restates_profile_categories(body: str) -> list[str]:
    lo = _lo(body)
    return [
        f"profile_restatement:{p}"
        for p in _PROFILE_RESTATEMENT if p in lo
    ]


def _feels_over_optimized(body: str) -> list[str]:
    lo = _lo(body)
    raw_hits = _contains_any(lo, _OVER_OPTIMIZED_HINTS)
    # One small "no agenda" / "not a pitch" hint is survivable on
    # its own. Two or more is the tell.
    if len(raw_hits) < 2:
        return []
    return [f"over_optimized:{h}" for h in raw_hits]


def _word_count_out_of_bounds(body: str) -> Optional[str]:
    words = re.findall(r"\S+", body or "")
    if len(words) < MIN_BODY_WORDS:
        return f"too_short:{len(words)}"
    if len(words) > MAX_BODY_WORDS:
        return f"too_long:{len(words)}"
    return None


def _has_comma_stack_from_naturalness(naturalness_verdict: Optional[dict]) -> bool:
    if not naturalness_verdict:
        return False
    for v in naturalness_verdict.get("violations") or []:
        if v.startswith("comma_stack:") or v.startswith("keyword_stacking:"):
            return True
    return False


def _collect_attached_violations(
    candidate: dict,
) -> list[str]:
    """
    Pull the taste-relevant subset of violations already attached by
    earlier validators. The taste filter inherits these so it produces
    ONE unified verdict the UI can surface, rather than forcing the
    UI to cross-reference five different verdict dicts.
    """
    out: list[str] = []
    ag = candidate.get("anti_generic") or {}
    for v in ag.get("violations") or []:
        if v.startswith("banned_opener:") or v.startswith("buzzword:"):
            out.append(f"anti_generic:{v}")
    nat = candidate.get("naturalness") or {}
    for v in nat.get("violations") or []:
        if (
            v.startswith("comma_stack:")
            or v.startswith("keyword_stacking:")
            or v.startswith("profile_summary:")
            or v.startswith("profile_copy:")
        ):
            out.append(f"naturalness:{v}")
    return out


# ----- Public API ---------------------------------------------------

REJECT_REASONS = {
    "template": "sounds like a template / SDR opener",
    "crm_tags": "reads like CRM tags stitched into a sentence",
    "profile_restatement": "restates the recipient's profile",
    "sdr_bot": "sounds like an SDR bot",
    "over_optimized": "feels over-optimized, not like a real DM",
    "keyword_stack": "contains a keyword stack",
    "length": "the body is the wrong length for a peer DM",
}


def evaluate(
    candidate: dict,
    profile: Optional[dict] = None,
) -> dict:
    """
    Evaluate a candidate and return a structured taste verdict.

    Shape::

        {
            "passes_taste": bool,
            "reject_reasons": ["template", "crm_tags", ...],
            "human_reason": "sounds like a template / SDR opener",
            "violations": [str, ...],
            "taste_score": 0.0..1.0,  # higher = more human
        }

    Never raises. Callers should attach the returned dict to the
    candidate and consult ``passes_taste``.
    """
    body = candidate.get("body") or ""
    violations: list[str] = []
    reject_reasons: list[str] = []

    template_hits = _sounds_like_template(body)
    if template_hits:
        violations.extend(template_hits)
        # If any TEMPLATE_OPENERS hit, it's a template.
        if any(v.startswith("template_opener:") for v in template_hits):
            reject_reasons.append("template")
        # If any SDR tells hit, it's also an SDR bot.
        if any(v.startswith("sdr_tell:") for v in template_hits):
            reject_reasons.append("sdr_bot")

    crm_hits = _reads_like_crm_tags(body)
    if crm_hits:
        violations.extend(crm_hits)
        reject_reasons.append("crm_tags")

    restatement_hits = _restates_profile_categories(body)
    if restatement_hits:
        violations.extend(restatement_hits)
        reject_reasons.append("profile_restatement")

    over_optimized_hits = _feels_over_optimized(body)
    if over_optimized_hits:
        violations.extend(over_optimized_hits)
        reject_reasons.append("over_optimized")

    length_hit = _word_count_out_of_bounds(body)
    if length_hit:
        violations.append(length_hit)
        reject_reasons.append("length")

    # Inherited: the naturalness validator's hard comma-stack /
    # keyword-stack signal is the single most reliable indicator of
    # CRM-prose. If it fired upstream, mark this as a keyword_stack
    # rejection here too so the UI sees one unified reason.
    if _has_comma_stack_from_naturalness(candidate.get("naturalness")):
        violations.append("naturalness:keyword_stack_upstream")
        if "keyword_stack" not in reject_reasons:
            reject_reasons.append("keyword_stack")

    # Pull in the subset of other-validator violations the taste filter
    # cares about, so the filter verdict is a single source of truth.
    inherited = _collect_attached_violations(candidate)
    violations.extend(inherited)

    # Score: start at 1.0 and subtract per reject reason. This is a
    # soft score for ranking — the hard decision is ``passes_taste``.
    score = 1.0
    for reason in reject_reasons:
        if reason in ("template", "crm_tags", "keyword_stack", "sdr_bot"):
            score -= 0.40
        elif reason == "profile_restatement":
            score -= 0.25
        elif reason == "over_optimized":
            score -= 0.15
        elif reason == "length":
            score -= 0.10
    # Clamp.
    score = max(0.0, min(1.0, score))

    # Dedupe preserving order.
    seen: set[str] = set()
    dedup_reasons: list[str] = []
    for r in reject_reasons:
        if r not in seen:
            seen.add(r)
            dedup_reasons.append(r)

    passes = len(dedup_reasons) == 0

    human_reason: Optional[str] = None
    if dedup_reasons:
        human_reason = REJECT_REASONS.get(
            dedup_reasons[0], dedup_reasons[0]
        )

    return {
        "passes_taste": passes,
        "reject_reasons": dedup_reasons,
        "human_reason": human_reason,
        "violations": violations,
        "taste_score": round(score, 3),
    }


def evaluate_all(
    candidates: list[dict],
    profile: Optional[dict] = None,
) -> list[dict]:
    """
    Run the taste filter over every candidate and annotate each in
    place with a ``taste_filter`` verdict. Returns the same list.
    """
    for c in candidates or []:
        c["taste_filter"] = evaluate(c, profile=profile)
    return candidates or []
