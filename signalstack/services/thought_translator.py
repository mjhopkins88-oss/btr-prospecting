"""
Thought Translation Layer.

This module sits BETWEEN the insight engine and the message generator.
It exists because of a specific failure mode we observed: when the
generator was handed a sharp insight *plus* the raw profile context
(featured topics, keywords, about-text), it would reliably stitch
keywords from the profile into the final message. The result was
something like:

    "Curious how you're thinking about build to rent, commercial real
     estate, insurance — how's that going?"

Technically grounded, unmistakably unnatural. CRM-tag prose.

The fix is a translation step that converts each insight into a
plain-language, peer-voice "internal thought" BEFORE the generator
is allowed to see it. Crucially:

  * the thought is written as a sentence a human would actually think,
    not as a topic list;
  * it strips out keyword stacks, industry acronyms, and profile
    fragments that would otherwise leak into the final message;
  * it is the ONLY source of insight-derived phrasing the message
    generator is allowed to use.

Downstream the generate_user.txt prompt explicitly tells Claude to
write FROM the internal thought — not from the profile keywords, the
featured topics list, or the raw observation text. The naturalness
validator then rejects any message that still reads like a stitched
keyword summary.

Shape of a translated thought:

    {
        "id": "thought-0",
        "based_on_insight_id": "insight-0",
        "text": "most groups right now seem more constrained by cost than chasing demand",
        "angle_hint": "market_pattern",
        "source": "ai|heuristic",
    }

The module has two execution paths:

  1) Deterministic / rule-based fallback. Always works. No network.
     Rewrites the insight text into peer voice using simple lexical
     substitutions ("teams" → "most groups", "tends to" → "seems to",
     etc.) and strips any comma-separated keyword stack that the
     insight inherited from the profile.

  2) AI-augmented path (Claude). Used when the configured AI provider
     exposes a ``translate_thoughts`` method. The deterministic output
     is always kept as a safety fallback so a provider failure never
     crashes the generator.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from .style_modes import normalize_thought_type, THOUGHT_TYPES

# The pipeline aims to give the generator FIVE candidate thoughts
# before any message is written. When the upstream insight engine
# produced fewer insights, we top up with typed fallback thoughts
# drawn from the context_expansion hypotheses so the generator
# always has a full set of five distinct reasoning lenses.
TARGET_THOUGHTS = 5
MAX_THOUGHTS = 5
MAX_THOUGHT_CHARS = 180

# Industry / CRM-tag words that should NEVER appear verbatim in an
# internal thought. If we see them in the insight text, we either
# paraphrase them away ("build-to-rent" → "this kind of build") or
# drop them entirely. The goal is a sentence that sounds like a
# thought, not a profile summary.
#
# This list is intentionally conservative — we only strip terms that
# have been observed leaking into messages as topic-list prose. Real
# peer-voice can still reference a market by name when it's the
# subject of the sentence, not a tag in a list.
_TAG_LIKE_TERMS = (
    "build to rent", "build-to-rent", "btr",
    "commercial real estate", "cre",
    "multifamily", "sfr", "townhomes",
    "capital markets", "asset management",
    "insurance", "wealth management",
    "fintech", "proptech", "saas",
)

# Vague floating phrases that are NOT contextual anchors. A thought
# that leans on any of these lacks a "where this shows up" anchor
# and must be rewritten so it lands on a real operating surface
# (pipeline, underwriting, newer deals, lease-up, capital
# allocation, deal execution, etc.).
#
# Replacements here are deliberate: we swap the vague phrase for a
# concrete operating surface so the final thought still reads as a
# complete sentence. The replacement list is intentionally short —
# downstream the generator and critic will push for stronger
# anchors where possible.
# Each entry is (pattern, replacement). The pattern is a regex
# (case-insensitive) that intentionally captures the leading
# preposition ("in", "of", "across") when present so the anchor
# substitution doesn't leave "in on newer deals" style grammar. When
# no leading preposition is captured we just drop in the anchor.
_VAGUE_ANCHOR_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (r"\bin\s+this\s+slice\s+of\s+the\s+market\b", "on newer deals"),
    (r"\bin\s+this\s+slice\s+of\s+the\s+business\b", "in your pipeline"),
    (r"\bin\s+this\s+slice\b", "on newer deals"),
    (r"\bin\s+this\s+part\s+of\s+the\s+market\b", "on newer deals"),
    (r"\bin\s+this\s+part\s+of\s+the\s+business\b", "in your pipeline"),
    (r"\bin\s+this\s+kind\s+of\s+market\b", "on newer deals"),
    (r"\bin\s+this\s+side\s+of\s+the\s+business\b", "in your pipeline"),
    (r"\bin\s+this\s+side\s+of\s+the\s+market\b", "on newer deals"),
    (r"\bin\s+this\s+segment\s+of\s+the\s+market\b", "on newer deals"),
    (r"\bin\s+this\s+segment\b", "on newer deals"),
    (r"\bin\s+this\s+space\b", "in your pipeline"),
    (r"\bin\s+today'?s\s+market\b", "on newer deals"),
    (r"\bin\s+the\s+current\s+environment\b", "once deals get closer to execution"),
    (r"\bof\s+this\s+slice\s+of\s+the\s+market\b", "of newer deals"),
    (r"\bof\s+this\s+part\s+of\s+the\s+market\b", "of newer deals"),
    (r"\bof\s+this\s+segment\b", "of newer deals"),
    # Bare noun-phrase forms (no leading preposition): plain swap.
    (r"\bthis\s+slice\s+of\s+the\s+market\b", "newer deals"),
    (r"\bthis\s+slice\s+of\s+the\s+business\b", "your pipeline"),
    (r"\bthis\s+slice\b", "newer deals"),
    (r"\bthis\s+part\s+of\s+the\s+market\b", "newer deals"),
    (r"\bthis\s+part\s+of\s+the\s+business\b", "your pipeline"),
    (r"\bthis\s+kind\s+of\s+market\b", "newer deals"),
    (r"\bthis\s+side\s+of\s+the\s+business\b", "your pipeline"),
    (r"\bthis\s+side\s+of\s+the\s+market\b", "newer deals"),
    (r"\bthis\s+segment\s+of\s+the\s+market\b", "newer deals"),
    (r"\bthis\s+segment\b", "newer deals"),
    (r"\bthis\s+space\b", "your pipeline"),
    (r"\bthe\s+current\s+environment\b", "once deals get closer to execution"),
    (r"\btoday'?s\s+market\b", "newer deals"),
)


def _replace_vague_anchors(text: str) -> str:
    """
    Swap vague floating phrases for real operating-surface anchors.

    These phrases are banned by the generator / critic prompts because
    they are not anchors — they float. When a heuristic or AI-produced
    thought slips one through, we rewrite it here so the downstream
    message is still grounded on a real operating surface.

    Patterns intentionally capture the leading preposition when
    present so the rewrite produces natural grammar ("on newer deals"
    instead of "in on newer deals").
    """
    if not text:
        return text
    out = text
    for pattern, anchor in _VAGUE_ANCHOR_REPLACEMENTS:
        out = re.sub(pattern, anchor, out, flags=re.IGNORECASE)
    # Collapse any double spaces the substitutions may have left.
    out = re.sub(r"\s{2,}", " ", out).strip()
    return out

# Peer-voice lead-ins. These are used by the deterministic rewriter
# when it needs to turn a third-person insight into a first-person
# thought written THROUGH the sender's lens (risk, timing, deal
# execution, being pulled in late).
#
# The lead-ins intentionally use lens-first phrasings ("we see this
# a lot when…", "this usually shows up once…", "we often get pulled
# in when…") so every thought sounds like it came from inside the
# deal process, not from an outside market commentator. The old
# "pattern I keep noticing" phrasing is deliberately EXCLUDED — it
# reads like a newsletter, not an operator.
_PEER_LEAD_INS = (
    "we see this a lot when",
    "this usually shows up once",
    "we often get pulled in when",
    "by the time this hits our desk",
    "the thing we keep running into is",
)

# Phrasings that used to slip through from the insight engine and
# made thoughts read like newsletter commentary instead of operator
# voice. When we see these at the head of an insight we strip them
# and let the lens-first lead-in take over.
#
# Each entry is (pattern, replacement). Use short, anchored
# replacements so the rewrite still reads as a complete sentence.
_ANALYST_OPENER_REWRITES: tuple[tuple[str, str], ...] = (
    (r"^the pattern i keep noticing is that\s+", "we see this a lot when "),
    (r"^the pattern i keep seeing is that\s+", "we see this a lot when "),
    (r"^the pattern i keep noticing is\s+", "we see this a lot when "),
    (r"^the pattern i keep seeing is\s+", "we see this a lot when "),
    (r"^a pattern i keep noticing is\s+", "we see this a lot when "),
    (r"^the trend suggests that\s+", "we see this a lot when "),
    (r"^the trend suggests\s+", "we see this a lot when "),
    (r"^what i keep seeing is that\s+", "we see this a lot when "),
    (r"^what i keep seeing is\s+", "we see this a lot when "),
    (r"^i keep seeing that\s+", "we see this a lot when "),
    (r"^feels like the market is\s+", "we see this a lot when the market is "),
)


_TAIL_PREPOSITIONS = ("on ", "in ", "once ", "when ", "during ", "at ", "after ", "before ")


def _rewrite_analyst_openers(text: str) -> str:
    """
    Strip analyst / newsletter openers ("the pattern I keep noticing
    is…") and replace them with lens-first operator voice ("we see
    this a lot when…"). This keeps the thought grounded in the
    sender's seat instead of drifting into market commentary.

    When the tail after the opener already starts with a preposition
    ("on newer deals", "in the pipeline", "once deals get…"), we
    drop the trailing "when " from the replacement to avoid
    double-preposition phrasing like "we see this a lot when on
    newer deals". The result reads more naturally as "we see this
    a lot on newer deals".
    """
    if not text:
        return text
    out = text.strip()
    lowered = out.lower()
    for pattern, replacement in _ANALYST_OPENER_REWRITES:
        match = re.match(pattern, lowered)
        if not match:
            continue
        tail = out[match.end():]
        tail_lower = tail.lower().lstrip()
        # Strip the trailing "when " from the replacement when the
        # tail already carries a preposition of its own.
        if replacement.endswith("when ") and any(
            tail_lower.startswith(p) for p in _TAIL_PREPOSITIONS
        ):
            replacement = replacement[: -len("when ")]
        out = replacement + tail
        break
    return out


def _strip_tag_stacks(text: str) -> str:
    """
    Remove comma-separated CRM-tag stacks from ``text`` without
    mangling real prose.

    We ONLY remove a comma-separated run when at least two of the
    items in the run are tag-like terms from ``_TAG_LIKE_TERMS``.
    This prevents us from stripping legitimate "..., and ..." sentence
    rhythm while reliably killing "build to rent, commercial real
    estate, insurance" style prose.
    """
    if not text:
        return text
    lo = text.lower()
    # Quick exit: if the text contains no tag-like terms at all, do nothing.
    hits = [t for t in _TAG_LIKE_TERMS if t in lo]
    if len(hits) < 2:
        return text
    # Find runs of ",X, Y, Z" where at least 2 of X/Y/Z are tag terms.
    # We walk comma groups and rebuild the sentence.
    def _is_tagish(chunk: str) -> bool:
        c = chunk.strip().lower()
        return any(t == c or t in c for t in _TAG_LIKE_TERMS)

    parts = re.split(r"(,\s*)", text)
    # Group tokens into (content, separator) pairs.
    cleaned: list[str] = []
    skip_next_sep = False
    for i, part in enumerate(parts):
        if re.fullmatch(r",\s*", part):
            if skip_next_sep:
                skip_next_sep = False
                continue
            cleaned.append(part)
            continue
        if _is_tagish(part):
            # Drop this fragment entirely and the comma that follows it.
            skip_next_sep = True
            continue
        cleaned.append(part)
    out = "".join(cleaned)
    # Collapse any ", ," or leading/trailing commas left behind.
    out = re.sub(r",\s*,", ",", out)
    out = re.sub(r"(?:^|\s),\s+", " ", out)
    out = re.sub(r"\s{2,}", " ", out).strip(" ,.")
    return out or text


def _to_peer_voice(insight_text: str) -> str:
    """
    Rewrite an insight sentence into plain-language peer voice.

    Deterministic, side-effect-free. Does NOT invent new content —
    only reshapes the insight so it sounds like something a human
    might actually think, rather than a structured analyst note.
    """
    text = (insight_text or "").strip()
    if not text:
        return ""

    # Drop analyst-report openings that double-stack with our peer
    # lead-in. We only strip openers that leave a grammatical tail
    # when the lead-in is re-attached — never strip a bare subject
    # like "Teams" because that leaves a dangling participle.
    text = re.sub(
        r"^(?:the interesting tension is that|the signal itself isn't the point — what matters is)\s+",
        "",
        text,
        flags=re.IGNORECASE,
    )
    # Normalize "A lot of the groups" / "A lot of groups" / "A lot
    # of teams" to just "a lot of groups" so the downstream
    # `already_peer` check recognizes it and we don't attach a
    # second "most groups" lead-in on top.
    text = re.sub(
        r"^a lot of (?:the )?(groups|teams)\b",
        r"a lot of \1",
        text,
        flags=re.IGNORECASE,
    )

    # Analyst → peer lexical substitutions. Each pair turns a
    # research-report phrase into something that sounds like an
    # off-the-cuff observation.
    subs = [
        (r"\busually\b", "often"),
        (r"\btends to\b", "seems to"),
        (r"\btend to\b", "seem to"),
        (r"\bsecond[- ]order effects\b", "downstream stuff"),
        (r"\bfirst[- ]order effects\b", "immediate stuff"),
        (r"\btrade[- ]off\b", "tradeoff"),
        (r"\btiming window\b", "window"),
        (r"\bcost of capital\b", "cost of capital"),  # keep
        (r"\bcost pressure\b", "cost pressure"),  # keep
        (r"\bpure demand\b", "demand"),
        (r"\bconviction\b", "a decision already made"),
        (r"\bunderwriting bar\b", "bar for underwriting"),
    ]
    for pat, rep in subs:
        text = re.sub(pat, rep, text, flags=re.IGNORECASE)

    # If the insight starts with "A lot of the groups leaning into
    # townhome/BTR right now are solving for cost pressure more than
    # pure demand" we want something like "most folks in this kind
    # of build seem more constrained by cost than demand right now".
    # This is handled downstream by the lead-in + tag stripping; we
    # just lowercase the first letter so the final assembly flows.
    if text:
        text = text[0].lower() + text[1:]

    return text


def _deterministic_thought(
    insight: dict,
    index: int,
) -> Optional[dict]:
    """Produce one peer-voice thought from one insight.

    Never invents facts. Only rewrites the insight text into a
    plain-language thought, strips tag stacks, swaps analyst
    openers for lens-first phrasings, and truncates to the max
    thought length. Every returned thought carries a
    ``thought_type`` from the closed product vocabulary so the
    downstream generator can reason about the KIND of thought it
    is working with (pattern recognition vs timing vs contrarian
    observation etc.).
    """
    insight_text = (insight.get("text") or "").strip()
    if not insight_text:
        return None

    rewritten = _rewrite_analyst_openers(insight_text)
    rewritten = _to_peer_voice(rewritten)
    rewritten = _strip_tag_stacks(rewritten)
    rewritten = _replace_vague_anchors(rewritten)
    if not rewritten:
        return None

    # If the rewrite didn't already start with a peer lead-in, pick
    # one based on the insight type so the thought sounds like an
    # operator observation from inside the deal process rather than
    # a subject-less clause. The lead-ins are all lens-first: they
    # put the sender inside the process ("we see this a lot when",
    # "we often get pulled in when", etc.) instead of outside
    # commenting on the market.
    lower = rewritten.lower()
    already_peer = any(
        lower.startswith(p) for p in (
            "we see", "we often", "by the time", "this usually",
            "this tends", "the thing we keep", "we keep",
            "most folks", "most groups",
        )
    )
    if not already_peer:
        insight_type = (insight.get("type") or "").lower()
        if insight_type in ("market_pattern", "trend", "pattern_recognition"):
            lead = "we see this a lot when "
        elif insight_type in ("timing", "timing_insight"):
            lead = "this usually shows up once "
        elif insight_type in ("tension", "tension_tradeoff"):
            lead = "the thing we keep running into is that "
        elif insight_type in ("second_order", "second_order_effect"):
            lead = "by the time this hits our desk, "
        elif insight_type in ("contrarian", "contrarian_observation"):
            lead = "the default read is one thing, but we see this a lot when "
        elif insight_type in ("peer_pov", "self_relevance"):
            lead = "most folks in this seat seem to "
        else:
            lead = "we see this a lot when "
        rewritten = lead + rewritten

    if len(rewritten) > MAX_THOUGHT_CHARS:
        rewritten = rewritten[: MAX_THOUGHT_CHARS - 1].rsplit(" ", 1)[0] + "…"

    thought_type = normalize_thought_type(insight.get("type"))
    return {
        "id": f"thought-{index}",
        "based_on_insight_id": insight.get("id"),
        "text": rewritten,
        "angle_hint": (insight.get("type") or "trend"),
        "thought_type": thought_type,
        "source": "heuristic",
    }


# Type-specific fallback thoughts. These are used to top up the
# candidate set when the insight engine produced fewer than 5 real
# insights. They are intentionally broad — framed as possibilities,
# never as claims — and each one is typed to a DIFFERENT product
# vocabulary slot so the final set of 5 carries genuine diversity.
#
# Every fallback is:
#   * ANCHORED on a real operating surface ("on newer deals", "in
#     the pipeline", "when underwriting gets deeper", "on newer
#     communities", "once deals get closer to execution", etc.);
#   * LENSED through the sender's seat — risk, timing, deal
#     execution, being pulled in too late. Neutral market
#     commentary is deliberately avoided.
#
# Floating phrases like "this part of the market", "this space",
# "this slice", "this slice of the market" are explicitly banned.
# "Pattern I keep noticing" / newsletter voice is also banned —
# the whole point of the fallback is to sound like someone who
# sees risk across many deals and is usually pulled in too late,
# not a market-commentary bot.
_FALLBACK_THOUGHTS_BY_TYPE: dict[str, list[str]] = {
    "pattern_recognition": [
        "we see this a lot on newer BTR deals — the groups still moving are usually the ones who already rebuilt their risk assumptions before underwriting went deep",
        "we see this a lot when the pipeline starts moving faster than the risk work behind it — the trouble usually lands later, not up front",
    ],
    "tension_tradeoff": [
        "the thing we keep running into when underwriting gets deeper is that the real tradeoff isn't demand, it's whether the risk side can keep pace with the capital side",
        "on newer deals, the tradeoff we keep running into is sourcing speed versus how much of the risk work has actually been done",
    ],
    "contrarian_observation": [
        "the default read on newer communities is that growth is the question — but by the time deals hit our desk, it's usually about who can still execute without the risk side slipping",
        "the default read on the pipeline is that deal flow is the constraint — we see this a lot when it's actually the risk bar that's moved, not the flow",
    ],
    "timing_insight": [
        "this usually shows up once deals get closer to execution — the window for the next set of risk-side decisions is narrower than most timelines assume",
        "we often get pulled in when the timing of a decision has already started shaping the deal, rather than the other way around",
    ],
    "second_order_effect": [
        "a capital allocation shift on newer communities usually reshuffles what shows up on the risk side of underwriting inside a quarter",
        "by the time this hits our desk, the downstream thing we keep seeing is that a capital shift on newer deals lands in sourcing before anywhere else",
    ],
    "self_relevance": [
        "most folks in this seat seem to be weighing the same question on newer deals — whether the read they were underwriting against six months ago still holds, and where the risk side sits now",
        "we often get pulled in on newer deals exactly at the point where someone in that seat is trying to figure out which of their assumptions still holds",
    ],
}


def _fallback_thought(
    thought_type: str,
    index: int,
    used_texts: set[str],
) -> Optional[dict]:
    """
    Build one fallback thought for ``thought_type``. Skips any template
    whose normalized text has already been used in the current set,
    so the final set of 5 stays genuinely distinct.
    """
    templates = _FALLBACK_THOUGHTS_BY_TYPE.get(thought_type) or []
    for text in templates:
        key = re.sub(r"\s+", " ", text.strip().lower())
        if key in used_texts:
            continue
        used_texts.add(key)
        clipped = text.strip()
        if len(clipped) > MAX_THOUGHT_CHARS:
            clipped = clipped[: MAX_THOUGHT_CHARS - 1].rsplit(" ", 1)[0] + "…"
        return {
            "id": f"thought-{index}",
            "based_on_insight_id": None,
            "text": clipped,
            "angle_hint": thought_type,
            "thought_type": thought_type,
            "source": "fallback",
        }
    return None


def _top_up_to_target(
    thoughts: list[dict],
    target: int = TARGET_THOUGHTS,
) -> list[dict]:
    """
    Ensure the returned thought list carries at least ``target``
    entries by synthesizing typed fallback thoughts from
    ``_FALLBACK_THOUGHTS_BY_TYPE``.

    * Existing thoughts keep their original text and type.
    * Missing types are filled in rotation through ``THOUGHT_TYPES``
      so the final set carries maximum type diversity.
    * Fallback thoughts are clearly labelled ``source="fallback"``.
    """
    if len(thoughts) >= target:
        return thoughts[:target]

    used_texts: set[str] = set()
    used_types: set[str] = set()
    for t in thoughts:
        txt = (t.get("text") or "").strip().lower()
        if txt:
            used_texts.add(re.sub(r"\s+", " ", txt))
        tt = (t.get("thought_type") or "").strip().lower()
        if tt:
            used_types.add(tt)

    # Preferred fill order: any type we haven't seen yet, in the
    # canonical product vocabulary order.
    fill_order = [t for t in THOUGHT_TYPES if t not in used_types]
    # If we've already used every type at least once, allow a
    # second pass so we can still reach the target.
    fill_order += list(THOUGHT_TYPES)

    out = list(thoughts)
    i = len(out)
    for tt in fill_order:
        if len(out) >= target:
            break
        fb = _fallback_thought(tt, index=i, used_texts=used_texts)
        if fb is None:
            continue
        out.append(fb)
        i += 1
    return out[:target]


def _deterministic_thoughts(insights: list[dict]) -> list[dict]:
    out: list[dict] = []
    for i, insight in enumerate(insights or []):
        if len(out) >= MAX_THOUGHTS:
            break
        t = _deterministic_thought(insight, len(out))
        if t:
            out.append(t)
    return out


def _normalize_ai_thoughts(
    ai_thoughts: list[dict],
    insights: list[dict],
) -> list[dict]:
    """Accept AI-produced thoughts and shape them for downstream.

    We enforce:
      * a valid based_on_insight_id (fall back to insights[i].id),
      * tag-stack stripping (so AI-produced thoughts are still clean
        even if the model slipped a keyword list through),
      * max length truncation,
      * a typed ``thought_type`` drawn from the closed product
        vocabulary (pattern_recognition, tension_tradeoff,
        contrarian_observation, timing_insight, second_order_effect,
        self_relevance). Unknown values are projected onto the
        closest match.
    """
    out: list[dict] = []
    for i, raw in enumerate(ai_thoughts or []):
        if not isinstance(raw, dict):
            continue
        text = (raw.get("text") or raw.get("thought") or "").strip()
        if not text:
            continue
        text = _strip_tag_stacks(text)
        text = _replace_vague_anchors(text)
        if len(text) > MAX_THOUGHT_CHARS:
            text = text[: MAX_THOUGHT_CHARS - 1].rsplit(" ", 1)[0] + "…"
        based_on = raw.get("based_on_insight_id")
        if not based_on and i < len(insights or []):
            based_on = insights[i].get("id")
        raw_type = (
            raw.get("thought_type")
            or raw.get("type")
            or raw.get("angle_hint")
        )
        thought_type = normalize_thought_type(raw_type)
        out.append({
            "id": f"thought-{i}",
            "based_on_insight_id": based_on,
            "text": text,
            "angle_hint": (raw.get("angle_hint") or thought_type),
            "thought_type": thought_type,
            "source": "ai",
        })
        if len(out) >= MAX_THOUGHTS:
            break
    return out


def translate_insights(
    context: dict,
    provider: Optional[Any] = None,
) -> dict:
    """Produce internal thoughts from the insights in ``context``.

    Returns:
        {
          "thoughts": [...],
          "source": "ai|heuristic|hybrid",
          "error": Optional[str],
        }

    Never raises. On provider failure falls back to the deterministic
    branch and records the failure under ``error``.

    The pipeline aims to hand the generator exactly five candidate
    thoughts. When the insight engine produced fewer insights than
    that — which is the common case on thin LinkedIn-only inputs —
    the result is topped up with typed fallback thoughts drawn from
    the closed product vocabulary. Every returned thought carries
    a ``thought_type`` so the downstream generator can route each
    thought to a distinct style mode without re-deriving the type.
    """
    insights = context.get("insights") or []

    # Always compute the deterministic branch first so we have a
    # guaranteed non-empty fallback.
    fallback = _deterministic_thoughts(insights)

    if provider is None or not callable(getattr(provider, "translate_thoughts", None)):
        topped = _top_up_to_target(fallback, target=TARGET_THOUGHTS)
        return {"thoughts": topped, "source": "heuristic", "error": None}

    try:
        raw = provider.translate_thoughts(context)
    except Exception as e:
        print(
            f"[SignalStack] thought_translator: provider translate_thoughts "
            f"FAILED — falling back to heuristic: {type(e).__name__}: {e}"
        )
        topped = _top_up_to_target(fallback, target=TARGET_THOUGHTS)
        return {
            "thoughts": topped,
            "source": "heuristic",
            "error": f"provider_translation_failed:{type(e).__name__}",
        }

    ai_thoughts = _normalize_ai_thoughts(raw or [], insights)
    if not ai_thoughts:
        topped = _top_up_to_target(fallback, target=TARGET_THOUGHTS)
        return {
            "thoughts": topped,
            "source": "heuristic",
            "error": "ai_thoughts_empty",
        }

    # Hybrid: prefer AI but keep heuristic fallback as backfill so we
    # always have at least one thought per insight. Then top up with
    # typed fallback thoughts so we always return exactly
    # TARGET_THOUGHTS distinct thoughts to the generator.
    hybrid = ai_thoughts
    if fallback and len(hybrid) < len(insights):
        hybrid = hybrid + fallback[len(hybrid):]
    hybrid = _top_up_to_target(hybrid, target=TARGET_THOUGHTS)
    return {
        "thoughts": hybrid[:MAX_THOUGHTS],
        "source": "ai" if len(hybrid) == len(ai_thoughts) else "hybrid",
        "error": None,
    }
