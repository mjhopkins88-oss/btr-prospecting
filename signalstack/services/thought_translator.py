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

# Peer-voice lead-ins. These are used by the deterministic rewriter
# when it needs to turn a third-person insight ("teams leaning into X
# are solving for Y") into a first-person thought ("most groups
# right now seem more focused on Y than on X").
_PEER_LEAD_INS = (
    "most groups right now seem",
    "the pattern I keep noticing is that most teams",
    "my read right now is that a lot of folks",
    "feels like the real constraint right now is",
    "what I keep seeing is that teams",
)


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
    plain-language thought, strips tag stacks, and truncates to the
    max thought length.
    """
    insight_text = (insight.get("text") or "").strip()
    if not insight_text:
        return None

    rewritten = _to_peer_voice(insight_text)
    rewritten = _strip_tag_stacks(rewritten)
    if not rewritten:
        return None

    # If the rewrite didn't already start with a peer lead-in, pick
    # one based on the insight type so the thought sounds like an
    # internal observation rather than a subject-less clause.
    lower = rewritten.lower()
    already_peer = any(
        lower.startswith(p) for p in (
            "most", "feels like", "my read", "what i keep",
            "a lot of", "i keep", "the pattern",
        )
    )
    if not already_peer:
        insight_type = (insight.get("type") or "").lower()
        if insight_type in ("market_pattern", "trend"):
            lead = "feels like "
        elif insight_type == "timing":
            lead = "my read right now is that "
        elif insight_type in ("tension", "second_order"):
            lead = "the pattern I keep noticing is that "
        elif insight_type == "peer_pov":
            lead = "most folks in this seat seem to "
        else:
            lead = "what I keep seeing is that "
        rewritten = lead + rewritten

    if len(rewritten) > MAX_THOUGHT_CHARS:
        rewritten = rewritten[: MAX_THOUGHT_CHARS - 1].rsplit(" ", 1)[0] + "…"

    return {
        "id": f"thought-{index}",
        "based_on_insight_id": insight.get("id"),
        "text": rewritten,
        "angle_hint": (insight.get("type") or "trend"),
        "source": "heuristic",
    }


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
      * max length truncation.
    """
    out: list[dict] = []
    for i, raw in enumerate(ai_thoughts or []):
        if not isinstance(raw, dict):
            continue
        text = (raw.get("text") or raw.get("thought") or "").strip()
        if not text:
            continue
        text = _strip_tag_stacks(text)
        if len(text) > MAX_THOUGHT_CHARS:
            text = text[: MAX_THOUGHT_CHARS - 1].rsplit(" ", 1)[0] + "…"
        based_on = raw.get("based_on_insight_id")
        if not based_on and i < len(insights or []):
            based_on = insights[i].get("id")
        out.append({
            "id": f"thought-{i}",
            "based_on_insight_id": based_on,
            "text": text,
            "angle_hint": (raw.get("angle_hint") or "trend"),
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
    """
    insights = context.get("insights") or []
    if not insights:
        return {"thoughts": [], "source": "heuristic", "error": None}

    # Always compute the deterministic branch first so we have a
    # guaranteed non-empty fallback.
    fallback = _deterministic_thoughts(insights)

    if provider is None or not callable(getattr(provider, "translate_thoughts", None)):
        return {"thoughts": fallback, "source": "heuristic", "error": None}

    try:
        raw = provider.translate_thoughts(context)
    except Exception as e:
        print(
            f"[SignalStack] thought_translator: provider translate_thoughts "
            f"FAILED — falling back to heuristic: {type(e).__name__}: {e}"
        )
        return {
            "thoughts": fallback,
            "source": "heuristic",
            "error": f"provider_translation_failed:{type(e).__name__}",
        }

    ai_thoughts = _normalize_ai_thoughts(raw or [], insights)
    if not ai_thoughts:
        return {
            "thoughts": fallback,
            "source": "heuristic",
            "error": "ai_thoughts_empty",
        }

    # Hybrid: prefer AI but keep heuristic fallback as backfill so we
    # always have at least one thought per insight.
    hybrid = ai_thoughts
    if fallback and len(hybrid) < len(insights):
        hybrid = hybrid + fallback[len(hybrid):]
    return {
        "thoughts": hybrid[:MAX_THOUGHTS],
        "source": "ai" if len(hybrid) == len(ai_thoughts) else "hybrid",
        "error": None,
    }
