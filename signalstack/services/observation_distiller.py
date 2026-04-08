"""
Observation Distiller.

Takes raw signals, profile context, notes, and company context and
produces a small set of concise, 1-sentence internal *observations*.
These observations — not the raw source blobs — are what the message
generator is allowed to reason about.

This is a deliberately thin, deterministic layer on top of the existing
signal_interpreter. The distinction is important:

- signal_interpreter.interpret_signals() compresses *each* raw signal.
- observation_distiller.distill() selects and de-duplicates the 1–3
  best observations across signals / notes / profile, so the generator
  has a small, sharp working set instead of a noisy list.

Hypothesis fallback
-------------------
When strong sources are thin, the distiller will also pull from the
``context_expansion`` layer's hypotheses. Hypothesis-sourced
observations are clearly labelled (``source="hypothesis"``, strength
``"hypothetical"``) and framed as possibilities so the generator can
reason about them without treating them as facts. This is the key
fix for the "LinkedIn-profile-only → empty output" bug.
"""
from __future__ import annotations

from typing import Optional

MAX_OBSERVATIONS = 3
MAX_OBSERVATION_CHARS = 140


def _short(text: str, limit: int = MAX_OBSERVATION_CHARS) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


def distill(context: dict) -> list[dict]:
    """
    Return up to 3 concise internal observations.

    Each observation:
        {
          "text": "Their team appears active around a Charlotte BTR/townhome opportunity.",
          "source": "signal|note|profile|company",
          "source_id": "...",
          "strength": "strong|moderate|weak",
        }
    """
    observations = context.get("observations") or []
    notes = context.get("notes") or []
    profile = context.get("profile") or {}
    company = context.get("company") or {}

    out: list[dict] = []
    seen_keys: set[str] = set()

    def _push(text: str, source: str, source_id: Optional[str], strength: str):
        key = (text or "").strip().lower()
        if not key or key in seen_keys:
            return
        seen_keys.add(key)
        out.append({
            "text": _short(text),
            "source": source,
            "source_id": source_id,
            "strength": strength,
        })

    # 1) Strong: compressed signal observations.
    for obs in observations:
        if len(out) >= MAX_OBSERVATIONS:
            break
        summary = obs.get("summary") or ""
        if not summary:
            continue
        stype = (obs.get("signal_type") or "").lower()
        if stype == "company_expansion":
            text = f"The company appears to be expanding; {summary}."
        elif stype == "hiring_activity":
            text = f"The team appears to be hiring around {summary}."
        elif stype in ("listing_activity", "deal_activity"):
            text = f"They may be close to an active capital markets process — {summary}."
        elif stype == "post_topic":
            text = f"Recent posting suggests focus on {summary}."
        else:
            text = f"Their team appears active around {summary}."
        _push(text, "signal", obs.get("signal_id"), "strong")

    # 2) Strong: user notes with real content.
    for n in notes:
        if len(out) >= MAX_OBSERVATIONS:
            break
        body = (n.get("body") or "").strip()
        if len(body) < 8:
            continue
        first = body.split(".")[0].strip()
        _push(f"Internal note: {first}.", "note", n.get("id"), "strong")

    # 3) Moderate: profile context blobs.
    if len(out) < MAX_OBSERVATIONS:
        topics = profile.get("featured_topics")
        if topics:
            _push(f"Profile emphasizes {topics}.", "profile", "featured_topics", "moderate")
    if len(out) < MAX_OBSERVATIONS:
        shared = profile.get("shared_context")
        if shared:
            _push(f"Shared context: {shared}.", "profile", "shared_context", "moderate")

    # 4) Moderate: company context.
    if len(out) < MAX_OBSERVATIONS and company:
        cname = company.get("name")
        ctype = company.get("company_type") or company.get("industry")
        if cname and ctype:
            _push(
                f"{cname} operates in the {ctype} space.",
                "company", company.get("id"), "moderate",
            )

    # 5) Hypothetical fallback: pull from the context_expansion layer
    #    when the real sources didn't fill us up. Hypotheses are
    #    framed as possibilities, never as claims — the generator
    #    must preserve that framing in the final message.
    if len(out) < MAX_OBSERVATIONS:
        expansion = context.get("context_expansion") or {}
        hypotheses = expansion.get("hypotheses") or []
        for h in hypotheses:
            if len(out) >= MAX_OBSERVATIONS:
                break
            text = (h.get("text") or "").strip()
            if not text:
                continue
            # Hypotheses already read as "likely / possibly / may be".
            # We capitalize the first letter and drop a trailing period
            # so the rendered observation reads naturally.
            pretty = text[0].upper() + text[1:] if text else text
            if not pretty.endswith("."):
                pretty = pretty + "."
            _push(
                pretty,
                "hypothesis",
                h.get("basis") or "default",
                "hypothetical",
            )

    return out
