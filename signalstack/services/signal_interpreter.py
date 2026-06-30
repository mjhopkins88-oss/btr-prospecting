"""
Signal Interpretation Layer.

Converts raw signals (which may contain long pasted posts, listings, or
news articles) into short, structured *observations* that the message
generator is allowed to reference.

The generator must NEVER consume `signal["text"]` directly. It should
consume the compressed `observation` produced here. This is the primary
fix for the bug where the generator was pasting raw listing/post bodies
straight into LinkedIn messages.

Heuristic-only — no LLM required. Deterministic and safe for tests.
"""
from __future__ import annotations

import re
from typing import Optional

# Keyword vocab we recognize as "topic anchors". Anything outside this
# list is treated as raw source text and is *not* surfaced verbatim.
TOPIC_KEYWORDS = {
    "btr", "build-to-rent", "build to rent",
    "townhome", "townhomes", "sfr", "single-family", "multifamily",
    "listing", "fund", "capital markets", "acquisition", "acquisitions",
    "hiring", "expansion", "launch", "raise", "close", "deal",
    "development", "portfolio", "pipeline", "joint venture",
}

# Common US metros / states we'll allow as a location anchor.
# Ordered: prefer specific cities over state abbreviations.
KNOWN_PLACES = [
    "Charlotte", "Raleigh", "Durham", "Atlanta", "Nashville", "Phoenix",
    "Dallas", "Houston", "Austin", "Tampa", "Orlando", "Miami", "Denver",
    "Boise", "Salt Lake City", "Las Vegas", "Jacksonville", "Charleston",
    "Greenville", "Asheville", "Birmingham", "Memphis", "Indianapolis",
    "Columbus", "NC", "SC", "GA", "TN", "FL", "TX", "AZ", "CO",
]

MAX_OBSERVATION_CHARS = 140


def _find_place(text: str) -> Optional[str]:
    for place in KNOWN_PLACES:
        if re.search(rf"\b{re.escape(place)}\b", text):
            return place
    return None


def _find_topics(text: str) -> list[str]:
    lo = text.lower()
    hits = []
    for kw in TOPIC_KEYWORDS:
        if kw in lo and kw not in hits:
            hits.append(kw)
    return hits[:3]


def _compress_text(text: str) -> str:
    """Return a 1-sentence neutral summary of arbitrary signal text."""
    text = (text or "").strip()
    if not text:
        return ""
    place = _find_place(text)
    topics = _find_topics(text)

    if place and topics:
        topic_phrase = "/".join(topics[:2])
        return f"recent activity around {place} {topic_phrase}"
    if place:
        return f"some recent movement in {place}"
    if topics:
        return f"recent activity around {topics[0]}"
    # Last-resort: take the first short clause, but cap hard so we
    # never pass a long pasted block downstream.
    first = re.split(r"[.\n!?]", text, maxsplit=1)[0].strip()
    if len(first) > 80:
        first = first[:77].rsplit(" ", 1)[0] + "…"
    return first


def interpret_signal(signal: dict) -> dict:
    """
    Convert a raw signal into a structured observation.

    Returns a dict suitable for the generator to use, e.g.:
        {
          "signal_id": "...",
          "summary": "recent activity around Charlotte BTR/townhome",
          "relevance_reason": "Listing/post indicates active capital markets process",
          "safe_reference_text": "a new Charlotte BTR opportunity",
          "message_angle_candidates": ["timing_context", "curiosity"],
          "is_reference_safe": True,
          "raw_length": 1842,
        }
    """
    raw = (signal.get("text") or "").strip()
    summary = _compress_text(raw)
    place = _find_place(raw)
    topics = _find_topics(raw)
    stype = (signal.get("type") or "").lower()

    # Build a *very* short safe-reference snippet — this is the only
    # phrase derived from the source that the generator may use.
    if place and topics:
        safe_ref = f"a new {place} {topics[0]} opportunity"
    elif place:
        safe_ref = f"some movement in {place}"
    elif topics:
        safe_ref = f"a new {topics[0]} opportunity"
    elif stype == "hiring_activity":
        safe_ref = "the recent hiring push"
    elif stype == "company_expansion":
        safe_ref = "the team's recent expansion"
    elif stype in ("company_news", "post_topic"):
        safe_ref = "your team's recent activity"
    else:
        safe_ref = summary or "your recent activity"

    if stype in ("post_topic", "company_news") or len(raw) > 240:
        relevance = "Source is long-form content; compressed to a single observation."
    else:
        relevance = f"Signal type {stype or 'observation'} compressed for outreach."

    angles = ["curiosity", "timing_context", "observation"]

    return {
        "signal_id": signal.get("id"),
        "signal_type": stype,
        "summary": summary,
        "relevance_reason": relevance,
        "safe_reference_text": safe_ref[:MAX_OBSERVATION_CHARS],
        "message_angle_candidates": angles,
        "is_reference_safe": True,
        "raw_length": len(raw),
    }


def interpret_signals(signals: list[dict]) -> list[dict]:
    return [interpret_signal(s) for s in signals or []]
