"""
Knowledge extraction service.

Converts a raw knowledge source (raw_text + summary + notes) into a list
of structured knowledge_entries that the generator can later consult as
strategy/style/angle guidance.

Design:
  * Provider-agnostic. The service first tries the AI provider's
    `extract_knowledge` method if it exists; otherwise it falls back to
    a deterministic mock that always produces sensible starter entries.
  * Never crashes the route layer — extraction failures degrade to the
    mock path and the source's extraction_status is left unchanged so
    the user can retry.
  * Generated entries are NOT prospect facts. They are strategy/style
    knowledge — see KNOWLEDGE_ENTRY_CATEGORIES in signalstack/types.py.
"""
from __future__ import annotations

import re
from typing import Optional

from . import repo as kn_repo
from ..ai.provider import get_provider
from ..types import KNOWLEDGE_ENTRY_CATEGORIES


# ----------------------- Utility -----------------------

def _split_sentences(text: str) -> list[str]:
    if not text:
        return []
    # Lightweight splitter — good enough for chunking notes/transcripts
    # without pulling in nltk. Keeps things deterministic for the mock.
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\"'\(])", text.strip())
    return [p.strip() for p in parts if p and p.strip()]


def _first_n_words(text: str, n: int = 12) -> str:
    words = (text or "").split()
    return " ".join(words[:n]) + ("…" if len(words) > n else "")


def _guess_category(sentence: str) -> str:
    s = (sentence or "").lower()
    if any(k in s for k in ("curious", "ask", "question", "wonder")):
        return "curiosity"
    if any(k in s for k in ("trust", "credibility", "honesty", "earn")):
        return "trust_building"
    if any(k in s for k in ("specific", "concrete", "named", "number", "metric")):
        return "specificity"
    if any(k in s for k in ("recent", "today", "this week", "timely", "window")):
        return "timing"
    if any(k in s for k in ("peer", "pattern", "operators", "industry", "market")):
        return "industry_pattern"
    if any(k in s for k in ("template", "generic", "sdr", "vendor", "boilerplate")):
        return "anti_template"
    if any(k in s for k in ("tone", "voice", "casual", "peer", "warm")):
        return "tone"
    if any(k in s for k in ("frame", "framing", "angle", "lens")):
        return "framing"
    if any(k in s for k in ("relevance", "relevant", "tied to")):
        return "relevance"
    if any(k in s for k in ("authority", "show, don't claim", "expertise")):
        return "authority_without_chest_beating"
    if any(k in s for k in ("objection", "no agenda", "low pressure", "easy reply")):
        return "objection_softening"
    if any(k in s for k in ("social proof", "case study", "logos")):
        return "social_proof"
    return "outreach_angle"


def _coerce_category(cat: Optional[str]) -> str:
    if cat and cat in KNOWLEDGE_ENTRY_CATEGORIES:
        return cat
    return "other"


# ----------------------- Mock extractor -----------------------

def mock_extract(source: dict) -> list[dict]:
    """Deterministically derive 1–6 starter knowledge entries from a source.

    The mock favors *useful starter scaffolding* over magic — it will
    always produce something, even if the only thing the user gave us
    is a title and a notes blob. The user can edit/curate from there.
    """
    title = (source.get("title") or "Untitled source").strip()
    summary = (source.get("summary") or "").strip()
    notes = (source.get("notes") or "").strip()
    raw = (source.get("raw_text") or "").strip()

    # 1) Pull candidate sentences from raw_text → notes → summary, in
    #    that order, capped to keep things readable.
    candidates: list[str] = []
    for blob in (raw, notes, summary):
        for s in _split_sentences(blob):
            if 30 <= len(s) <= 280 and s not in candidates:
                candidates.append(s)
            if len(candidates) >= 6:
                break
        if len(candidates) >= 6:
            break

    # 2) If we still have nothing, fabricate one entry from the title /
    #    summary so the source isn't left empty.
    if not candidates:
        seed = summary or notes or raw or f"Knowledge from {title}"
        candidates = [seed[:240]]

    entries: list[dict] = []
    for i, sentence in enumerate(candidates):
        cat = _guess_category(sentence)
        principle = _first_n_words(sentence, 8) or f"{title} insight #{i+1}"
        entries.append({
            "category": _coerce_category(cat),
            "principle_name": principle.strip().rstrip(".") or f"Insight #{i+1}",
            "description": sentence,
            "practical_use_case": f"Apply when crafting outreach where '{cat}' matters.",
            "allowed_contexts": "Use as tone/framing guidance only — never quote verbatim into a message.",
            "disallowed_contexts": "Do not paste this text into a prospect message.",
            "example_pattern": None,
            "anti_pattern": None,
            "confidence": 0.7,
            "active": True,
        })
    return entries


# ----------------------- Public API -----------------------

def extract_for_source(source_id: str) -> dict:
    """Extract knowledge entries for a given source and persist them.

    Returns a dict with the new entries and the updated source. Uses the
    AI provider's `extract_knowledge` if available, else falls back to
    the deterministic mock so the feature works offline.
    """
    source = kn_repo.get_source(source_id)
    if not source:
        return {"error": "source_not_found"}

    provider = get_provider()
    extracted: list[dict] = []
    try:
        if hasattr(provider, "extract_knowledge"):
            extracted = provider.extract_knowledge(source) or []  # type: ignore[attr-defined]
    except Exception as e:
        print(f"[SignalStack] knowledge extractor provider failed: {e}")
        extracted = []

    if not extracted:
        extracted = mock_extract(source)

    # Coerce categories so we never store an unknown enum value.
    cleaned = []
    for e in extracted:
        cleaned.append({
            **e,
            "category": _coerce_category(e.get("category")),
            "confidence": float(e.get("confidence") or 0.7),
            "active": bool(e.get("active", True)),
        })

    new_entries = kn_repo.replace_entries_for_source(source_id, cleaned)
    kn_repo.update_source(source_id, {"extraction_status": "EXTRACTED"})
    return {
        "source_id": source_id,
        "entries": new_entries,
        "entry_count": len(new_entries),
        "extraction_status": "EXTRACTED",
    }
