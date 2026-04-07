"""
Anti-copy validator.

Detects when a generated message has copied raw source material (such
as a pasted listing, news article, or LinkedIn post body) instead of
producing an original short outreach message.

Strategy: token-level n-gram overlap. If any 6-word window from the
source appears verbatim in the message, or if more than 25% of the
message tokens are part of long shared n-grams with any source, the
message is flagged as a copy.

Pure heuristic, no LLM. Deterministic.
"""
from __future__ import annotations

import re
from typing import Iterable

NGRAM_SIZE = 6
HARD_OVERLAP_RATIO = 0.25
SOFT_TARGET_CHARS = 320
HARD_MAX_CHARS = 450


_word_re = re.compile(r"[A-Za-z0-9']+")


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _word_re.findall(text or "")]


def _ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    if len(tokens) < n:
        return set()
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def check_message(body: str, sources: Iterable[str]) -> dict:
    """
    Compare a generated message body against the raw source texts it
    was inspired by. Returns scores + a pass/fail verdict.
    """
    body = body or ""
    body_tokens = _tokens(body)
    body_ngrams = _ngrams(body_tokens, NGRAM_SIZE)

    worst_overlap = 0.0
    copied_phrase = None
    for src in sources:
        src_tokens = _tokens(src or "")
        if len(src_tokens) < NGRAM_SIZE or not body_tokens:
            continue
        src_ngrams = _ngrams(src_tokens, NGRAM_SIZE)
        shared = body_ngrams & src_ngrams
        if not shared:
            continue
        # Ratio = body tokens that participate in any shared n-gram.
        covered = set()
        for gram in shared:
            for i in range(len(body_tokens) - NGRAM_SIZE + 1):
                if tuple(body_tokens[i:i + NGRAM_SIZE]) == gram:
                    covered.update(range(i, i + NGRAM_SIZE))
        ratio = len(covered) / max(1, len(body_tokens))
        if ratio > worst_overlap:
            worst_overlap = ratio
            copied_phrase = " ".join(next(iter(shared)))

    too_long = len(body) > HARD_MAX_CHARS
    has_bullets = bool(re.search(r"(^|\n)\s*[-*•]\s+\S", body))
    has_link = bool(re.search(r"https?://", body))

    violations: list[str] = []
    if worst_overlap >= HARD_OVERLAP_RATIO:
        violations.append(f"raw_source_overlap:{worst_overlap:.2f}")
    if too_long:
        violations.append(f"too_long:{len(body)}>{HARD_MAX_CHARS}")
    if has_bullets:
        violations.append("contains_bullets")
    if has_link:
        violations.append("contains_link")

    return {
        "passes_anti_copy_check": not violations,
        "raw_source_overlap_score": round(worst_overlap, 3),
        "copied_phrase": copied_phrase,
        "char_count": len(body),
        "soft_target_chars": SOFT_TARGET_CHARS,
        "hard_max_chars": HARD_MAX_CHARS,
        "violations": violations,
    }


def shorten(body: str, target: int = SOFT_TARGET_CHARS) -> str:
    """Trim a too-long message at the nearest sentence/word boundary."""
    if not body or len(body) <= target:
        return body
    cut = body[:target]
    # Prefer ending at a sentence boundary.
    for sep in (". ", "? ", "! "):
        idx = cut.rfind(sep)
        if idx > target * 0.5:
            return cut[:idx + 1].strip()
    # Otherwise cut at the last space.
    idx = cut.rfind(" ")
    if idx > 0:
        cut = cut[:idx]
    return cut.rstrip(",;:- ").rstrip() + "…"
