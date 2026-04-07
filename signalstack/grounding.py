"""
SignalStack grounding & safety layer.

This module enforces the rule: every generated message must map back
to at least one stored fact or signal, and must avoid manipulative,
templated, or fake-familiarity language.

It is intentionally simple and deterministic so it is easy to audit.
The AI provider can return candidate messages, but they MUST pass
`validate_message()` before being persisted or shown to the user.
"""
import re
from typing import Iterable

# Phrases that indicate templated / robotic / pushy outreach.
BANNED_PHRASES = [
    r"\bi help (companies|businesses|teams) like yours\b",
    r"\bquick (call|chat) this week\b",
    r"\bhope this finds you well\b",
    r"\bsynerg(y|ies)\b",
    r"\bcircle back\b",
    r"\bjust checking in\b",
    r"\bmoving the needle\b",
    r"\boptimi[sz]e (your )?growth\b",
    r"\blove to (jump on|hop on) a call\b",
    r"\bleverage\b",
    r"\bgame[- ]chang(er|ing)\b",
    r"\bbest[- ]in[- ]class\b",
]

# Words that fake familiarity / invent personal context.
FAKE_FAMILIARITY = [
    r"\bbuddy\b",
    r"\bmy friend\b",
    r"\bfellow (.*?)er\b",
]

CREEPY_PATTERNS = [
    r"\bi('| ha)ve been watching\b",
    r"\bi noticed you (live|moved) (in|to)\b",  # personal location stalking
]

# LinkedIn first-touch hard cap. The anti-copy validator also enforces
# a 450-char soft ceiling and auto-shortens before this runs.
MAX_MESSAGE_CHARS = 450


class GroundingError(ValueError):
    """Raised when a generated message fails grounding/safety checks."""


def _matches_any(text: str, patterns: Iterable[str]) -> list:
    found = []
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            found.append(p)
    return found


GENERIC_OPENERS = [
    r"\bi help (companies|businesses|teams) like yours\b",
    r"\bwould love to connect\b",
    r"\bsaw your profile and thought\b",
    r"\bcongrats on your recent success\b",
    r"\bi wanted to (reach out|introduce myself)\b",
    r"\bhope you('| a)re (doing )?well\b",
]


def validate_message(
    body: str,
    signals_used: list,
    facts_used: list,
    profile_fields_used: list | None = None,
) -> dict:
    """
    Validate a generated message against grounding + safety rules.

    Returns a dict with keys:
        ok: bool
        score: float in [0, 1]   — grounding confidence
        violations: list[str]
    Raises GroundingError if `ok` is False AND caller wants strict mode;
    instead we return the result so the caller decides what to do.
    """
    violations = []

    if not body or not body.strip():
        violations.append("empty_body")

    if len(body) > MAX_MESSAGE_CHARS:
        violations.append(f"too_long:{len(body)}>{MAX_MESSAGE_CHARS}")

    profile_fields_used = profile_fields_used or []
    # Must reference at least one stored fact, signal, or profile field.
    if not signals_used and not facts_used and not profile_fields_used:
        violations.append("ungrounded:no_signals_facts_or_profile")

    banned = _matches_any(body, BANNED_PHRASES)
    if banned:
        violations.append(f"banned_phrases:{len(banned)}")

    generic = _matches_any(body, GENERIC_OPENERS)
    if generic:
        violations.append(f"generic_opener:{len(generic)}")

    fake = _matches_any(body, FAKE_FAMILIARITY)
    if fake:
        violations.append(f"fake_familiarity:{len(fake)}")

    creepy = _matches_any(body, CREEPY_PATTERNS)
    if creepy:
        violations.append(f"creepy:{len(creepy)}")

    # Light heuristic grounding score: evidence weight minus violations.
    evidence = len(signals_used) + len(facts_used) + len(profile_fields_used)
    score = max(0.0, min(1.0, 0.4 + 0.15 * evidence - 0.25 * len(violations)))

    return {
        "ok": len(violations) == 0,
        "score": round(score, 3),
        "violations": violations,
    }


def filter_safe_signals(signals: list) -> list:
    """Return only signals explicitly marked safe to reference."""
    return [s for s in signals if s.get("safe_to_reference") in (1, True)]
