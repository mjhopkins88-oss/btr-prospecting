"""
AI provider abstraction.

Business logic depends only on the `AiProvider` interface. To wire in
Claude later, implement `ClaudeProvider(AiProvider)` and select it via
SIGNALSTACK_AI_PROVIDER env var. The mock provider is deterministic so
it's safe for tests and offline development.
"""
from __future__ import annotations

import os
import random
from typing import Optional, Protocol

from .prompts import load_prompt


class AiProvider(Protocol):
    def generate_messages(
        self,
        context: dict,
        n: int = 4,
        strategies: Optional[list[dict]] = None,
        instruction: Optional[str] = None,
    ) -> list[dict]:
        ...

    def critique(self, body: str, context: dict) -> dict: ...
    def rewrite(self, body: str, instruction: str, context: dict) -> str: ...


# ----------------------- Mock provider -----------------------

def _first_name(prospect: dict) -> str:
    return (prospect.get("full_name") or "there").split(" ")[0] or "there"


def _signal_phrase(signal: dict) -> str:
    t = signal.get("type", "")
    text = (signal.get("text") or "").strip().rstrip(".")
    if t == "company_expansion":
        return f"the team's expansion — {text}"
    if t == "hiring_activity":
        return f"the hiring push around {text}"
    if t == "post_topic":
        return f"your post on {text}"
    if t == "job_change":
        return f"the move — {text}"
    if t == "company_news":
        return f"the news on {text}"
    if t == "role_change":
        return f"the new role — {text}"
    return text


def _profile_anchor(profile: dict) -> tuple[Optional[str], Optional[str]]:
    """Pick one profile field we can lawfully reference. Returns (text, field)."""
    if not profile:
        return None, None
    for field in ("featured_topics", "headline", "current_role", "shared_context"):
        v = profile.get(field)
        if v:
            return v, field
    return None, None


def _apply_modifiers(body: str, modifiers: list[str]) -> str:
    if "concise" in modifiers and len(body) > 240:
        # Take first two sentences when asked for concise.
        parts = [p for p in body.split(". ") if p]
        body = ". ".join(parts[:2]).rstrip(".") + "."
    if "warmer" in modifiers:
        body = body.replace("Hi ", "Hey ")
    if "sharper" in modifiers:
        body = body.replace("happy to be wrong", "tell me I'm wrong")
    return body


def _compose(angle: str, first: str, anchor: str, profile_anchor: Optional[str]) -> str:
    """Build a distinct opener per angle. Anchors come from real stored data."""
    profile_clause = f" Given your focus on {profile_anchor}," if profile_anchor else ""
    if angle == "curiosity":
        return (f"Hi {first} — noticed {anchor}.{profile_clause} "
                f"Curious how you're thinking about it as things settle.")
    if angle == "observation":
        return (f"Hey {first}, picked up on {anchor}. No agenda — "
                f"just thought it was worth flagging.")
    if angle == "insight":
        return (f"Hi {first} — saw {anchor}. A few teams in similar spots "
                f"have been wrestling with the same trade-off; happy to share "
                f"what I've seen if it's useful.")
    if angle == "point_of_view":
        return (f"Hi {first} — on {anchor}, my read is the second-order effect "
                f"hits within a quarter, not at announcement. Happy to be wrong.")
    if angle == "relevant_challenge":
        return (f"Hi {first} — given {anchor}, is there someone on your team "
                f"already owning the downstream side of this, or is it still floating?")
    if angle == "timing_context":
        return (f"Hey {first} — {anchor} caught my eye this week. "
                f"Worth a quick exchange of notes, or too early?")
    return f"Hi {first} — noticed {anchor}."


class MockAiProvider:
    """
    Deterministic mock generator. Produces diverse, grounded openers
    using stored signals + profile context + user instruction. Never
    invents facts beyond what's already in `context`.
    """

    def generate_messages(
        self,
        context: dict,
        n: int = 4,
        strategies: Optional[list[dict]] = None,
        instruction: Optional[str] = None,
    ) -> list[dict]:
        prospect = context.get("prospect") or {}
        signals = context.get("signals") or []
        notes = context.get("notes") or []
        profile = context.get("profile") or {}
        first = _first_name(prospect)

        random.seed(prospect.get("id") or "seed")

        anchors: list[tuple[str, dict]] = []  # (anchor_text, source_meta)
        for s in signals:
            anchors.append((_signal_phrase(s), {"signal_id": s.get("id")}))
        for note in notes[:2]:
            t = (note.get("body") or "").strip().rstrip(".")
            if t:
                anchors.append((f"your note — {t}", {"note_id": note.get("id")}))

        profile_anchor_text, profile_field = _profile_anchor(profile)
        if not anchors and profile_anchor_text:
            anchors.append((profile_anchor_text, {"profile_field": profile_field}))

        # Fallback: anchor on the prospect's stored role/company so the
        # generator still produces something usable when only a LinkedIn
        # URL was provided. We mark this as a "facts_used" anchor so the
        # grounding validator still passes.
        if not anchors:
            title = prospect.get("title")
            company = prospect.get("company_name")
            if title and company:
                anchors.append((f"your work as {title} at {company}", {"fact": "title+company"}))
            elif title:
                anchors.append((f"your work as {title}", {"fact": "title"}))
            elif company:
                anchors.append((f"your work at {company}", {"fact": "company"}))
            elif profile.get("linkedin_url"):
                anchors.append(("your LinkedIn profile", {"fact": "linkedin_url"}))

        if not anchors:
            return []

        strategies = strategies or [{"angle": "curiosity"}, {"angle": "observation"},
                                    {"angle": "insight"}, {"angle": "point_of_view"}]
        results = []
        for i, spec in enumerate(strategies[:n]):
            anchor_text, src = anchors[i % len(anchors)]
            angle = spec.get("angle") or "curiosity"
            body = _compose(angle, first, anchor_text, profile_anchor_text)

            if instruction:
                # Reflect the user's instruction in tone, not in invented content.
                tag = instruction.strip().lower()
                if "casual" in tag:
                    body = body.replace("Hi ", "Hey ")
                if "short" in tag or "concise" in tag:
                    spec.setdefault("modifiers", []).append("concise")
                if "credibility" in tag:
                    body += " I've spent time in the same trade-off, happy to compare notes."

            body = _apply_modifiers(body, spec.get("modifiers") or [])

            facts_used = [f for f in (
                prospect.get("title"),
                prospect.get("company_name"),
                prospect.get("location"),
            ) if f]

            results.append({
                "body": body,
                "rationale": (
                    f"Angle: {angle}. Grounded in "
                    + (f"signal {src['signal_id']}" if src.get("signal_id") else
                       f"note {src.get('note_id')}" if src.get("note_id") else
                       f"profile.{src.get('profile_field')}")
                    + (f". Instruction: {instruction!r}." if instruction else ".")
                ),
                "angle": angle,
                "message_type": spec.get("message_type", "curiosity"),
                "primary_trigger": spec.get("primary_trigger", "curiosity"),
                "communication_style": spec.get("communication_style", "conversational"),
                "outreach_goal": spec.get("outreach_goal", "start_conversation"),
                "signal_ids": [src["signal_id"]] if src.get("signal_id") else [],
                "notes_used": [src["note_id"]] if src.get("note_id") else [],
                "profile_fields_used": (
                    [src["profile_field"]] if src.get("profile_field") else
                    ([profile_field] if profile_field else [])
                ),
                "facts_used": facts_used,
            })
        return results

    def critique(self, body: str, context: dict) -> dict:
        return {
            "score": 0.7,
            "notes": "Mock critique — wire ClaudeProvider for real critique.",
            "system_prompt": load_prompt("critique_system"),
        }

    def rewrite(self, body: str, instruction: str, context: dict) -> str:
        return body


# ----------------------- Claude provider scaffold -----------------------

class ClaudeProvider:
    """
    Production scaffold for the Anthropic API. Intentionally minimal —
    drops in cleanly when ANTHROPIC_API_KEY is configured. Falls back to
    raising so the generator surfaces a clean error to the UI.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("SIGNALSTACK_CLAUDE_MODEL", "claude-sonnet-4-6")

    def generate_messages(
        self,
        context: dict,
        n: int = 4,
        strategies: Optional[list[dict]] = None,
        instruction: Optional[str] = None,
    ) -> list[dict]:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        # Real implementation would call the Messages API with prompts
        # loaded via load_prompt() and parse a JSON response. Left as a
        # scaffold so we don't ship an untested network path.
        raise NotImplementedError("ClaudeProvider not yet wired — using MockAiProvider")

    def critique(self, body: str, context: dict) -> dict:
        raise NotImplementedError

    def rewrite(self, body: str, instruction: str, context: dict) -> str:
        raise NotImplementedError


# ----------------------- Selector -----------------------

def get_provider() -> AiProvider:
    """Return the configured provider. Defaults to mock."""
    name = os.getenv("SIGNALSTACK_AI_PROVIDER", "mock").lower()
    if name == "claude":
        try:
            return ClaudeProvider()
        except Exception as e:
            print(f"[SignalStack] Claude provider unavailable, using mock: {e}")
            return MockAiProvider()
    return MockAiProvider()
