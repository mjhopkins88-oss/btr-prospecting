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


def _signal_phrase(signal: dict, observation: Optional[dict] = None) -> str:
    """
    Return a SHORT, paraphrased anchor for a signal. We must never paste
    the raw `signal["text"]` here — long source bodies (listings, posts,
    news articles) would leak straight into the LinkedIn message.
    Always prefer the compressed `observation.safe_reference_text`.
    """
    if observation and observation.get("safe_reference_text"):
        return observation["safe_reference_text"]
    t = signal.get("type", "")
    if t == "company_expansion":
        return "the team's recent expansion"
    if t == "hiring_activity":
        return "the recent hiring push"
    if t == "post_topic":
        return "your recent post"
    if t == "job_change":
        return "the recent move"
    if t == "company_news":
        return "the recent company update"
    if t == "role_change":
        return "the new role"
    return "your recent activity"


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
        return (f"Hi {first} — {anchor} caught my attention.{profile_clause} "
                f"Curious how you're thinking about that segment right now.")
    if angle in ("observation", "timely_observation"):
        return (f"Hey {first} — {anchor} jumped out at me this week. "
                f"No agenda, just thought I'd flag it while it's timely.")
    if angle in ("insight", "light_insight"):
        return (f"Hi {first} — on {anchor}, a few teams in similar spots "
                f"have been wrestling with the same trade-off. Happy to share "
                f"what I've seen if it's useful.")
    if angle == "market_pattern":
        return (f"Hi {first} — {anchor} lines up with a pattern we're seeing "
                f"across similar desks this quarter. Curious if you're reading it the same way.")
    if angle == "point_of_view":
        return (f"Hi {first} — on {anchor}, my read is the second-order effect "
                f"hits within a quarter, not at announcement. Tell me I'm wrong.")
    if angle == "relevant_challenge":
        return (f"Hi {first} — given {anchor}, is someone on your team already "
                f"owning the downstream side of this, or is it still floating?")
    if angle == "low_pressure_starter":
        return (f"Hi {first} — no agenda here, just wanted to open a line "
                f"in case it's useful down the road.")
    return f"Hi {first} — {anchor} caught my eye."


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
        # Pre-computed observations from the Signal Interpretation Layer.
        # See signalstack/services/signal_interpreter.py — these are the
        # ONLY source-derived strings the generator is allowed to use.
        observations = context.get("observations") or []
        obs_by_signal = {o.get("signal_id"): o for o in observations}
        first = _first_name(prospect)

        random.seed(prospect.get("id") or "seed")

        anchors: list[tuple[str, dict]] = []  # (anchor_text, source_meta)
        for s in signals:
            obs = obs_by_signal.get(s.get("id"))
            anchors.append((
                _signal_phrase(s, observation=obs),
                {"signal_id": s.get("id"), "observation": obs},
            ))
        for note in notes[:2]:
            t = (note.get("body") or "").strip()
            if not t:
                continue
            # Compress notes too — never paste a long note verbatim.
            short = t.split(".")[0].strip()
            if len(short) > 80:
                short = short[:77].rsplit(" ", 1)[0] + "…"
            anchors.append((f"your note about {short}", {"note_id": note.get("id")}))

        profile_anchor_text, profile_field = _profile_anchor(profile)
        if not anchors and profile_anchor_text:
            anchors.append((profile_anchor_text, {"profile_field": profile_field}))

        # NOTE: We deliberately do NOT fall back to anchoring on the
        # prospect's title / company / location here. Those are weak
        # profile facts and lead to "noticed your work as Managing
        # Director at JLL"-style fake personalization. When no real
        # anchor exists we hand back a generic, clearly-low-context
        # opener and let the anti-generic validator + UI flag it as
        # a "low-context fallback option".
        low_context_mode = not anchors
        if low_context_mode:
            anchors.append(("", {"low_context": True}))

        strategies = strategies or [{"angle": "curiosity"}, {"angle": "observation"},
                                    {"angle": "insight"}, {"angle": "point_of_view"}]
        results = []
        for i, spec in enumerate(strategies[:n]):
            anchor_text, src = anchors[i % len(anchors)]
            angle = spec.get("angle") or "curiosity"
            if src.get("low_context"):
                # Force the only safe low-context angle so we never
                # produce fake-personalized lines from weak facts.
                angle = "low_pressure_starter"
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

            # Hard cap: LinkedIn first-touch should never exceed ~450 chars.
            from ..services.anti_copy import shorten as _shorten
            body = _shorten(body, target=320)

            obs = src.get("observation") or {}
            results.append({
                "observation": {
                    "summary": obs.get("summary"),
                    "safe_reference_text": obs.get("safe_reference_text"),
                    "signal_id": obs.get("signal_id"),
                } if obs else None,
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
                "low_context": bool(src.get("low_context")),
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
