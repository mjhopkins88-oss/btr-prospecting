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
from typing import Protocol

from .prompts import load_prompt


class AiProvider(Protocol):
    def generate_messages(self, context: dict, n: int = 4) -> list[dict]:
        """
        Return a list of {body, rationale, message_type, primary_trigger,
        communication_style, outreach_goal, signal_ids, facts_used} dicts.
        Implementations MUST only use facts/signals present in `context`.
        """
        ...

    def critique(self, body: str, context: dict) -> dict:
        ...

    def rewrite(self, body: str, instruction: str, context: dict) -> str:
        ...


# ----------------------- Mock provider -----------------------

_STYLES = [
    ("curiosity", "curiosity", "conversational", "start_conversation"),
    ("insight", "self_relevance", "analytical", "offer_insight"),
    ("casual", "liking", "conversational", "build_familiarity"),
    ("direct", "authority", "direct", "get_routed"),
]


def _pick_signal_phrase(signal: dict) -> str:
    """Build a single observational sentence from one signal."""
    t = signal.get("type", "")
    text = signal.get("text", "").strip().rstrip(".")
    if t == "company_expansion":
        return f"Saw the team's been expanding — {text}."
    if t == "hiring_activity":
        return f"Noticed the hiring push around {text}."
    if t == "post_topic":
        return f"Your recent post on {text} stuck with me."
    if t == "job_change":
        return f"Congrats on the move — {text}."
    if t == "company_news":
        return f"Saw the news on {text}."
    if t == "role_change":
        return f"Noticed the new role — {text}."
    return f"Noticed {text}."


class MockAiProvider:
    """
    Deterministic mock generator. Builds short, observational openers
    grounded in real stored signals. Never invents facts.
    """

    def generate_messages(self, context: dict, n: int = 4) -> list[dict]:
        prospect = context.get("prospect", {})
        signals = context.get("signals", []) or []
        if not signals:
            # No signals → no grounded message can be produced.
            return []

        first = (prospect.get("full_name") or "").split(" ")[0] or "there"
        results = []
        random.seed(prospect.get("id", "seed"))

        # Use up to n different signal/style combos.
        for i in range(min(n, max(1, len(signals)))):
            sig = signals[i % len(signals)]
            mtype, trigger, style, goal = _STYLES[i % len(_STYLES)]
            opener = _pick_signal_phrase(sig)

            if mtype == "curiosity":
                body = f"Hi {first} — {opener} Curious how you're thinking about it as things evolve."
            elif mtype == "insight":
                body = (f"Hi {first} — {opener} A few teams in similar spots have been "
                        f"wrestling with the same trade-off; happy to share what I've seen if useful.")
            elif mtype == "casual":
                body = f"Hey {first}, {opener} No agenda — just thought it was interesting."
            else:  # direct
                body = (f"Hi {first} — {opener} Worth a short conversation, "
                        f"or is there someone on your team I should be talking to instead?")

            results.append({
                "body": body,
                "rationale": (f"Grounded in signal {sig.get('id')} "
                              f"({sig.get('type')}). Style: {style}, trigger: {trigger}."),
                "message_type": mtype,
                "primary_trigger": trigger,
                "communication_style": style,
                "outreach_goal": goal,
                "signal_ids": [sig.get("id")],
                "facts_used": [
                    f for f in [
                        prospect.get("title"),
                        prospect.get("company_name"),
                        prospect.get("location"),
                    ] if f
                ],
            })
        return results

    def critique(self, body: str, context: dict) -> dict:
        return {
            "score": 0.7,
            "notes": "Mock critique — wire ClaudeProvider for real critique.",
            "system_prompt": load_prompt("critique_system"),
        }

    def rewrite(self, body: str, instruction: str, context: dict) -> str:
        return body  # mock no-op


# ----------------------- Selector -----------------------

def get_provider() -> AiProvider:
    """Return the configured provider. Defaults to mock."""
    name = os.getenv("SIGNALSTACK_AI_PROVIDER", "mock").lower()
    if name == "mock":
        return MockAiProvider()
    # Future: if name == "claude": from .claude_provider import ClaudeProvider; return ClaudeProvider()
    return MockAiProvider()
