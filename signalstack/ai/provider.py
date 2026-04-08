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
import re
from typing import Any, Optional, Protocol

from .prompts import load_prompt


# Very small topic/place vocab we allow the mock provider to lift out
# of a note body. Kept intentionally tiny — we only need enough to
# produce a 2-4 word anchor that doesn't trip anti_copy's 6-gram
# overlap threshold. If nothing matches we fall back to a generic
# "your recent note" anchor, which is safer than pasting first-sentence
# text from the note verbatim.
_NOTE_TOPIC_VOCAB = {
    "btr", "build-to-rent", "build to rent", "sunbelt", "townhome",
    "townhomes", "multifamily", "sfr", "capital markets", "land",
    "nmhc", "development", "pipeline", "acquisition", "acquisitions",
    "raise", "deal", "expansion", "hiring",
}


def _compress_note_anchor(body: str) -> str:
    """
    Produce a very short (2-4 word) anchor phrase for a note so the
    generated message will not paste verbatim note text. We look for
    a known topic keyword in the note and hand back something like
    ``"your recent NMHC note"``; otherwise ``"your recent note"``.

    This is the narrow Step 3 fix for the degradation where any note
    of >=8 words caused the mock provider to leak a 6-gram overlap
    into every note-anchored candidate, which ``anti_copy_check``
    then rejected at ~30% overlap.
    """
    text = (body or "").strip().lower()
    if not text:
        return "your recent note"
    for kw in _NOTE_TOPIC_VOCAB:
        if re.search(rf"\b{re.escape(kw)}\b", text):
            # Uppercase 1-token acronyms, title-case the rest, so
            # "nmhc" -> "NMHC" and "sunbelt" -> "Sunbelt".
            label = kw.upper() if kw.isalpha() and len(kw) <= 4 else kw.title()
            return f"your recent {label} note"
    return "your recent note"


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
            # Compress notes to a SHORT topical anchor (2-4 words).
            # Previously we pasted the first ~80 chars of the note,
            # which reliably tripped anti_copy_check's 6-gram overlap
            # threshold for any realistic note and caused every
            # note-anchored candidate to be rejected during
            # candidate_validation. The compressed anchor avoids any
            # shared 6-gram with the raw note body.
            anchor_phrase = _compress_note_anchor(t)
            anchors.append((anchor_phrase, {"note_id": note.get("id")}))

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


# ----------------------- Claude provider -----------------------

def _safe_json_loads(raw: str) -> Any:
    """Best-effort JSON parsing for Claude's output.

    Claude occasionally wraps JSON in ```json fences, adds a leading
    prose paragraph, or emits trailing whitespace. This helper strips
    the common wrappers and falls back to a substring match on the
    first balanced ``{...}`` or ``[...]`` block.
    """
    import json as _json
    import re as _re

    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    # Strip Markdown fences.
    if text.startswith("```"):
        text = _re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = _re.sub(r"\s*```\s*$", "", text)
    try:
        return _json.loads(text)
    except Exception:
        pass
    # Try to find the first top-level JSON structure.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start < 0:
            continue
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return _json.loads(text[start : i + 1])
                    except Exception:
                        break
    return None


def _summarize_context_for_prompt(context: dict) -> dict:
    """Produce a compact, JSON-safe view of the context for Claude.

    We deliberately strip raw signal/note text — the AI only sees the
    compressed observations and a tiny identifying header per entity.
    This keeps us under token budget AND prevents the AI from being
    tempted to copy raw source material verbatim.
    """
    prospect = context.get("prospect") or {}
    company = context.get("company") or {}
    profile = context.get("profile") or {}
    signals = context.get("signals") or []
    notes = context.get("notes") or []
    observations = context.get("observations") or []
    distilled = context.get("distilled_observations") or []
    insights = context.get("insights") or []
    knowledge_entries = context.get("knowledge_entries") or []
    playbook = context.get("playbook") or {}

    return {
        "prospect": {
            "id": prospect.get("id"),
            "full_name": prospect.get("full_name"),
            "title": prospect.get("title"),
            "company_name": prospect.get("company_name"),
            "location": prospect.get("location"),
            "industry": prospect.get("industry"),
        },
        "company": {
            "id": company.get("id"),
            "name": company.get("name"),
            "industry": company.get("industry"),
            "company_type": company.get("company_type"),
        },
        "profile": {
            "headline": profile.get("headline"),
            "featured_topics": profile.get("featured_topics"),
            "about_text": (profile.get("about_text") or "")[:400],
            "shared_context": profile.get("shared_context"),
            "current_role": profile.get("current_role"),
        },
        "signals": [
            {
                "id": s.get("id"),
                "type": s.get("type"),
                "source": s.get("source"),
                "summary": (s.get("text") or "")[:160],
            }
            for s in signals[:10]
        ],
        "notes": [
            {
                "id": n.get("id"),
                "body_preview": (n.get("body") or "")[:160],
            }
            for n in notes[:5]
        ],
        "signal_observations": [
            {
                "signal_id": o.get("signal_id"),
                "summary": o.get("summary"),
                "safe_reference_text": o.get("safe_reference_text"),
            }
            for o in observations[:6]
        ],
        "distilled_observations": [
            {
                "text": o.get("text"),
                "source": o.get("source"),
                "source_id": o.get("source_id"),
                "strength": o.get("strength"),
            }
            for o in distilled[:5]
        ],
        "insights": [
            {
                "id": i.get("id"),
                "text": i.get("text"),
                "type": i.get("type"),
                "confidence": i.get("confidence"),
            }
            for i in insights[:5]
        ],
        "knowledge_style_guidance": [
            {
                "category": k.get("category"),
                "principle_name": k.get("principle_name"),
            }
            for k in knowledge_entries[:10]
        ],
        "playbook": {
            "name": (playbook.get("playbook") or {}).get("name")
            if isinstance(playbook, dict)
            else None,
            "preferred_angles": playbook.get("preferred_angles") or []
            if isinstance(playbook, dict)
            else [],
        },
    }


class ClaudeProvider:
    """
    Claude-backed provider for SignalStack.

    Wires the full multi-stage pipeline to the Anthropic Messages API.
    Every method is wrapped to raise cleanly on network/JSON errors so
    the generator's existing structured-error handling can take over.

    Env vars:
      ANTHROPIC_API_KEY         — required
      SIGNALSTACK_CLAUDE_MODEL  — optional (default: claude-sonnet-4-6)

    Secrets are never logged or echoed back in responses.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("SIGNALSTACK_CLAUDE_MODEL", "claude-sonnet-4-6")
        self._client = None
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        try:
            import anthropic  # type: ignore

            self._client = anthropic.Anthropic(api_key=self.api_key)
        except Exception as e:
            raise RuntimeError(
                f"anthropic SDK not available: {type(e).__name__}: {e}"
            )

    # -------- low level --------

    def _call_messages(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 1600,
        temperature: float = 0.6,
    ) -> str:
        """Single Messages API call. Returns the joined text of all
        text blocks in the first content list. Raises on any transport
        error so the generator can surface a clean structured error.
        """
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        parts: list[str] = []
        for block in getattr(resp, "content", []) or []:
            txt = getattr(block, "text", None)
            if txt:
                parts.append(txt)
        return "\n".join(parts).strip()

    # -------- pipeline: insight engine --------

    def generate_insights(self, context: dict) -> list[dict]:
        """Called by insight_engine when configured as an AI provider."""
        import json as _json

        system = load_prompt("insight_engine_system")
        ctx = _summarize_context_for_prompt(context)
        prospect_line = (
            f"{(ctx['prospect'] or {}).get('full_name') or 'Unknown'} "
            f"— {(ctx['prospect'] or {}).get('title') or ''} "
            f"at {(ctx['prospect'] or {}).get('company_name') or ''}"
        ).strip()
        user = (
            load_prompt("insight_engine_user")
            .replace("{prospect_line}", prospect_line)
            .replace("{observations_json}", _json.dumps(ctx.get("distilled_observations") or []))
            .replace("{signals_json}", _json.dumps(ctx.get("signal_observations") or []))
            .replace("{notes_json}", _json.dumps(ctx.get("notes") or []))
            .replace("{knowledge_json}", _json.dumps(ctx.get("knowledge_style_guidance") or []))
        )
        raw = self._call_messages(system, user, max_tokens=1200, temperature=0.6)
        parsed = _safe_json_loads(raw)
        if isinstance(parsed, dict) and "insights" in parsed:
            parsed = parsed.get("insights")
        if not isinstance(parsed, list):
            return []
        return parsed

    # -------- pipeline: message generator --------

    def generate_messages(
        self,
        context: dict,
        n: int = 4,
        strategies: Optional[list[dict]] = None,
        instruction: Optional[str] = None,
    ) -> list[dict]:
        import json as _json

        system = load_prompt("generate_system")
        ctx = _summarize_context_for_prompt(context)
        prospect_line = (
            f"{(ctx['prospect'] or {}).get('full_name') or 'Unknown'} "
            f"— {(ctx['prospect'] or {}).get('title') or ''} "
            f"at {(ctx['prospect'] or {}).get('company_name') or ''}"
        ).strip()
        user = (
            load_prompt("generate_user")
            .replace("{n}", str(n))
            .replace("{prospect_line}", prospect_line)
            .replace("{context_json}", _json.dumps(ctx))
            .replace("{observations_json}", _json.dumps(ctx.get("distilled_observations") or []))
            .replace("{insights_json}", _json.dumps(ctx.get("insights") or []))
            .replace("{strategies_json}", _json.dumps(strategies or []))
            .replace("{instruction}", instruction or "")
        )
        raw = self._call_messages(system, user, max_tokens=2000, temperature=0.7)
        parsed = _safe_json_loads(raw)
        if isinstance(parsed, dict) and "messages" in parsed:
            parsed = parsed.get("messages")
        if not isinstance(parsed, list):
            # Return empty list — the generator treats this as a
            # structured parse/empty result, not a hard crash.
            return []
        return parsed

    # -------- pipeline: message critic --------

    def critique_candidate(
        self,
        candidate: dict,
        context: dict,
        insights: Optional[list[dict]] = None,
    ) -> dict:
        import json as _json

        system = load_prompt("message_critic_system")
        ctx = _summarize_context_for_prompt(context)
        insight_text = ""
        iid = candidate.get("insight_id")
        if iid:
            for i in insights or []:
                if i.get("id") == iid:
                    insight_text = i.get("text") or ""
                    break
        user = (
            load_prompt("message_critic_user")
            .replace("{body}", candidate.get("body") or "")
            .replace("{angle}", candidate.get("angle") or "")
            .replace("{insight}", insight_text)
            .replace("{context_json}", _json.dumps(ctx))
        )
        raw = self._call_messages(system, user, max_tokens=700, temperature=0.2)
        parsed = _safe_json_loads(raw)
        if not isinstance(parsed, dict):
            return {}
        return parsed

    # -------- legacy passthroughs --------

    def critique(self, body: str, context: dict) -> dict:
        # Legacy entrypoint — the critic used via the new pipeline is
        # critique_candidate above. Kept here so the AiProvider Protocol
        # remains satisfied.
        return {
            "score": 0.7,
            "notes": "Claude critique call — use critique_candidate for the pipeline.",
        }

    def rewrite(self, body: str, instruction: str, context: dict) -> str:
        system = load_prompt("rewrite_system")
        user = f"Rewrite:\n{body}\n\nInstruction: {instruction}"
        try:
            return self._call_messages(system, user, max_tokens=500, temperature=0.5) or body
        except Exception:
            return body


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
