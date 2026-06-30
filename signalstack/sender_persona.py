"""
Sender persona for SignalStack.

SignalStack writes LinkedIn outreach *from* a specific operator, not
from a generic sender. That operator's background, seat, and stance
shape how every message should be framed — tone, angle selection,
what counts as a credible peer observation, and what is explicitly
OFF the table (pitching, pricing, asks for calls).

This module is the single source of truth for the sender's identity.
The generator, insight engine, thought translator, message critic,
and prompt assembly layer all pull from here so the operator's voice
and strengths stay consistent across every stage of the pipeline.

The persona can be overridden at runtime via the
``SIGNALSTACK_SENDER_PERSONA_JSON`` env var (a JSON object that is
shallow-merged on top of the defaults). This lets a deployment swap
in a different operator without a code change, while keeping the
in-repo default locked to the real sender we ship with.

The persona is deliberately structured as small primitive fields so
we can drop it straight into JSON prompts without additional
serialization logic.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Default sender persona
# ---------------------------------------------------------------------------
#
# This is the live operator SignalStack writes on behalf of today.
# Anything here flows directly into the generation prompts, the
# insight engine, the thought translator, and the message critic,
# so the wording is chosen to be short, concrete, and peer-readable.
#
# NOTE: these fields describe the SENDER, not the prospect. Nothing
# in here is ever treated as prospect personalization. The generator
# uses them to shape voice and angle, not to claim facts about the
# recipient.

DEFAULT_SENDER_PERSONA: dict = {
    "name": "Alkeme BTR Insurance Program Director",
    "role": "Director of a Build-to-Rent insurance program at Alkeme",
    "company": "Alkeme",
    "seat_summary": (
        "Runs Alkeme's Build-to-Rent insurance program. Sees risk "
        "across many BTR deals and is usually brought in too late in "
        "the process — when insurance has already started shaping "
        "timing, capital, or structure and the room is scrambling."
    ),
    "works_with": [
        "BTR developers",
        "capital partners",
        "operators",
        "GP / LP structures",
    ],
    "strengths": [
        "Sees risk across many BTR deals at once, not just one at a time",
        "Knows how insurance quietly shapes deal timing, capital, and structure",
        "Has seen the downstream pattern when insurance is dealt with too late",
        "Focused on long-term partnerships, not transactions",
        "Calm, peer-level, and most useful when brought in early to shape the deal",
    ],
    "market_context": [
        "Insurance is a deal-shaping factor, not a line item — and it usually shows up late",
        "Timing of insurance decisions matters — it can gate capital and close timing",
        "Submarket differences drive very different underwriting outcomes",
        "The same risk pattern keeps surfacing across different operators' pipelines",
    ],
    "lens": {
        "description": (
            "Every message must be written THROUGH this operator's lens. "
            "The lens is insurance, risk, and deal timing — but the lens "
            "is a FRAMING, not a product pitch. The sender interprets "
            "what they see in the market through the question: 'where "
            "does this create friction, risk, or a timing problem in "
            "someone's deal execution?' That framing should shape the "
            "angle of every observation."
        ),
        "write_every_message_as": [
            "Someone who sees risk across many deals at once",
            "Someone who is usually brought in too late and has seen the pattern repeat",
            "Someone who thinks of insurance as a deal-shaping factor, not a product",
            "Someone who has watched the same risk issue quietly break deal timing",
        ],
        "interpret_market_through": [
            "risk exposure that shows up during deal execution",
            "insurance as a gating factor on capital, timing, or structure",
            "the gap between when insurance gets looked at and when it actually matters",
            "the cost of being brought in late vs. brought in early",
        ],
        "preferred_phrasings": [
            "we see this a lot when…",
            "this usually shows up once…",
            "this tends to become an issue when…",
            "we often get pulled in when…",
            "the thing we keep running into on deals like this is…",
            "by the time this hits our desk, it's usually…",
        ],
        "banned_phrasings": [
            "pattern I keep noticing",
            "the trend suggests",
            "in this space",
            "in this part of the market",
            "teams in this segment",
            "the current environment",
            "today's market",
        ],
    },
    "voice_identity": {
        "writes_like": [
            "someone inside the deal process who sees risk across many deals",
            "someone who has seen the same issue surface late, over and over",
            "an operator who thinks of insurance as a deal-shaping factor",
            "a peer who compares notes across pipelines, not a vendor pitching one",
        ],
        "not": [
            "a broker",
            "a salesperson",
            "an SDR",
            "a vendor pitching pricing",
            "a market commentator",
            "a newsletter writer",
            "an analyst",
        ],
    },
    "core_objective": (
        "Start high-quality conversations that can turn into long-term "
        "partnerships. Not selling insurance, not pushing pricing, not "
        "asking for calls. Instead: show the recipient, through the "
        "lens, that the sender already sees the risk pattern on deals "
        "like theirs and thinks about it earlier than most."
    ),
    "partnership_signal": (
        "Each message should subtly communicate: I see risk across "
        "many deals and I usually wish I'd been in the conversation "
        "earlier — so I'm reaching out before anything is on fire."
    ),
    "hard_bans": [
        "Do NOT sell or pitch insurance. The lens is framing, not a product.",
        "Do NOT mention pricing, quotes, programs, or carriers.",
        "Do NOT ask for a call, a meeting, or a 'quick chat'.",
        "Do NOT introduce yourself as a broker or an SDR.",
        "Do NOT use 'I help companies like yours' framing.",
        "Do NOT write a generic profile summary of the recipient.",
        "Do NOT force personalization from weak facts (title / company / location alone).",
        "Do NOT write neutral market commentary. Every observation must be filtered through the sender's risk / timing / deal-execution lens.",
        "Do NOT use 'pattern I keep noticing' phrasing — it reads like a newsletter, not an operator.",
    ],
    "success_criteria": [
        "Message clearly reflects the sender's seat — risk, timing, deal execution.",
        "Feels like it comes from someone inside the process, not observing it.",
        "Sounds like an operator who has seen this specific issue repeat, not a commentator.",
        "Gives the recipient a concrete reason to engage — not a market take.",
        "Still peer-level, calm, low-pressure, and never a pitch.",
    ],
}


# ---------------------------------------------------------------------------
# Loading + overrides
# ---------------------------------------------------------------------------

_ENV_VAR = "SIGNALSTACK_SENDER_PERSONA_JSON"


def _load_env_override() -> Optional[dict]:
    raw = os.getenv(_ENV_VAR)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception as e:
        print(
            f"[SignalStack] sender_persona: ignoring invalid "
            f"{_ENV_VAR} JSON: {type(e).__name__}: {e}"
        )
        return None
    if not isinstance(data, dict):
        return None
    return data


def _shallow_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if v in (None, ""):
            continue
        out[k] = v
    return out


def get_sender_persona() -> dict:
    """Return the active sender persona, applying env overrides."""
    override = _load_env_override()
    if not override:
        # Return a shallow copy so callers can't mutate the module default.
        return dict(DEFAULT_SENDER_PERSONA)
    return _shallow_merge(DEFAULT_SENDER_PERSONA, override)


# ---------------------------------------------------------------------------
# Prompt-ready formatters
# ---------------------------------------------------------------------------
#
# Every prompt in ``signalstack/ai/prompts`` reads the same JSON blob
# and the same one-line headline, so the voice stays consistent across
# stages. Prompts that only need a short identity line use
# ``sender_persona_line``; prompts that reason about strengths/market
# context use the full ``sender_persona_prompt_block``.


def sender_persona_line(persona: Optional[dict] = None) -> str:
    """Return a one-line identity string for prompts that only need
    the sender's seat. Example::

        Director of a Build-to-Rent insurance program at Alkeme —
        works across developers, capital partners, and operators.
    """
    p = persona or get_sender_persona()
    role = p.get("role") or p.get("name") or "operator"
    works = ", ".join((p.get("works_with") or [])[:4])
    if works:
        return f"{role} — works across {works}."
    return f"{role}."


def sender_persona_prompt_block(persona: Optional[dict] = None) -> str:
    """Return a multi-line text block describing the sender. This is
    what the system prompts embed so every generation stage sees the
    same identity, strengths, market context, lens, and hard bans.

    The LENS block is the most important part: it tells the downstream
    generator that every message must be written THROUGH this
    operator's specific perspective (risk, timing, deal execution),
    not as neutral market commentary.
    """
    p = persona or get_sender_persona()

    def _bullets(items: list[str]) -> str:
        return "\n".join(f"- {x}" for x in items if x)

    strengths = _bullets(p.get("strengths") or [])
    works_with = _bullets(p.get("works_with") or [])
    market = _bullets(p.get("market_context") or [])
    writes_like = _bullets((p.get("voice_identity") or {}).get("writes_like") or [])
    not_like = _bullets((p.get("voice_identity") or {}).get("not") or [])
    hard_bans = _bullets(p.get("hard_bans") or [])
    success = _bullets(p.get("success_criteria") or [])

    lens = p.get("lens") or {}
    lens_description = (lens.get("description") or "").strip()
    lens_write_as = _bullets(lens.get("write_every_message_as") or [])
    lens_interpret = _bullets(lens.get("interpret_market_through") or [])
    lens_preferred = _bullets(lens.get("preferred_phrasings") or [])
    lens_banned = _bullets(lens.get("banned_phrasings") or [])

    lens_block = ""
    if lens_description or lens_write_as or lens_interpret or lens_preferred:
        lens_block = (
            "\n=== SENDER'S LENS (write every message THROUGH this lens) ===\n"
            f"{lens_description}\n\n"
            f"Write every message as:\n{lens_write_as}\n\n"
            f"Interpret market observations through:\n{lens_interpret}\n\n"
            f"Preferred phrasings (lens-first, operator voice):\n{lens_preferred}\n\n"
            f"Banned phrasings (analyst / newsletter voice):\n{lens_banned}\n"
            "=== END LENS ===\n\n"
        )

    return (
        "SENDER IDENTITY (the operator these messages are written FROM —\n"
        "never treat any of this as prospect personalization):\n\n"
        f"Role: {p.get('role') or p.get('name')}\n"
        f"Seat: {p.get('seat_summary') or ''}\n\n"
        f"Works with:\n{works_with}\n\n"
        f"Strengths the sender can lean on:\n{strengths}\n\n"
        f"Market context the sender already carries:\n{market}\n"
        f"{lens_block}"
        f"Writes like:\n{writes_like}\n\n"
        f"Does NOT write like:\n{not_like}\n\n"
        f"Core objective: {p.get('core_objective') or ''}\n\n"
        f"Partnership signal: {p.get('partnership_signal') or ''}\n\n"
        f"Hard bans for first-touch messages:\n{hard_bans}\n\n"
        f"Success criteria:\n{success}\n"
    )


def sender_persona_for_context(persona: Optional[dict] = None) -> dict:
    """Return a JSON-safe projection suitable for embedding in the
    context summary that Claude receives. Keeps the same top-level
    shape as the default persona so downstream prompts can read any
    field by name without missing-key guards.
    """
    p = persona or get_sender_persona()
    lens = p.get("lens") or {}
    return {
        "role": p.get("role"),
        "company": p.get("company"),
        "seat_summary": p.get("seat_summary"),
        "works_with": list(p.get("works_with") or []),
        "strengths": list(p.get("strengths") or []),
        "market_context": list(p.get("market_context") or []),
        "lens": {
            "description": lens.get("description"),
            "write_every_message_as": list(lens.get("write_every_message_as") or []),
            "interpret_market_through": list(lens.get("interpret_market_through") or []),
            "preferred_phrasings": list(lens.get("preferred_phrasings") or []),
            "banned_phrasings": list(lens.get("banned_phrasings") or []),
        },
        "voice_identity": {
            "writes_like": list((p.get("voice_identity") or {}).get("writes_like") or []),
            "not": list((p.get("voice_identity") or {}).get("not") or []),
        },
        "core_objective": p.get("core_objective"),
        "partnership_signal": p.get("partnership_signal"),
        "hard_bans": list(p.get("hard_bans") or []),
        "success_criteria": list(p.get("success_criteria") or []),
    }


def describe_sender_for_logs() -> str:
    """Short string used in pipeline logs so operators can confirm
    which persona is active for a given deploy.
    """
    p = get_sender_persona()
    return f"{p.get('role') or p.get('name') or 'unknown'} @ {p.get('company') or '?'}"


__all__ = [
    "DEFAULT_SENDER_PERSONA",
    "get_sender_persona",
    "sender_persona_line",
    "sender_persona_prompt_block",
    "sender_persona_for_context",
    "describe_sender_for_logs",
]
