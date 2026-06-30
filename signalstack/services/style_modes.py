"""
Style Modes and Psychology Angles.

This module is the single source of truth for the five distinct
voice/style modes the message engine rotates through on every
generation call, and the psychology angles the generator is allowed
to lean on.

Why this module exists
----------------------
Previously ``message_angle_planner`` tracked only "angles" like
``curiosity`` and ``point_of_view``. The result was that when the
generator produced 4 options, the options tended to collapse into
minor rewrites of the same line — different angle names, same voice.

The fix is to layer an orthogonal axis on top of the angle axis:
**style mode**. A style mode describes the *voice* the message is
written in. Two messages can share an angle (e.g. ``market_pattern``)
but still land as completely different-sounding messages if they're
written in two different style modes (e.g. ``quiet_contrarian`` vs
``low_ego_peer``).

The five style modes are the ones the product spec explicitly calls
for. Each one is paired with:
  * a voice description the LLM is given in the prompt,
  * a typical pacing / rhythm cue,
  * a small list of allowed psychology angles,
  * a short "must not" list so the generator can't slide back into
    sales-bot mode from inside the style.

Psychology angles
-----------------
Six psychology levers, each ethically scoped. These are the ONLY
levers the generator is allowed to lean on — the taste filter rejects
anything that tries to use manipulation, fake scarcity, or aggressive
reverse psychology.

Nothing in this module runs at request time beyond pure lookups and
small helper functions — it is safe to import anywhere.
"""
from __future__ import annotations

from typing import Optional


# ----- Psychology angles (ethical levers only) ---------------------

PSYCHOLOGY_ANGLES: dict[str, dict] = {
    "curiosity": {
        "description": (
            "Open a question the recipient would also like to know the "
            "answer to. Not a pitch hook — a real question."
        ),
        "tone_cue": "open, unweighted",
    },
    "self_relevance": {
        "description": (
            "Frame the observation so it implicates something the "
            "recipient is already thinking about. The recipient "
            "recognizes themselves in the sentence without being told "
            "'this is about you'."
        ),
        "tone_cue": "mirror-like, understated",
    },
    "low_pressure_control": {
        "description": (
            "Put the recipient in control of the next move. No asks, "
            "no time pressure, no commitment. The cost of ignoring it "
            "is zero."
        ),
        "tone_cue": "calm, no-ask",
    },
    "pattern_recognition": {
        "description": (
            "Name a pattern the writer is seeing across similar roles "
            "or markets. The recipient is invited to compare notes, "
            "not to accept the pattern."
        ),
        "tone_cue": "observational, plural",
    },
    "peer_status_framing": {
        "description": (
            "Write as a peer, not a vendor. Subtle status signal: the "
            "writer is in the same conversation the recipient is in, "
            "not outside it asking to be let in."
        ),
        "tone_cue": "shoulder-to-shoulder",
    },
    "subtle_contrast": {
        "description": (
            "Put two plausible interpretations in light tension. The "
            "recipient feels the contrast without being told which "
            "side is correct."
        ),
        "tone_cue": "understated, two-handed",
    },
    "earned_contrarianism": {
        "description": (
            "Disagree lightly with the default reading of a situation. "
            "Earned, not performative. Invites pushback — 'tell me I'm "
            "wrong' is fine, theatrics are not."
        ),
        "tone_cue": "calm, falsifiable",
    },
}


# ----- Style Modes -------------------------------------------------

STYLE_MODES: list[dict] = [
    {
        "mode": "curious_insider",
        "description": (
            "The writer sounds like someone already inside the "
            "conversation, asking a real question a peer would ask. "
            "Not surprised to be in the room. The voice is warm but "
            "not eager."
        ),
        "voice_guidelines": [
            "Open with a short observation the recipient would plausibly think themselves.",
            "Ask a real question, not a rhetorical one.",
            "Keep the middle sentence calm, not loaded.",
            "Avoid any 'I help X' or 'I work with firms like Y' framing.",
        ],
        "allowed_psychology": ["curiosity", "self_relevance", "peer_status_framing"],
        "must_not": [
            "sound eager or flattering",
            "ask for time or a call",
            "restate the profile",
        ],
        "pacing": "short observation -> single question -> stop",
    },
    {
        "mode": "quiet_contrarian",
        "description": (
            "The writer holds a light, earned counter-view of the "
            "default read. Says 'I may be wrong, but here's how I see "
            "it' without theatrics. Invites pushback."
        ),
        "voice_guidelines": [
            "Name the default read briefly, then offer the contrast.",
            "Keep the counter-view falsifiable — one sentence, no hedging stack.",
            "End with a soft 'tell me I'm reading it wrong' style invitation.",
            "Never perform contrarianism for attention — it has to be earned.",
        ],
        "allowed_psychology": ["earned_contrarianism", "subtle_contrast", "pattern_recognition"],
        "must_not": [
            "be aggressive or dunk on anyone",
            "use fake scarcity or reverse psychology",
            "stack multiple hedges back-to-back",
        ],
        "pacing": "default read -> contrast -> soft pushback invitation",
    },
    {
        "mode": "pattern_spotter",
        "description": (
            "The writer has been watching a lot of similar desks and "
            "names the pattern they keep seeing. The recipient is "
            "invited to compare notes, not to accept the pattern."
        ),
        "voice_guidelines": [
            "Open with 'pattern I keep seeing' / 'feels like' / 'most groups in this seat'.",
            "Frame the pattern as a possibility, not a fact.",
            "End with a compare-notes ask — never a sales ask.",
            "Name ONE pattern per message. No lists.",
        ],
        "allowed_psychology": ["pattern_recognition", "self_relevance", "low_pressure_control"],
        "must_not": [
            "stack multiple patterns in one message",
            "claim the pattern applies to this specific person",
            "insert buzzwords",
        ],
        "pacing": "plural observation -> one-line interpretation -> compare-notes ask",
    },
    {
        "mode": "low_ego_peer",
        "description": (
            "The writer is calm, understated, a little self-deprecating. "
            "Opens a line without pitching anything. Would still be "
            "welcome even if the recipient ignores the message entirely."
        ),
        "voice_guidelines": [
            "Keep the middle line understated — the cost of 'no' is visibly zero.",
            "One real thought, no list.",
            "Be fine with silence — the message has to survive a non-reply.",
            "Small casual language is allowed; slick language is not.",
        ],
        "allowed_psychology": ["low_pressure_control", "peer_status_framing", "curiosity"],
        "must_not": [
            "ask for a call",
            "sound like an opener in a sequence",
            "use any 'quick chat' / 'circle back' language",
        ],
        "pacing": "soft observation -> understated thought -> no-ask close",
    },
    {
        "mode": "sharp_operator",
        "description": (
            "The writer sounds like an operator who's been through the "
            "tradeoff themselves. Concise, specific in framing (not in "
            "false facts), slightly understated. Earned authority, not "
            "claimed authority."
        ),
        "voice_guidelines": [
            "Lead with the interpretation, not the greeting.",
            "Be direct but not pushy — operators don't chase.",
            "Use first-person 'my read' language where it fits, sparingly.",
            "Short sentences. No hedging stack.",
        ],
        "allowed_psychology": ["earned_contrarianism", "subtle_contrast", "self_relevance", "peer_status_framing"],
        "must_not": [
            "sound like a vendor / demo request",
            "over-explain the reasoning",
            "use authority-claiming phrases like 'in my experience I've found that'",
        ],
        "pacing": "one-line interpretation -> short peer ask",
    },
]

# Mode name -> spec lookup. Stable iteration order (insertion order).
STYLE_MODE_BY_NAME: dict[str, dict] = {m["mode"]: m for m in STYLE_MODES}

# Default psychology angle to assign when a mode allows several and
# the planner didn't pick one.
DEFAULT_PSYCHOLOGY_BY_MODE: dict[str, str] = {
    "curious_insider": "curiosity",
    "quiet_contrarian": "earned_contrarianism",
    "pattern_spotter": "pattern_recognition",
    "low_ego_peer": "low_pressure_control",
    "sharp_operator": "self_relevance",
}


def list_style_modes() -> list[dict]:
    """Return the full style mode spec list (stable order)."""
    return list(STYLE_MODES)


def get_style_mode(name: str) -> Optional[dict]:
    return STYLE_MODE_BY_NAME.get((name or "").strip().lower())


def rotate_style_modes(n: int, start_index: int = 0) -> list[dict]:
    """
    Return ``n`` distinct style modes, rotating through the canonical
    list so two consecutive requests don't always produce the same
    ordering. Order is deterministic given ``start_index``.
    """
    if n <= 0:
        return []
    n = min(n, len(STYLE_MODES))
    out: list[dict] = []
    for i in range(n):
        out.append(STYLE_MODES[(start_index + i) % len(STYLE_MODES)])
    return out


def default_psychology_for(mode_name: str) -> str:
    return DEFAULT_PSYCHOLOGY_BY_MODE.get(
        (mode_name or "").strip().lower(), "curiosity"
    )


def psychology_angle_names() -> list[str]:
    return list(PSYCHOLOGY_ANGLES.keys())


def describe_psychology(angle_name: str) -> Optional[dict]:
    return PSYCHOLOGY_ANGLES.get((angle_name or "").strip().lower())


# ----- Thought type vocabulary (used by insight_engine + translator) -----
#
# The product spec requires each candidate thought to carry a type
# drawn from this closed vocabulary. This keeps the generator honest:
# a thought is a specific KIND of observation, not a vibe.

THOUGHT_TYPES = (
    "pattern_recognition",
    "tension_tradeoff",
    "contrarian_observation",
    "timing_insight",
    "second_order_effect",
    "self_relevance",
)


# Map internal insight_engine type names (legacy) to the product-spec
# thought-type vocabulary. Used so the existing insight engine output
# doesn't need to be rewritten in a single patch.
LEGACY_INSIGHT_TYPE_TO_THOUGHT_TYPE: dict[str, str] = {
    "market_pattern": "pattern_recognition",
    "pattern": "pattern_recognition",
    "trend": "pattern_recognition",
    "timing": "timing_insight",
    "tension": "tension_tradeoff",
    "second_order": "second_order_effect",
    "peer_pov": "self_relevance",
    "contrarian": "contrarian_observation",
}


def normalize_thought_type(raw: Optional[str]) -> str:
    """Project any legacy or near-match thought type name onto the
    closed product vocabulary. Unknown values become ``pattern_recognition``
    (the safest generic fallback)."""
    if not raw:
        return "pattern_recognition"
    key = raw.strip().lower()
    if key in THOUGHT_TYPES:
        return key
    return LEGACY_INSIGHT_TYPE_TO_THOUGHT_TYPE.get(key, "pattern_recognition")
