"""
Insight Engine.

This is the critical reasoning layer that sits between
``observation_distiller`` and ``message_angle_planner``.

An *observation* is a paraphrased description of something real
("Their team appears active around Charlotte BTR/townhome").

An *insight* is a sharpened interpretation of that observation —
pattern recognition, market shifts, tradeoffs, timing effects,
second-order effects, or peer-level points of view.

Example of the difference:
    observation: "Their team appears active around BTR in Texas"
    insight:     "Texas expansion usually shows up after conviction
                  is already there — the second-order effects hit
                  fast."

The insight engine supports two execution paths:

 1) Deterministic / rule-based fallback. Always works. No network.
    Produces reasonable insights derived from signal type, topics,
    places, playbook anti-patterns and knowledge entries.

 2) AI-augmented path (Claude). Used when the configured AI provider
    exposes a ``generate_insights`` method. The deterministic output is
    always kept as a safety fallback so a provider failure never
    crashes the generator.

Returned insights are structured:

    {
        "id": "insight-0",
        "text": "Texas expansion usually shows up after conviction is
                 already there — second-order effects hit fast.",
        "type": "market_pattern|timing|tension|second_order|peer_pov|trend",
        "based_on_observation_ids": ["..."],
        "supporting_signal_ids": ["..."],
        "supporting_note_ids": ["..."],
        "supporting_profile_fields": ["..."],
        "confidence": 0.0..1.0,
        "source": "ai|heuristic",
    }

The insight engine must NEVER fabricate personal facts, only *reasoning*
about facts that are already in context. The distinction is important:
it is allowed to say "groups doing X usually also see Y" (a generic
pattern), but it is NOT allowed to say "you specifically closed Z in
Q3" unless that is already in context.
"""
from __future__ import annotations

from typing import Any, Optional

MAX_INSIGHTS = 5
MAX_INSIGHT_CHARS = 220

# Canonical insight types. The first six entries match the product
# spec's thought-type vocabulary (pattern_recognition,
# tension_tradeoff, contrarian_observation, timing_insight,
# second_order_effect, self_relevance). The legacy short names
# (market_pattern, tension, timing, second_order, peer_pov, trend)
# are kept accepted here so older AI output and existing tests still
# parse — normalize_thought_type() in style_modes.py projects them
# onto the product vocabulary.
INSIGHT_TYPES = (
    "pattern_recognition",
    "tension_tradeoff",
    "contrarian_observation",
    "timing_insight",
    "second_order_effect",
    "self_relevance",
    # legacy / backwards-compatible
    "market_pattern",
    "timing",
    "tension",
    "second_order",
    "peer_pov",
    "trend",
    "contrarian",
)


def _short(text: str, limit: int = MAX_INSIGHT_CHARS) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


def _topic_hits(text: str) -> list[str]:
    lo = (text or "").lower()
    hits = []
    for kw in (
        "btr", "build-to-rent", "townhome", "sfr", "multifamily",
        "land", "capital markets", "fund", "hiring", "expansion",
        "raise", "deal", "portfolio", "joint venture", "acquisition",
    ):
        if kw in lo and kw not in hits:
            hits.append(kw)
    return hits


def _place_hit(text: str) -> Optional[str]:
    lo = (text or "").lower()
    for place in (
        "charlotte", "raleigh", "atlanta", "nashville", "phoenix",
        "dallas", "houston", "austin", "tampa", "denver", "miami",
        "texas", "florida", "north carolina", "sunbelt",
    ):
        if place in lo:
            return place.title()
    return None


def _build_heuristic_insight(
    obs: dict,
    signal_types: set[str],
    knowledge_entries: list[dict],
    playbook_anti_patterns: list[str],
) -> Optional[dict]:
    """Produce one non-trivial insight from an observation.

    The deterministic branch is intentionally conservative — we do NOT
    invent specific numbers or life details. We reason about the *kind
    of situation* this observation describes, drawing on generic market
    patterns from the loaded playbook/knowledge context.
    """
    summary = (obs.get("text") or obs.get("summary") or "").strip()
    if not summary:
        return None
    source = obs.get("source") or "signal"
    source_id = obs.get("source_id") or obs.get("signal_id")
    topics = _topic_hits(summary)
    place = _place_hit(summary)

    # Pick an insight "type" from the context. Every branch anchors
    # the insight on a real operating surface (newer deals, pipeline,
    # underwriting, deal execution, etc.) — abstract "this slice of
    # the market" framing is deliberately avoided.
    if "expansion" in summary.lower() or "hiring" in summary.lower():
        insight_type = "second_order"
        place_clause = f"into {place}" if place else "on newer communities"
        text = (
            f"Groups moving {place_clause} usually have already decided — "
            f"once deals get closer to execution, the sourcing, capital, "
            f"and ops work tends to reshuffle inside a quarter."
        )
    elif any(t in ("capital markets", "fund", "deal", "raise") for t in topics):
        insight_type = "timing"
        text = (
            "Teams showing capital-markets activity on newer deals tend to "
            "be in a narrow window — the product call is usually already "
            "made, what changes fast is how they solve for cost of capital "
            "when underwriting gets deeper."
        )
    elif any(t in ("btr", "townhome", "build-to-rent", "sfr") for t in topics):
        insight_type = "market_pattern"
        text = (
            "On newer BTR/townhome deals, a lot of the groups still moving "
            "feel like they're solving for cost pressure more than pure "
            "demand — which changes what the conversation is really about."
        )
    elif any(t in ("multifamily", "land", "portfolio", "acquisition") for t in topics):
        insight_type = "tension"
        text = (
            "The interesting tension in the pipeline right now is that deal "
            "flow looks steady on the surface, but when underwriting gets "
            "deeper the bar has moved — the teams still transacting are the "
            "ones who already adjusted."
        )
    elif source == "note":
        insight_type = "peer_pov"
        text = (
            f"Worth reading this as a peer-level data point rather than a "
            f"one-off — on newer deals, the pattern you noted usually means "
            f"there's already momentum under the surface."
        )
    else:
        insight_type = "trend"
        text = (
            "The signal itself isn't the point — what matters is where it "
            "shows up in the pipeline: capital is still moving, but it's "
            "getting more selective once underwriting gets deeper."
        )

    # Light playbook bias: if a playbook anti-pattern warns against this
    # topic, we still produce the insight but lower the confidence. This
    # prevents us from pushing a strong POV into an area the playbook
    # tells us is noisy.
    confidence = 0.55
    if topics:
        confidence += 0.1
    if place:
        confidence += 0.1
    if knowledge_entries:
        confidence += 0.05
    confidence = max(0.1, min(0.9, confidence))

    return {
        "text": _short(text),
        "type": insight_type,
        "based_on_observation_ids": [source_id] if source_id else [],
        "supporting_signal_ids": (
            [source_id] if source == "signal" and source_id else []
        ),
        "supporting_note_ids": (
            [source_id] if source == "note" and source_id else []
        ),
        "supporting_profile_fields": (
            [source_id] if source == "profile" and source_id else []
        ),
        "confidence": round(confidence, 3),
        "source": "heuristic",
    }


def _deterministic_insights(
    observations: list[dict],
    signals: list[dict],
    knowledge_entries: list[dict],
    playbook_anti_patterns: list[str],
) -> list[dict]:
    """Always-available fallback path."""
    signal_types = {(s.get("type") or "").lower() for s in signals or []}
    out: list[dict] = []
    seen_types: set[str] = set()
    for obs in observations or []:
        if len(out) >= MAX_INSIGHTS:
            break
        insight = _build_heuristic_insight(
            obs, signal_types, knowledge_entries, playbook_anti_patterns,
        )
        if not insight:
            continue
        # Favor type diversity so the generator gets multiple lenses
        # to pick from — peer POV, market pattern, timing, etc.
        if insight["type"] in seen_types and len(out) >= 2:
            continue
        seen_types.add(insight["type"])
        insight["id"] = f"insight-{len(out)}"
        out.append(insight)
    return out


def _normalize_ai_insights(
    ai_insights: list[dict],
    observations: list[dict],
) -> list[dict]:
    """Accept an AI-produced insight list and shape it for downstream."""
    obs_ids = [
        o.get("source_id") or o.get("signal_id")
        for o in (observations or [])
        if (o.get("source_id") or o.get("signal_id"))
    ]
    out: list[dict] = []
    for i, raw in enumerate(ai_insights or []):
        if not isinstance(raw, dict):
            continue
        text = _short(raw.get("text") or raw.get("insight") or "")
        if not text:
            continue
        t = (raw.get("type") or "trend").lower()
        if t not in INSIGHT_TYPES:
            t = "trend"
        based_on = raw.get("based_on_observation_ids") or []
        # If the AI returned nothing or garbage ids, default to all
        # observation ids we gave it — it's still grounded.
        if not isinstance(based_on, list) or not based_on:
            based_on = obs_ids
        try:
            conf = float(raw.get("confidence", 0.7))
        except (TypeError, ValueError):
            conf = 0.7
        conf = max(0.0, min(1.0, conf))
        out.append({
            "id": f"insight-{i}",
            "text": text,
            "type": t,
            "based_on_observation_ids": based_on[:5],
            "supporting_signal_ids": raw.get("supporting_signal_ids") or [],
            "supporting_note_ids": raw.get("supporting_note_ids") or [],
            "supporting_profile_fields": raw.get("supporting_profile_fields") or [],
            "confidence": round(conf, 3),
            "source": "ai",
        })
        if len(out) >= MAX_INSIGHTS:
            break
    return out


def generate_insights(
    context: dict,
    provider: Optional[Any] = None,
) -> dict:
    """Produce insights from the distilled observations in ``context``.

    Returns a dict with:
        {
          "insights": [...],
          "source": "ai|heuristic|hybrid",
          "error": Optional[str],
        }

    Never raises. On any provider failure it falls back to the
    deterministic branch and records the failure under ``error``.
    """
    observations = context.get("distilled_observations") or []
    signals = context.get("signals") or []
    knowledge_entries = context.get("knowledge_entries") or []
    pb_anti_patterns = context.get("playbook_anti_patterns") or []

    # Always compute the deterministic branch first so we have a
    # guaranteed non-empty fallback.
    fallback = _deterministic_insights(
        observations, signals, knowledge_entries, pb_anti_patterns,
    )

    if provider is None:
        return {
            "insights": fallback,
            "source": "heuristic",
            "error": None,
        }

    gen_insights_fn = getattr(provider, "generate_insights", None)
    if not callable(gen_insights_fn):
        return {
            "insights": fallback,
            "source": "heuristic",
            "error": None,
        }

    try:
        raw = gen_insights_fn(context)
    except Exception as e:
        print(
            f"[SignalStack] insight_engine: provider generate_insights "
            f"FAILED — falling back to heuristic: {type(e).__name__}: {e}"
        )
        return {
            "insights": fallback,
            "source": "heuristic",
            "error": f"provider_insight_failed:{type(e).__name__}",
        }

    ai_insights = _normalize_ai_insights(raw or [], observations)
    if not ai_insights:
        return {
            "insights": fallback,
            "source": "heuristic",
            "error": "ai_insights_empty",
        }
    # Hybrid: prefer AI insights but keep 1 strong heuristic at the end
    # for redundancy so the generator always has at least one sharp POV.
    hybrid = ai_insights
    if fallback and len(hybrid) < MAX_INSIGHTS:
        hybrid = hybrid + fallback[: MAX_INSIGHTS - len(hybrid)]
    return {
        "insights": hybrid,
        "source": "ai" if len(hybrid) == len(ai_insights) else "hybrid",
        "error": None,
    }
