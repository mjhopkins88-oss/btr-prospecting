"""
Reasoning Pipeline Orchestrator.

This module is the thin "conductor" that runs the multi-stage
AI-native pipeline on a prepared ``context`` dict. It is deliberately
slim and side-effect-free beyond mutating the context it is given —
all of the heavy lifting lives in the individual stage modules so
each stage can be tested and swapped independently.

Stage ordering:

    1. input_quality_scorer.score_inputs
    2. observation_distiller.distill
    3. (optional) playbook_loader.load_relevant_entries
    4. insight_engine.generate_insights
    5. message_angle_planner.plan (strategy selector)
    6. provider.generate_messages
    7. grounding + anti_copy + anti_generic validation
    8. message_critic.critique_all
    9. final accept/rewrite/reject bucketing

The generator.generate() entry point still owns the context build and
the final response shape; the orchestrator is here so we have one place
to reason about pipeline ordering when we add more stages.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from . import insight_engine
from . import message_critic
from .input_quality_scorer import score_inputs
from .message_angle_planner import plan as plan_angles
from .observation_distiller import distill as distill_observations


def run_pre_generation_stages(
    context: dict,
    provider: Any,
    stage_recorder: Optional[Callable[[str, str], None]] = None,
) -> dict:
    """Run normalization -> observations -> insights -> strategy.

    Mutates ``context`` in place so downstream generator code can
    consume the distilled observations / insights / strategies. Returns
    a small summary dict for the response payload.
    """

    def _stage(name: str, status: str) -> None:
        if stage_recorder is not None:
            stage_recorder(name, status)

    _stage("input_quality", "running")
    quality = score_inputs(context)
    _stage("input_quality", "ok")

    _stage("observation_distill", "running")
    distilled = distill_observations(context)
    context["distilled_observations"] = distilled
    _stage("observation_distill", "ok")

    _stage("insight_engine", "running")
    insight_result = insight_engine.generate_insights(context, provider=provider)
    context["insights"] = insight_result.get("insights") or []
    _stage(
        "insight_engine",
        (
            "ai" if insight_result.get("source") == "ai"
            else ("hybrid" if insight_result.get("source") == "hybrid" else "heuristic")
        ),
    )

    return {
        "quality": quality,
        "distilled_observations": distilled,
        "insights": context["insights"],
        "insight_source": insight_result.get("source"),
        "insight_error": insight_result.get("error"),
    }


def run_strategy_selection(
    context: dict,
    quality: dict,
    n: int,
    strategy_override: Optional[dict],
    playbook_preferred_angles: Optional[list[str]],
    stage_recorder: Optional[Callable[[str, str], None]] = None,
) -> list[dict]:
    """Strategy selector stage. Isolated here so the AI-augmented path
    can be wired in without touching generator.generate().
    """
    if stage_recorder is not None:
        stage_recorder("strategy_plan", "running")
    strategies = plan_angles(
        quality,
        n=n,
        override=strategy_override,
        playbook_preferred_angles=playbook_preferred_angles,
    )
    # Attach "why" metadata to each strategy — the UI renders this
    # under the "strategy reasoning" block so the user can see WHY
    # this particular angle mix was chosen.
    strongest_sig = (quality.get("strongest_available_signal") or {}).get("type")
    insights = context.get("insights") or []
    top_insight_type = insights[0]["type"] if insights else None
    for s in strategies:
        reasons = []
        if s.get("angle") == "point_of_view" and top_insight_type in ("market_pattern", "second_order"):
            reasons.append("insight_type_supports_POV")
        if strongest_sig == "post_topic" and s.get("angle") == "curiosity":
            reasons.append("strongest_signal_is_post_topic")
        if strongest_sig in ("company_expansion", "hiring_activity") and s.get("angle") == "timely_observation":
            reasons.append("timely_signal_available")
        if quality.get("weak_only") and s.get("angle") == "low_pressure_starter":
            reasons.append("weak_inputs_only")
        if not reasons:
            reasons.append("default_diversity")
        s["reasons"] = reasons
    if stage_recorder is not None:
        stage_recorder("strategy_plan", "ok")
    return strategies


def run_critique_stage(
    candidates: list[dict],
    context: dict,
    provider: Any,
    stage_recorder: Optional[Callable[[str, str], None]] = None,
) -> dict:
    """Run the critic over every candidate and bucket by verdict.

    Returns:
        {
          "accepted": [...],
          "rewrite": [...],  # kept as-is; the generator downgrades these
          "rejected": [...],
          "summary": {counts...},
        }
    """
    if stage_recorder is not None:
        stage_recorder("message_critic", "running")
    insights = context.get("insights") or []
    critiqued = message_critic.critique_all(
        candidates, context, insights=insights, provider=provider,
    )

    accepted: list[dict] = []
    rewrite: list[dict] = []
    rejected: list[dict] = []
    for c in critiqued:
        verdict = (c.get("critique") or {}).get("verdict", "accept")
        if verdict == "accept":
            accepted.append(c)
        elif verdict == "rewrite":
            rewrite.append(c)
        else:
            rejected.append(c)

    summary = {
        "accepted": len(accepted),
        "rewrite": len(rewrite),
        "rejected": len(rejected),
    }
    if stage_recorder is not None:
        stage_recorder(
            "message_critic",
            (
                "ok" if accepted or rewrite
                else "degraded_all_rejected"
            ),
        )
    return {
        "accepted": accepted,
        "rewrite": rewrite,
        "rejected": rejected,
        "summary": summary,
    }
