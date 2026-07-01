"""
Sales Intelligence Engine orchestrator.

Ties together lead-context building, conversation-strategy selection,
question-path generation, message drafting, the objection playbook, and
reasoning explanation into one SalesIntelligencePackage. Live-computed —
mirrors how stage_timing/process_stage already work (never persisted as
the source of truth, never recomputes scoring math).

Optionally logs an append-only decision event for REAL leads only (demo
lead ids regenerate every pipeline run, so a logged decision on one would
be orphaned before anyone could read it back — same rule as every other
append-only table in this module). The log is deliberately NOT written on
every view: only when the actual decision (temperature/origin/scenario/
awareness/resistance/stage/action) has changed since the last logged
event, or when the caller passes a nonzero `variant` (an explicit
"Regenerate approach" from the operator). This keeps the history useful
for future calibration (which approach correlates with meetings/wins)
without spamming a new row every time a drawer or Workbench row is opened.
"""
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from multifamily.types import MultifamilyLead
from multifamily.timing.process_stage_types import ProcessStageResult
from multifamily.timing.process_stage_detector import detect_process_stage
from multifamily import repository
from multifamily.sales_intelligence.nepq_types import SalesIntelligencePackage
from multifamily.sales_intelligence.lead_context_builder import build_lead_context
from multifamily.sales_intelligence.conversation_strategy_engine import select_strategy
from multifamily.sales_intelligence.question_path_engine import build_question_path
from multifamily.sales_intelligence.message_strategy_engine import build_message_package
from multifamily.sales_intelligence.objection_strategy_engine import objection_playbook
from multifamily.sales_intelligence.reasoning_explainer import build_reasoning
from multifamily.sales_intelligence.tone_guardrails import check_message_package, worst_status
from multifamily.sales_intelligence.follow_up_strategy_engine import select_follow_up_strategy


def build_sales_intelligence(
    lead: MultifamilyLead,
    stage_result: Optional[ProcessStageResult] = None,
    activities: Optional[List[Dict[str, Any]]] = None,
    outcomes: Optional[List[Dict[str, Any]]] = None,
    variant: int = 0,
    log: bool = True,
) -> SalesIntelligencePackage:
    stage_result = stage_result or detect_process_stage(lead)
    context = build_lead_context(lead, stage_result, activities, outcomes)
    strategy = select_strategy(context)
    question_path = build_question_path(context, strategy)
    messages = build_message_package(context, strategy, question_path, variant=variant)
    playbook = objection_playbook(context)
    follow_up_strategy = select_follow_up_strategy(context, strategy)
    reasoning = build_reasoning(context, strategy, question_path)
    guardrail_status = worst_status(check_message_package(messages))

    if log and not lead.is_demo:
        _maybe_log_event(lead.id, context, strategy, follow_up_strategy, reasoning, variant, guardrail_status)

    return SalesIntelligencePackage(
        lead_id=lead.id, variant=variant, context=context, strategy=strategy,
        question_path=question_path, messages=messages, objection_playbook=playbook,
        follow_up_strategy=follow_up_strategy, reasoning=reasoning,
    )


def _decision_tuple(context, strategy, follow_up_strategy):
    return (
        context.lead_temperature, context.lead_origin, context.insurance_scenario,
        context.buyer_awareness_level, context.resistance_risk, strategy.starting_nepq_stage,
        strategy.recommended_action, strategy.conversation_mode, follow_up_strategy.follow_up_type,
    )


def _maybe_log_event(
    lead_id: str, context, strategy, follow_up_strategy, reasoning, variant: int, guardrail_status: str,
) -> None:
    latest = repository.get_latest_sales_intelligence_event(lead_id)
    if latest and variant == 0:
        prev_tuple = (
            latest.get('lead_temperature'), latest.get('lead_origin'), latest.get('insurance_scenario'),
            latest.get('buyer_awareness_level'), latest.get('resistance_risk'), latest.get('nepq_stage'),
            latest.get('recommended_action'), latest.get('conversation_mode'), latest.get('follow_up_type'),
        )
        if prev_tuple == _decision_tuple(context, strategy, follow_up_strategy):
            return  # nothing changed -> don't spam the decision log
    repository.log_sales_intelligence_event(
        lead_id, variant=variant, lead_temperature=context.lead_temperature, lead_origin=context.lead_origin,
        insurance_scenario=context.insurance_scenario, buyer_awareness_level=context.buyer_awareness_level,
        resistance_risk=context.resistance_risk, nepq_stage=strategy.starting_nepq_stage,
        recommended_action=strategy.recommended_action, confidence_score=reasoning.confidence_score,
        reasoning=asdict(reasoning), conversation_mode=strategy.conversation_mode,
        follow_up_type=follow_up_strategy.follow_up_type, guardrail_status=guardrail_status,
    )
