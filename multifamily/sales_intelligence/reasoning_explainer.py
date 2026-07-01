"""
Reasoning Explainer — produces the "Why this approach?" summary that
accompanies every generated sales-intelligence package, so an operator
(and the drawer/Workbench UI) can see WHY the engine chose what it chose,
not just the output.
"""
from typing import List

from multifamily.sales_intelligence.nepq_types import (
    SalesLeadContext, ConversationStrategy, QuestionPath, SalesIntelligenceReasoning,
)

_RULE_LABELS = {
    'rule_1_11_direct_inbound': 'Direct inbound request',
    'rule_2_website_intent_soft_curiosity': 'Website/search intent — soft curiosity',
    'rule_3_renewal_within_120': 'Renewal-window pressure',
    'rule_4_acquisition_diligence': 'Acquisition due-diligence validation',
    'rule_5_refinance_lender': 'Refinance / lender-condition check',
    'rule_6_construction_builders_risk': "Construction / builder's risk placement",
    'rule_7_completion_lease_up': 'Completion / lease-up transition',
    'rule_8_permit_news_soft_relevance_check': 'Trigger-only — soft relevance check',
    'rule_9_nurture_watchlist_no_pitch': 'Nurture / watchlist — no pitch',
    'rule_default_unknown_scenario': 'Unclassified — cautious opener',
}


def _key_lead_signals_used(context: SalesLeadContext) -> List[str]:
    signals = [
        f"temperature={context.lead_temperature}",
        f"origin={context.lead_origin}",
        f"scenario={context.insurance_scenario}",
        f"buyer_awareness={context.buyer_awareness_level}",
        f"resistance_risk={context.resistance_risk}",
    ]
    if context.process_stage:
        signals.append(f"process_stage={context.process_stage}")
    if context.signal_types:
        signals.append(f"signals={','.join(context.signal_types)}")
    if context.pain_flags:
        signals.append(f"pain_flags={','.join(context.pain_flags)}")
    if context.days_until_renewal is not None:
        signals.append(f"days_until_renewal={context.days_until_renewal}")
    return signals


def _assumed_pain_points(context: SalesLeadContext) -> List[str]:
    if context.pain_flags:
        return list(context.pain_flags)
    if context.likely_emotional_driver:
        return [context.likely_emotional_driver]
    return ['none confirmed yet — this is a hypothesis to test through discovery, not a stated pain point']


def _confidence_score(context: SalesLeadContext) -> float:
    score = 0.5
    if context.insurance_scenario != 'unknown':
        score += 0.1
    if context.buyer_awareness_level not in ('unknown',):
        score += 0.1
    if context.pain_flags:
        score += 0.1
    if context.signal_count >= 2:
        score += 0.1
    if context.contact_title:
        score += 0.1
    if context.resistance_risk == 'high':
        score -= 0.15
    if context.is_demo:
        score -= 0.1
    return round(max(0.05, min(0.95, score)), 2)


def _recommended_next_step(strategy: ConversationStrategy, question_path: QuestionPath) -> str:
    if strategy.recommended_action == 'call_now':
        return f"Call now. Open with: \"{question_path.connection_question}\""
    if strategy.recommended_action == 'nurture':
        return f"No active outreach — nurture. If reconnecting: \"{question_path.fallback_question}\""
    return f"{strategy.recommended_action.replace('_', ' ')}. Suggested ask: \"{question_path.commitment_question}\""


def build_reasoning(
    context: SalesLeadContext, strategy: ConversationStrategy, question_path: QuestionPath,
) -> SalesIntelligenceReasoning:
    rule_label = _RULE_LABELS.get(strategy.rule_applied, strategy.rule_applied or 'unclassified')
    why_this_stage = (
        f"{rule_label} matched this lead's context (temperature={context.lead_temperature}, "
        f"origin={context.lead_origin}, scenario={context.insurance_scenario}), so the engine starts "
        f"in '{strategy.starting_nepq_stage}' rather than jumping to presentation."
    )
    why_this_message = (
        f"Tone set to '{strategy.recommended_tone}' because resistance_risk={context.resistance_risk} "
        f"and buyer_awareness={context.buyer_awareness_level}; the message leads with a question about "
        f"{context.insurance_scenario.replace('_', ' ')} rather than any claim, and avoids presenting the "
        f"program before enough situation/problem context exists."
    )
    return SalesIntelligenceReasoning(
        selected_strategy=rule_label,
        selected_nepq_stage=strategy.starting_nepq_stage,
        why_this_stage=why_this_stage,
        why_this_message=why_this_message,
        key_lead_signals_used=_key_lead_signals_used(context),
        assumed_pain_points=_assumed_pain_points(context),
        missing_information=list(context.missing_information),
        what_to_avoid=list(strategy.do_not),
        confidence_score=_confidence_score(context),
        recommended_next_step=_recommended_next_step(strategy, question_path),
    )
