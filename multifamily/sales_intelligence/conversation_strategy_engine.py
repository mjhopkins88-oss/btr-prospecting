"""
Conversation Strategy Engine — decides HOW to approach a lead, before any
copy is generated. Implements the 14 strategy rules from the Multifamily
Sales Intelligence brief as an ordered rule chain (first match wins, see
sales_stage_classifier.py); every strategy carries the rule_applied name
for the reasoning explainer and a conversation_mode label for the UI.

Universal guardrails (always applied, regardless of which rule matched):
  - never claim savings percentages
  - never present the full program before situation/problem context exists
  - lead with questions, not conclusions
"""
from multifamily.sales_intelligence.nepq_types import SalesLeadContext, ConversationStrategy
from multifamily.sales_intelligence.sales_stage_classifier import classify_stage

_UNIVERSAL_DO_NOT = [
    "claim a specific savings percentage or guarantee an outcome",
    "present the full program/coverage details before enough situation/problem context exists",
    "sound like a scripted salesperson — keep it conversational",
]

_HIGH_RESISTANCE_DO_NOT = [
    "send a long message — keep it to 2-3 sentences",
    "ask more than one question at a time",
    "assume they have a problem — offer an easy out",
]

_TRIGGER_ONLY_DO_NOT = [
    "assume they're actively looking for insurance help",
    "open with anything that sounds like a pitch",
]

_NURTURE_DO_NOT = [
    "use direct pitch language",
    "push for a call or meeting",
]

# 1:1 mapping from rule_applied -> conversation_mode (see nepq_types.CONVERSATION_MODES).
# objection_resolution and follow_up are assigned elsewhere (objection engine /
# follow_up_strategy_engine), not by select_strategy().
_CONVERSATION_MODE_BY_RULE = {
    'rule_8_permit_news_soft_relevance_check': 'trigger_based_outbound',
    'rule_3_renewal_within_120': 'renewal_discovery',
    'rule_4_acquisition_diligence': 'acquisition_discovery',
    'rule_5_refinance_lender': 'lender_compliance_discovery',
    'rule_6_construction_builders_risk': 'construction_discovery',
    'rule_7_completion_lease_up': 'completion_transition_discovery',
    'rule_2_website_intent_soft_curiosity': 'warm_contextual_outreach',
    'rule_1_11_direct_inbound': 'inbound_response',
    'rule_9_nurture_watchlist_no_pitch': 'nurture_check_in',
    'rule_default_unknown_scenario': 'warm_contextual_outreach',
}


def _base(**kwargs) -> ConversationStrategy:
    do_not = list(_UNIVERSAL_DO_NOT)
    extra_do_not = kwargs.pop('extra_do_not', None) or []
    do_not = extra_do_not + do_not
    return ConversationStrategy(do_not=do_not, **kwargs)


def _build_rule_8_permit_news_soft_relevance_check(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    return _base(
        starting_nepq_stage=stage,
        primary_objective="check whether insurance/coverage is even on their radar at this stage — no assumptions",
        recommended_tone='soft, low-pressure, curious',
        recommended_action='nurture',
        ask_first="whether this project/event has reached the point where insurance is something they're thinking about yet",
        should_present=False, call_now=False, ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=False,
        extra_do_not=_TRIGGER_ONLY_DO_NOT,
        rule_applied='rule_8_permit_news_soft_relevance_check',
    )


def _build_rule_3_renewal_within_120(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    temperature = context.lead_temperature
    return _base(
        starting_nepq_stage=stage,
        primary_objective='understand renewal timeline, market-testing status, incumbent broker process, premium/deductible movement, and any lender/NOI pressure',
        recommended_tone='neutral, calm, curious',
        recommended_action=('call_now' if temperature in ('call_today', 'hot') else 'ask_for_renewal_timing'),
        ask_first='where they are in the renewal process and whether the market has already been tested this cycle',
        should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
        challenge_assumptions_carefully=True, move_toward_next_step=(temperature in ('call_today', 'hot')),
        rule_applied='rule_3_renewal_within_120',
    )


def _build_rule_4_acquisition_diligence(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    temperature = context.lead_temperature
    return _base(
        starting_nepq_stage=stage,
        primary_objective='understand whether they are underwriting off seller-provided insurance numbers or independently validating property/GL/excess/deductible assumptions before close',
        recommended_tone='neutral, consultative',
        recommended_action='ask_for_current_program_details',
        ask_first='whether the insurance assumptions in the deal are being independently pressure-tested or taken from the seller as-is',
        should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
        challenge_assumptions_carefully=True, move_toward_next_step=(temperature == 'call_today'),
        rule_applied='rule_4_acquisition_diligence',
    )


def _build_rule_5_refinance_lender(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    # Covers both the refinance_or_financing scenario and a bare
    # lender_requirement pain flag (a lender issue on its own is squarely
    # this rule's domain per the brief).
    temperature = context.lead_temperature
    return _base(
        starting_nepq_stage=stage,
        primary_objective='understand which lender insurance conditions are still open — property, GL, excess, deductibles, exclusions, escrow, carrier rating',
        recommended_tone='neutral, precise',
        recommended_action='ask_for_lender_requirements',
        ask_first='whether the lender insurance requirements are already cleared or if items are still open',
        should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=(temperature == 'call_today'),
        rule_applied='rule_5_refinance_lender',
    )


def _build_rule_6_construction_builders_risk(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    temperature = context.lead_temperature
    return _base(
        starting_nepq_stage=stage,
        primary_objective="find out whether builder's risk is already placed and locked in, or still a moving piece",
        recommended_tone='neutral, practical',
        recommended_action='ask_for_current_program_details',
        ask_first="whether builder's risk has already been bound or is still open",
        should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=(temperature == 'call_today'),
        rule_applied='rule_6_construction_builders_risk',
    )


def _build_rule_7_completion_lease_up(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    temperature = context.lead_temperature
    return _base(
        starting_nepq_stage=stage,
        primary_objective="understand where they are in the transition from builder's risk to operating property/GL as units come online",
        recommended_tone='neutral, forward-looking',
        recommended_action='ask_for_current_program_details',
        ask_first="whether the transition off builder's risk has already been mapped out",
        should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=(temperature == 'call_today'),
        rule_applied='rule_7_completion_lease_up',
    )


def _build_rule_2_website_intent_soft_curiosity(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    return _base(
        starting_nepq_stage=stage,
        primary_objective='use soft curiosity to find out what (if anything) prompted the interest — do not assume a problem',
        recommended_tone='soft, curious, no pressure',
        recommended_action='send_soft_email',
        ask_first='which bucket (if any) is closest to what brought them to look — renewal, acquisition, lender requirement, or deductible concern',
        should_present=False, call_now=False, ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=False,
        rule_applied='rule_2_website_intent_soft_curiosity',
    )


def _build_rule_1_11_direct_inbound(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    temperature = context.lead_temperature
    return _base(
        starting_nepq_stage=stage,
        primary_objective='acknowledge the request, then move quickly into situation and problem-awareness before assuming what they need',
        recommended_tone='neutral, warm, question-led',
        recommended_action=('call_now' if temperature in ('call_today', 'hot') else 'schedule_benchmark_call'),
        ask_first='what prompted them to reach out now',
        should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=True,
        rule_applied='rule_1_11_direct_inbound',
    )


def _build_rule_9_nurture_watchlist_no_pitch(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    # Reached only when no specific scenario/origin rule above matched
    # (i.e. there's genuinely no active discovery thread yet, not just a
    # low raw score on an otherwise identifiable scenario — those are
    # handled by rules 3-7 regardless of temperature, softened only via
    # recommended_action/tone).
    return _base(
        starting_nepq_stage=stage,
        primary_objective='stay visible, ask permission to revisit at a better time — no pitch',
        recommended_tone='very low pressure, patient',
        recommended_action='nurture',
        ask_first='whether it would be worth reconnecting closer to a more relevant time (renewal, acquisition, next project)',
        should_present=False, call_now=False, ask_for_information=False,
        challenge_assumptions_carefully=False, move_toward_next_step=False,
        extra_do_not=_NURTURE_DO_NOT,
        rule_applied='rule_9_nurture_watchlist_no_pitch',
    )


def _build_rule_default_unknown_scenario(context: SalesLeadContext, stage: str) -> ConversationStrategy:
    return _base(
        starting_nepq_stage=stage,
        primary_objective='establish relevance before asking anything specific',
        recommended_tone='neutral, low-key',
        recommended_action='ask_for_context',
        ask_first='whether multifamily insurance is even something on their plate right now',
        should_present=False, call_now=False, ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=False,
        rule_applied='rule_default_unknown_scenario',
    )


_RULE_BUILDERS = {
    'rule_8_permit_news_soft_relevance_check': _build_rule_8_permit_news_soft_relevance_check,
    'rule_3_renewal_within_120': _build_rule_3_renewal_within_120,
    'rule_4_acquisition_diligence': _build_rule_4_acquisition_diligence,
    'rule_5_refinance_lender': _build_rule_5_refinance_lender,
    'rule_6_construction_builders_risk': _build_rule_6_construction_builders_risk,
    'rule_7_completion_lease_up': _build_rule_7_completion_lease_up,
    'rule_2_website_intent_soft_curiosity': _build_rule_2_website_intent_soft_curiosity,
    'rule_1_11_direct_inbound': _build_rule_1_11_direct_inbound,
    'rule_9_nurture_watchlist_no_pitch': _build_rule_9_nurture_watchlist_no_pitch,
    'rule_default_unknown_scenario': _build_rule_default_unknown_scenario,
}


def select_strategy(context: SalesLeadContext) -> ConversationStrategy:
    stage, rule_applied = classify_stage(context)
    strategy = _RULE_BUILDERS[rule_applied](context, stage)
    strategy.conversation_mode = _CONVERSATION_MODE_BY_RULE.get(rule_applied)
    return _apply_resistance_softening(strategy, context.resistance_risk)


def _apply_resistance_softening(strategy: ConversationStrategy, resistance: str) -> ConversationStrategy:
    """Rule 10 — high resistance-risk leads get shorter, softer, lower-
    pressure treatment regardless of which scenario rule matched."""
    if resistance == 'high':
        strategy.recommended_tone = f'{strategy.recommended_tone} — keep it short and give an easy out'
        strategy.do_not = _HIGH_RESISTANCE_DO_NOT + strategy.do_not
        strategy.move_toward_next_step = False
        if strategy.recommended_action == 'call_now':
            strategy.recommended_action = 'send_soft_email'
            strategy.call_now = False
    return strategy
