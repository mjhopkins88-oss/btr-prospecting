"""
Conversation Strategy Engine — decides HOW to approach a lead, before any
copy is generated. Implements the 14 strategy rules from the Multifamily
Sales Intelligence brief as an ordered rule chain (first match wins);
every strategy carries the rule_applied name for the reasoning explainer.

Universal guardrails (always applied, regardless of which rule matched):
  - never claim savings percentages
  - never present the full program before situation/problem context exists
  - lead with questions, not conclusions
"""
from typing import List

from multifamily.sales_intelligence.nepq_types import SalesLeadContext, ConversationStrategy

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


def _base(**kwargs) -> ConversationStrategy:
    do_not = list(_UNIVERSAL_DO_NOT)
    extra_do_not = kwargs.pop('extra_do_not', None) or []
    do_not = extra_do_not + do_not
    return ConversationStrategy(do_not=do_not, **kwargs)


def select_strategy(context: SalesLeadContext) -> ConversationStrategy:
    origin = context.lead_origin
    scenario = context.insurance_scenario
    temperature = context.lead_temperature
    resistance = context.resistance_risk

    is_direct_inbound = origin in ('benchmark_request', 'inbound_form', 'linkedin_lead_form') and (
        'quote_request' in context.signal_types or 'meeting_request' in context.signal_types
        or 'benchmark_form_submit' in context.signal_types or 'linkedin_lead_form_submit' in context.signal_types
    )

    # Rule 8 — permit/news trigger-only leads: soft relevance check, never a pitch.
    if origin in ('permit_trigger', 'news_trigger'):
        strategy = _base(
            starting_nepq_stage='connection',
            primary_objective="check whether insurance/coverage is even on their radar at this stage — no assumptions",
            recommended_tone='soft, low-pressure, curious',
            recommended_action='nurture',
            ask_first="whether this project/event has reached the point where insurance is something they're thinking about yet",
            should_present=False, call_now=False, ask_for_information=True,
            challenge_assumptions_carefully=False, move_toward_next_step=False,
            extra_do_not=_TRIGGER_ONLY_DO_NOT,
            rule_applied='rule_8_permit_news_soft_relevance_check',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 3 — renewal within 120 days (or renewal-window process stage).
    if scenario == 'renewal_pressure' or context.process_stage in ('renewal_window', 'post_renewal'):
        strategy = _base(
            starting_nepq_stage='situation',
            primary_objective='understand renewal timeline, market-testing status, incumbent broker process, premium/deductible movement, and any lender/NOI pressure',
            recommended_tone='neutral, calm, curious',
            recommended_action=('call_now' if temperature in ('call_today', 'hot') else 'ask_for_renewal_timing'),
            ask_first='where they are in the renewal process and whether the market has already been tested this cycle',
            should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
            challenge_assumptions_carefully=True, move_toward_next_step=(temperature in ('call_today', 'hot')),
            rule_applied='rule_3_renewal_within_120',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 4 — acquisition / due diligence.
    if scenario == 'acquisition_due_diligence':
        strategy = _base(
            starting_nepq_stage='situation',
            primary_objective='understand whether they are underwriting off seller-provided insurance numbers or independently validating property/GL/excess/deductible assumptions before close',
            recommended_tone='neutral, consultative',
            recommended_action='ask_for_current_program_details',
            ask_first='whether the insurance assumptions in the deal are being independently pressure-tested or taken from the seller as-is',
            should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
            challenge_assumptions_carefully=True, move_toward_next_step=(temperature == 'call_today'),
            rule_applied='rule_4_acquisition_diligence',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 5 — refinance / lender. Covers both the refinance_or_financing
    # scenario and a bare lender_requirement pain flag (a lender issue on
    # its own is squarely this rule's domain per the brief).
    if scenario in ('refinance_or_financing', 'lender_requirement'):
        strategy = _base(
            starting_nepq_stage='situation',
            primary_objective='understand which lender insurance conditions are still open — property, GL, excess, deductibles, exclusions, escrow, carrier rating',
            recommended_tone='neutral, precise',
            recommended_action='ask_for_current_program_details',
            ask_first='whether the lender insurance requirements are already cleared or if items are still open',
            should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
            challenge_assumptions_carefully=False, move_toward_next_step=(temperature == 'call_today'),
            rule_applied='rule_5_refinance_lender',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 6 — construction / builder's risk.
    if scenario == 'builders_risk' or context.process_stage in ('construction_loan_closing', 'construction_start', 'entitlement_or_permit'):
        strategy = _base(
            starting_nepq_stage='situation',
            primary_objective="find out whether builder's risk is already placed and locked in, or still a moving piece",
            recommended_tone='neutral, practical',
            recommended_action='ask_for_current_program_details',
            ask_first="whether builder's risk has already been bound or is still open",
            should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
            challenge_assumptions_carefully=False, move_toward_next_step=(temperature == 'call_today'),
            rule_applied='rule_6_construction_builders_risk',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 7 — completion / lease-up.
    if scenario == 'completion_or_lease_up':
        strategy = _base(
            starting_nepq_stage='situation',
            primary_objective="understand where they are in the transition from builder's risk to operating property/GL as units come online",
            recommended_tone='neutral, forward-looking',
            recommended_action='ask_for_current_program_details',
            ask_first="whether the transition off builder's risk has already been mapped out",
            should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
            challenge_assumptions_carefully=False, move_toward_next_step=(temperature == 'call_today'),
            rule_applied='rule_7_completion_lease_up',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 2 — website intent / repeat visits (soft curiosity, no direct scenario yet).
    if origin == 'website_intent' or context.buyer_awareness_level == 'unaware':
        strategy = _base(
            starting_nepq_stage='connection',
            primary_objective='use soft curiosity to find out what (if anything) prompted the interest — do not assume a problem',
            recommended_tone='soft, curious, no pressure',
            recommended_action='send_soft_email',
            ask_first='which bucket (if any) is closest to what brought them to look — renewal, acquisition, lender requirement, or deductible concern',
            should_present=False, call_now=False, ask_for_information=True,
            challenge_assumptions_carefully=False, move_toward_next_step=False,
            rule_applied='rule_2_website_intent_soft_curiosity',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 1 / 11 — inbound benchmark/quote/meeting request or other direct inbound ask.
    if is_direct_inbound or scenario == 'just_benchmarking':
        strategy = _base(
            starting_nepq_stage='connection',
            primary_objective='acknowledge the request, then move quickly into situation and problem-awareness before assuming what they need',
            recommended_tone='neutral, warm, question-led',
            recommended_action=('call_now' if temperature in ('call_today', 'hot') else 'schedule_benchmark_call'),
            ask_first='what prompted them to reach out now',
            should_present=False, call_now=(temperature in ('call_today', 'hot')), ask_for_information=True,
            challenge_assumptions_carefully=False, move_toward_next_step=True,
            rule_applied='rule_1_11_direct_inbound',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Rule 9 — nurture/watchlist fallback: reached only when no specific
    # scenario/origin rule above matched (i.e. there's genuinely no active
    # discovery thread yet, not just a low raw score on an otherwise
    # identifiable scenario — those are handled by rules 3-7 regardless of
    # temperature, softened only via recommended_action/tone).
    if temperature in ('nurture', 'watchlist'):
        strategy = _base(
            starting_nepq_stage='nurture',
            primary_objective='stay visible, ask permission to revisit at a better time — no pitch',
            recommended_tone='very low pressure, patient',
            recommended_action='nurture',
            ask_first='whether it would be worth reconnecting closer to a more relevant time (renewal, acquisition, next project)',
            should_present=False, call_now=False, ask_for_information=False,
            challenge_assumptions_carefully=False, move_toward_next_step=False,
            extra_do_not=_NURTURE_DO_NOT,
            rule_applied='rule_9_nurture_watchlist_no_pitch',
        )
        return _apply_resistance_softening(strategy, resistance)

    # Default fallback — unknown scenario, general watchlist-style caution.
    strategy = _base(
        starting_nepq_stage='connection',
        primary_objective='establish relevance before asking anything specific',
        recommended_tone='neutral, low-key',
        recommended_action='ask_for_context',
        ask_first='whether multifamily insurance is even something on their plate right now',
        should_present=False, call_now=False, ask_for_information=True,
        challenge_assumptions_carefully=False, move_toward_next_step=False,
        rule_applied='rule_default_unknown_scenario',
    )
    return _apply_resistance_softening(strategy, resistance)


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
