"""
Sales Stage Classifier — decides WHICH of the Multifamily Sales
Intelligence brief's strategy rules applies to a lead, and therefore
which NEPQ stage the conversation should start at. This is the single
source of truth for "which rule matched" (first-match-wins, ordered);
conversation_strategy_engine.py builds the rest of the ConversationStrategy
from whatever this returns — the two never duplicate the decision tree.
"""
from typing import Tuple

from multifamily.sales_intelligence.nepq_types import SalesLeadContext


def classify_stage(context: SalesLeadContext) -> Tuple[str, str]:
    """Returns (starting_nepq_stage, rule_applied)."""
    origin = context.lead_origin
    scenario = context.insurance_scenario

    is_direct_inbound = origin in ('benchmark_request', 'inbound_form', 'linkedin_lead_form') and (
        'quote_request' in context.signal_types or 'meeting_request' in context.signal_types
        or 'benchmark_form_submit' in context.signal_types or 'linkedin_lead_form_submit' in context.signal_types
    )

    # Rule 8 — permit/news trigger-only leads.
    if origin in ('permit_trigger', 'news_trigger'):
        return 'connection', 'rule_8_permit_news_soft_relevance_check'

    # Rule 3 — renewal within 120 days (or renewal-window process stage).
    if scenario == 'renewal_pressure' or context.process_stage in ('renewal_window', 'post_renewal'):
        return 'situation', 'rule_3_renewal_within_120'

    # Rule 4 — acquisition / due diligence.
    if scenario == 'acquisition_due_diligence':
        return 'situation', 'rule_4_acquisition_diligence'

    # Rule 5 — refinance / lender.
    if scenario in ('refinance_or_financing', 'lender_requirement'):
        return 'situation', 'rule_5_refinance_lender'

    # Rule 6 — construction / builder's risk.
    if scenario == 'builders_risk' or context.process_stage in ('construction_loan_closing', 'construction_start', 'entitlement_or_permit'):
        return 'situation', 'rule_6_construction_builders_risk'

    # Rule 7 — completion / lease-up.
    if scenario == 'completion_or_lease_up':
        return 'situation', 'rule_7_completion_lease_up'

    # Rule 2 — website intent / repeat visits (soft curiosity, no scenario yet).
    if origin == 'website_intent' or context.buyer_awareness_level == 'unaware':
        return 'connection', 'rule_2_website_intent_soft_curiosity'

    # Rule 1 / 11 — inbound benchmark/quote/meeting request or other direct inbound ask.
    if is_direct_inbound or scenario == 'just_benchmarking':
        return 'connection', 'rule_1_11_direct_inbound'

    # Rule 9 — nurture/watchlist fallback.
    if context.lead_temperature in ('nurture', 'watchlist'):
        return 'nurture', 'rule_9_nurture_watchlist_no_pitch'

    # Default fallback — unknown scenario.
    return 'connection', 'rule_default_unknown_scenario'
