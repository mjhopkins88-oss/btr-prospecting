#!/usr/bin/env python
"""
SERP Phase E tests: sales-intelligence tuning for SERP-sourced leads.

Covers the two rules from the approved plan (resistance_risk='high' by
default for SERP; conversation_mode is never inbound_response for a
SERP-only lead) plus the category-specific NEPQ rule routing this
already gets "for free" once 'serp' is a recognized source with the
right signal types (acquisition/financing/groundbreaking/completion, or
the two zero-weight insurance_market_pressure/market_mention types) —
confirming the whole chain (types -> intake_trigger -> lead_context ->
conversation_strategy_engine) produces the exact NEPQ guidance the plan
calls for, per category. Never touches scoring math or the network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.intake_trigger import build_lead_from_trigger
from multifamily.sales_intelligence.lead_context_builder import build_lead_context
from multifamily.sales_intelligence.conversation_strategy_engine import select_strategy
from multifamily.sales_intelligence.engine import build_sales_intelligence
from multifamily.timing.process_stage_detector import detect_process_stage

_FAILURES = []
_M = '(SERPSI TEST)'


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _serp_lead(company, signal_type, confidence=0.6, property_name=None):
    payload = {
        'company': f'{company} {_M}', 'state': 'TX', 'city': 'Austin',
        'source': 'serp', 'signalType': signal_type, 'sourceUrl': 'https://example.com/x',
        'confidence': confidence,
    }
    if property_name:
        payload['propertyName'] = property_name
    lead, errors = build_lead_from_trigger(payload)
    assert not errors, errors
    return lead


def test_serp_lead_is_always_high_resistance():
    for signal_type in ('acquisition', 'financing', 'groundbreaking', 'completion',
                         'insurance_market_pressure', 'market_mention'):
        lead = _serp_lead(f'Resist {signal_type}', signal_type)
        context = build_lead_context(lead, detect_process_stage(lead))
        check(f'{signal_type}: SERP lead defaults to high resistance risk', context.resistance_risk == 'high')


def test_serp_lead_never_reaches_inbound_response_mode():
    for signal_type in ('acquisition', 'financing', 'groundbreaking', 'completion',
                         'insurance_market_pressure', 'market_mention'):
        lead = _serp_lead(f'NeverInbound {signal_type}', signal_type)
        context = build_lead_context(lead, detect_process_stage(lead))
        strategy = select_strategy(context)
        check(f'{signal_type}: conversation_mode is never inbound_response',
              strategy.conversation_mode != 'inbound_response')
        check(f'{signal_type}: rule_applied is never the direct-inbound rule',
              strategy.rule_applied != 'rule_1_11_direct_inbound')


def test_serp_lead_never_reaches_call_now():
    for signal_type in ('acquisition', 'financing', 'groundbreaking', 'completion'):
        lead = _serp_lead(f'NeverCallNow {signal_type}', signal_type, confidence=0.9)
        context = build_lead_context(lead, detect_process_stage(lead))
        strategy = select_strategy(context)
        check(f'{signal_type}: high-resistance softening keeps SERP-only leads off call_now',
              strategy.recommended_action != 'call_now' and strategy.call_now is False)


def test_serp_acquisition_gets_underwriting_strategy():
    lead = _serp_lead('AcqRoute Partners', 'acquisition')
    context = build_lead_context(lead, detect_process_stage(lead))
    strategy = select_strategy(context)
    check('SERP acquisition lead routes to rule_4 (acquisition due-diligence)',
          strategy.rule_applied == 'rule_4_acquisition_diligence')
    check('SERP acquisition lead starts at situation stage', strategy.starting_nepq_stage == 'situation')
    check('SERP acquisition lead gets acquisition_discovery conversation_mode',
          strategy.conversation_mode == 'acquisition_discovery')


def test_serp_financing_gets_lender_compliance_strategy():
    lead = _serp_lead('FinRoute Holdings', 'financing')
    context = build_lead_context(lead, detect_process_stage(lead))
    strategy = select_strategy(context)
    check('SERP financing lead routes to rule_5 (refinance/lender)', strategy.rule_applied == 'rule_5_refinance_lender')
    check('SERP financing lead asks the lender-requirements action',
          strategy.recommended_action == 'ask_for_lender_requirements')
    check('SERP financing lead gets lender_compliance_discovery conversation_mode',
          strategy.conversation_mode == 'lender_compliance_discovery')


def test_serp_construction_gets_builders_risk_strategy():
    lead = _serp_lead('ConstructRoute LLC', 'groundbreaking')
    context = build_lead_context(lead, detect_process_stage(lead))
    strategy = select_strategy(context)
    check('SERP construction lead routes to rule_6 (construction/builders risk)',
          strategy.rule_applied == 'rule_6_construction_builders_risk')
    check('SERP construction lead gets construction_discovery conversation_mode',
          strategy.conversation_mode == 'construction_discovery')


def test_serp_completion_gets_transition_strategy():
    lead = _serp_lead('CompleteRoute Group', 'completion')
    context = build_lead_context(lead, detect_process_stage(lead))
    strategy = select_strategy(context)
    check('SERP completion lead routes to rule_7 (completion/lease-up)',
          strategy.rule_applied == 'rule_7_completion_lease_up')
    check('SERP completion lead gets completion_transition_discovery conversation_mode',
          strategy.conversation_mode == 'completion_transition_discovery')


def test_serp_insurance_pressure_and_general_get_soft_curiosity():
    for signal_type in ('insurance_market_pressure', 'market_mention'):
        lead = _serp_lead(f'SoftRoute {signal_type}', signal_type)
        context = build_lead_context(lead, detect_process_stage(lead))
        check(f'{signal_type}: buyer awareness defaults to unaware', context.buyer_awareness_level == 'unaware')
        strategy = select_strategy(context)
        check(f'{signal_type}: routes to rule_2 (soft curiosity), not a hard pitch',
              strategy.rule_applied == 'rule_2_website_intent_soft_curiosity')
        check(f'{signal_type}: recommended action is a soft email, not call_now',
              strategy.recommended_action == 'send_soft_email')


def test_serp_lead_carries_trigger_only_risk_note():
    lead = _serp_lead('RiskNote Partners', 'acquisition')
    context = build_lead_context(lead, detect_process_stage(lead))
    check('SERP lead carries the third-party-trigger-only conversation risk note',
          any('third-party trigger only' in note for note in context.conversation_risk_notes))


def test_full_engine_produces_a_package_for_a_serp_lead():
    lead = _serp_lead('FullEngine Estates', 'acquisition')
    pkg = build_sales_intelligence(lead, log=False)
    check('full engine produces a package for a contactless SERP lead',
          pkg.strategy is not None and pkg.messages is not None and pkg.reasoning is not None)
    check('reasoning mentions resistance/trigger context is captured',
          pkg.context.resistance_risk == 'high')


def main():
    try:
        test_serp_lead_is_always_high_resistance()
        test_serp_lead_never_reaches_inbound_response_mode()
        test_serp_lead_never_reaches_call_now()
        test_serp_acquisition_gets_underwriting_strategy()
        test_serp_financing_gets_lender_compliance_strategy()
        test_serp_construction_gets_builders_risk_strategy()
        test_serp_completion_gets_transition_strategy()
        test_serp_insurance_pressure_and_general_get_soft_curiosity()
        test_serp_lead_carries_trigger_only_risk_note()
        test_full_engine_produces_a_package_for_a_serp_lead()
    finally:
        pass  # no persistence in this script — build_lead_from_trigger + build_sales_intelligence(log=False) never write to the DB

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All SERP sales-intelligence (Phase E) tests passed.')


if __name__ == '__main__':
    main()
