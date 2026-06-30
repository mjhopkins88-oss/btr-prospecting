#!/usr/bin/env python
"""
Unit-style tests for the Multifamily Lead Score engine — Phase 2.

Covers: inbound-intent priority weighting, the Call Today / Hot quality
gates (including the permit/news-only Call Today block and the
inbound-intent / known-renewal-timing / very-strong-trigger Hot gate),
reason codes, and disqualifier codes.

Plain assert-based script (matches the repo's existing test_*.py
convention) — no pytest dependency required.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.scoring.multifamily_score_rules import CONFIDENCE_THRESHOLD

_FAILURES = []


def check(name, condition):
    if condition:
        print(f'  PASS  {name}')
    else:
        print(f'  FAIL  {name}')
        _FAILURES.append(name)


def _lead(signals, **overrides):
    company = MultifamilyCompany(
        id=new_id(), name='Test Co', is_owner_operator_developer=True,
        portfolio_property_count=3, decision_maker_role='VP',
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Test Prop', city='Austin', state='TX',
        unit_count=150, asset_type='garden', cat_exposed=True, company_id=company.id,
    )
    defaults = dict(
        id=new_id(), company=company, property=prop, signals=signals,
        state='TX', city='Austin', source_url='https://example.com/x', confidence=0.8,
    )
    defaults.update(overrides)
    return MultifamilyLead(**defaults)


def _signal(signal_type, source='form', **detail):
    return MultifamilySignal(id=new_id(), signal_type=signal_type, source=source, detail=detail)


def _max_support(**extra):
    """Maximal fit/pain/relationship support a lead can have, so tests
    isolate the inbound/timing component being exercised."""
    return dict(
        pain_flags=['premium_increase', 'deductible_concern'],
        relationship_flags=['prior_reply', 'existing_client_or_referral'],
        **extra,
    )


def test_inbound_priority_ordering():
    # Requirement #1: benchmark form / quote / meeting / calculator / guide
    # download / repeat visit / paid click / known renewal date are the
    # highest-priority signals, in that order. (Source doesn't affect
    # inbound_intent, so every fixture below just uses 'website'.)
    single_signal_totals = {}
    for signal_type in (
        'benchmark_form_submit', 'quote_request', 'meeting_request', 'calculator_submit',
        'guide_download', 'repeat_website_visit', 'paid_search_click', 'website_visit',
    ):
        lead = _lead([_signal(signal_type, 'website')], primary_signal_type=signal_type, primary_source='website')
        single_signal_totals[signal_type] = score_lead(lead).inbound_intent

    check('Benchmark form / quote / meeting outrank calculator',
          single_signal_totals['benchmark_form_submit'] == single_signal_totals['quote_request'] == single_signal_totals['meeting_request'] > single_signal_totals['calculator_submit'])
    check('Calculator outranks guide download',
          single_signal_totals['calculator_submit'] > single_signal_totals['guide_download'])
    check('Guide download outranks repeat website visit',
          single_signal_totals['guide_download'] > single_signal_totals['repeat_website_visit'])
    check('Repeat website visit outranks paid search click',
          single_signal_totals['repeat_website_visit'] > single_signal_totals['paid_search_click'])
    check('Paid search click outranks a single website visit',
          single_signal_totals['paid_search_click'] > single_signal_totals['website_visit'])

    renewal_within = score_lead(_lead([_signal('renewal_date_known', 'crm', days_until_renewal=30)],
                                       primary_signal_type='renewal_date_known', primary_source='crm')).insurance_timing
    check('Known renewal within 120 days is a top-tier timing signal (25 pts)', renewal_within == 25)


def test_call_today_requires_direct_action():
    # A lead with strong inbound (LinkedIn lead form — NOT a Call Today gate
    # signal) + renewal timing + max support clears the 90+ raw band, but
    # must still be downgraded to Hot since there's no benchmark form,
    # meeting request, calculator submission, or quote request.
    lead = _lead(
        [_signal('linkedin_lead_form_submit', 'linkedin_lead_form'),
         _signal('renewal_date_known', 'crm', days_until_renewal=30)],
        primary_signal_type='linkedin_lead_form_submit', primary_source='linkedin_lead_form',
        **_max_support(),
    )
    score = score_lead(lead)
    check('Raw total reaches the Call Today band before gating', score.total >= 90)
    check('No Call Today without a direct form/meeting/calculator/quote signal', score.category == 'hot')
    check('GATE_CALL_TODAY_REQUIRES_DIRECT_ACTION reason code recorded', 'GATE_CALL_TODAY_REQUIRES_DIRECT_ACTION' in score.reason_codes)

    # The direct-action path (quote_request) reaches Call Today cleanly.
    lead2 = _lead(
        [_signal('quote_request', 'form'), _signal('renewal_date_known', 'crm', days_until_renewal=30)],
        primary_signal_type='quote_request', primary_source='form', **_max_support(),
    )
    score2 = score_lead(lead2)
    check('Call Today reachable with quote_request + renewal_within_120 + strong fit', score2.category == 'call_today')


def test_permit_news_only_blocked_from_call_today():
    # Defensive rule (requirement #2): even in the contrived case where a
    # permit/news-only lead somehow carries a direct-action signal type,
    # it must still never be Call Today.
    lead = _lead(
        [_signal('quote_request', 'permit'), _signal('renewal_date_known', 'permit', days_until_renewal=30)],
        primary_signal_type='quote_request', primary_source='permit', **_max_support(),
    )
    score = score_lead(lead)
    check('Raw total reaches the Call Today band before gating', score.total >= 90)
    check('Permit-only lead is never Call Today even with a direct-action signal', score.category != 'call_today')
    check('GATE_CALL_TODAY_PERMIT_NEWS_ONLY reason code recorded', 'GATE_CALL_TODAY_PERMIT_NEWS_ONLY' in score.reason_codes)

    # Realistic maximal permit-only and news-only leads (no inbound intent,
    # best-case fit/pain/relationship) never reach Call Today, and — given
    # the 18-point cap on non-renewal timing signals — never mathematically
    # clear the Hot threshold (75) either.
    for source, signal_type in (('permit', 'permit_filed'), ('permit', 'vertical_construction'), ('news', 'acquisition')):
        lead = _lead([_signal(signal_type, source)], primary_signal_type=signal_type, primary_source=source, **_max_support())
        score = score_lead(lead)
        check(f'Maximal {source}-only {signal_type} lead is never Call Today', score.category != 'call_today')
        check(f'Maximal {source}-only {signal_type} lead does not reach Hot under current point caps', score.category != 'hot')


def test_hot_requires_qualifying_signal():
    # No inbound intent, no renewal timing, no very-strong trigger (just a
    # weak permit_filed signal) — even with max support, this never reaches
    # the Hot/Call Today raw band, so the gate is moot but the category must
    # still never be hot/call_today.
    lead = _lead([_signal('permit_filed', 'permit')], primary_signal_type='permit_filed',
                 primary_source='permit', **_max_support())
    score = score_lead(lead)
    check('No Hot/Call Today without inbound intent, renewal timing, or a very strong trigger', score.category not in ('hot', 'call_today'))

    # Inbound intent alone (quote_request, no timing at all) reaches Hot.
    lead = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request',
                 primary_source='form', **_max_support())
    score = score_lead(lead)
    check('Inbound-intent-only lead reaches Hot', score.category in ('hot', 'call_today'))
    check('Inbound-intent-only lead is flagged MISSING_TIMING', 'MISSING_TIMING' in score.disqualifier_codes)


def test_missing_source_disqualifies():
    lead = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source=None)
    score = score_lead(lead)
    check('Missing source type disqualifies the lead', score.disqualified and score.category == 'watchlist')
    check('disqualifier_codes records MISSING_SOURCE', score.disqualifier_codes == ['MISSING_SOURCE'])


def test_source_url_penalty():
    base_signals = [_signal('quote_request', 'form')]
    with_url = score_lead(_lead(base_signals, primary_signal_type='quote_request', primary_source='form', source_url='https://example.com/x'))
    without_url_form = score_lead(_lead(base_signals, primary_signal_type='quote_request', primary_source='form', source_url=None))
    check('Missing source URL is NOT penalized for a direct form submission', with_url.total == without_url_form.total)

    non_form_signals = [_signal('paid_search_click', 'google_ads')]
    with_url2 = score_lead(_lead(non_form_signals, primary_signal_type='paid_search_click', primary_source='google_ads', source_url='https://example.com/x'))
    without_url2 = score_lead(_lead(non_form_signals, primary_signal_type='paid_search_click', primary_source='google_ads', source_url=None))
    check('Missing source URL IS penalized for a non-form signal', without_url2.total < with_url2.total)


def test_asset_type_and_state_penalties():
    known_asset = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form')
    unknown_asset = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form')
    unknown_asset.property.asset_type = None
    check('Unknown asset type reduces score', score_lead(unknown_asset).total < score_lead(known_asset).total)
    check('Unknown asset type flagged UNKNOWN_ASSET_TYPE', 'UNKNOWN_ASSET_TYPE' in score_lead(unknown_asset).disqualifier_codes)

    known_state = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form')
    unknown_state = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form', state=None)
    unknown_state.property.state = None
    check('Unknown/unsupported state reduces score', score_lead(unknown_state).total < score_lead(known_state).total)
    check('Unknown state flagged MISSING_STATE', 'MISSING_STATE' in score_lead(unknown_state).disqualifier_codes)


def test_low_confidence_caps_at_nurture():
    # Even a strong inbound lead is capped at Nurture if confidence is low.
    lead = _lead(
        [_signal('quote_request', 'form'), _signal('renewal_date_known', 'crm', days_until_renewal=10)],
        primary_signal_type='quote_request', primary_source='form',
        confidence=CONFIDENCE_THRESHOLD - 0.05, **_max_support(),
    )
    score = score_lead(lead)
    check('Low-confidence lead would otherwise reach Call Today', score.total >= 90)
    check('Low-confidence lead is capped at Nurture', score.category == 'nurture')
    check('LOW_CONFIDENCE disqualifier code present', 'LOW_CONFIDENCE' in score.disqualifier_codes)
    check('GATE_QUALITY_CAP_LOW_CONFIDENCE_OR_MISSING_STATE reason code recorded',
          'GATE_QUALITY_CAP_LOW_CONFIDENCE_OR_MISSING_STATE' in score.reason_codes)


def test_reason_codes_present():
    lead = _lead(
        [_signal('benchmark_form_submit', 'form'), _signal('renewal_date_known', 'crm', days_until_renewal=20)],
        primary_signal_type='benchmark_form_submit', primary_source='form',
        pain_flags=['premium_increase'], relationship_flags=['prior_reply'],
    )
    score = score_lead(lead)
    check('reason_codes includes INBOUND_BENCHMARK_FORM_SUBMIT', 'INBOUND_BENCHMARK_FORM_SUBMIT' in score.reason_codes)
    check('reason_codes includes TIMING_RENEWAL_WITHIN_120', 'TIMING_RENEWAL_WITHIN_120' in score.reason_codes)
    check('reason_codes includes PAIN_PREMIUM_INCREASE', 'PAIN_PREMIUM_INCREASE' in score.reason_codes)
    check('reason_codes includes RELATIONSHIP_PRIOR_REPLY', 'RELATIONSHIP_PRIOR_REPLY' in score.reason_codes)
    check('reasons and reason_codes are the same length (1:1 pairing)', len(score.reasons) == len(score.reason_codes))


def test_no_inbound_and_no_timing_disqualifier_codes():
    # A bare account-fit-only lead (no inbound, no timing signal) should
    # surface both quality flags.
    lead = _lead([], primary_signal_type=None, primary_source='manual')
    score = score_lead(lead)
    check('No-signal lead flagged NO_INBOUND_SIGNAL', 'NO_INBOUND_SIGNAL' in score.disqualifier_codes)
    check('No-signal lead flagged MISSING_TIMING', 'MISSING_TIMING' in score.disqualifier_codes)


def main():
    test_inbound_priority_ordering()
    test_call_today_requires_direct_action()
    test_permit_news_only_blocked_from_call_today()
    test_hot_requires_qualifying_signal()
    test_missing_source_disqualifies()
    test_source_url_penalty()
    test_asset_type_and_state_penalties()
    test_low_confidence_caps_at_nurture()
    test_reason_codes_present()
    test_no_inbound_and_no_timing_disqualifier_codes()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All scoring tests passed.')


if __name__ == '__main__':
    main()
