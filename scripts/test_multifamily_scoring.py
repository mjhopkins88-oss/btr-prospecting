#!/usr/bin/env python
"""
Unit-style tests for the Multifamily Lead Score engine.

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


def main():
    # 1. Maximal lead with a Call Today gate signal + strong timing reaches Call Today.
    lead = _lead(
        [_signal('quote_request', 'form'), _signal('renewal_date_known', 'crm', days_until_renewal=30)],
        primary_signal_type='quote_request', primary_source='form',
        pain_flags=['premium_increase'], relationship_flags=['prior_reply'],
    )
    score = score_lead(lead)
    check('Call Today reachable with quote_request + renewal_within_120 + strong fit', score.category == 'call_today')

    # 2. High raw score but NO call-today gate signal (e.g. only repeat website visit +
    #    acquisition trigger) must NOT reach Call Today even if total >= 90.
    lead = _lead(
        [_signal('repeat_website_visit', 'website'), _signal('acquisition', 'news')],
        primary_signal_type='repeat_website_visit', primary_source='website',
        pain_flags=['premium_increase', 'lender_requirement'], relationship_flags=['prior_reply', 'existing_client_or_referral'],
    )
    score = score_lead(lead)
    check('No Call Today without a form/meeting/calculator/quote signal', score.category != 'call_today')

    # 3. Hot requires inbound intent OR a strong timing trigger — neither present -> not Hot/Call Today.
    lead = _lead(
        [_signal('planning_approval', 'permit')],
        primary_signal_type='planning_approval', primary_source='permit',
        pain_flags=['premium_increase', 'deductible_concern'], relationship_flags=['prior_reply', 'existing_client_or_referral'],
    )
    score = score_lead(lead)
    check('No Hot/Call Today without inbound intent or a strong timing trigger', score.category not in ('hot', 'call_today'))

    # 4. Permit/news-only lead (no inbound intent) is capped at Warm even with a strong trigger.
    lead = _lead(
        [_signal('acquisition', 'news')],
        primary_signal_type='acquisition', primary_source='news',
        pain_flags=['premium_increase', 'lender_requirement'], relationship_flags=['prior_reply', 'existing_client_or_referral'],
    )
    score = score_lead(lead)
    check('Permit/news-only lead capped below Hot', score.category not in ('hot', 'call_today'))

    # 5. Missing source type disqualifies the lead entirely.
    lead = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source=None)
    score = score_lead(lead)
    check('Missing source type disqualifies the lead', score.disqualified and score.category == 'watchlist')

    # 6. Missing source URL reduces score, UNLESS the signal is a direct form submission.
    base_signals = [_signal('quote_request', 'form')]
    with_url = score_lead(_lead(base_signals, primary_signal_type='quote_request', primary_source='form', source_url='https://example.com/x'))
    without_url_form = score_lead(_lead(base_signals, primary_signal_type='quote_request', primary_source='form', source_url=None))
    check('Missing source URL is NOT penalized for a direct form submission', with_url.total == without_url_form.total)

    non_form_signals = [_signal('paid_search_click', 'google_ads')]
    with_url2 = score_lead(_lead(non_form_signals, primary_signal_type='paid_search_click', primary_source='google_ads', source_url='https://example.com/x'))
    without_url2 = score_lead(_lead(non_form_signals, primary_signal_type='paid_search_click', primary_source='google_ads', source_url=None))
    check('Missing source URL IS penalized for a non-form signal', without_url2.total < with_url2.total)

    # 7. Unknown asset type reduces score.
    known_asset = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form')
    unknown_asset = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form')
    unknown_asset.property.asset_type = None
    check('Unknown asset type reduces score', score_lead(unknown_asset).total < score_lead(known_asset).total)

    # 8. Unknown state reduces score.
    known_state = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form')
    unknown_state = _lead([_signal('quote_request', 'form')], primary_signal_type='quote_request', primary_source='form', state=None)
    unknown_state.property.state = None
    check('Unknown/unsupported state reduces score', score_lead(unknown_state).total < score_lead(known_state).total)

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All scoring tests passed.')


if __name__ == '__main__':
    main()
