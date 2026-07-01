#!/usr/bin/env python
"""
Phase C tests: source-attribution history + signal-based source view.

Confirms first/latest/conversion derivation, the UTM/landing/referrer
path persists across touches, and source performance exposes signal
counts. Inserts test rows tagged with a marker and cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake import build_lead_from_intake

_FAILURES = []
_M = '(ATTR TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, **over):
    payload = {
        'name': 'Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
        'sourcePage': 'Benchmark',
    }
    payload.update(over)
    lead, errors = build_lead_from_intake(payload, spam_status='clean', spam_reason_codes=[])
    assert not errors, errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    _ids.append(lead.id)
    return lead


def main():
    try:
        lead = _make('Attrflow', utmSource='google', utmMedium='cpc', utmCampaign='spring', landingPage='https://x.com/lp1', referrer='https://google.com')
        # first touch
        repository.record_lead_attribution_touch(lead, touch_type='first')

        # a later non-form touch (e.g. a website re-visit) with different UTM
        repository.record_attribution(lead.id, 'touch', source='website', utm_source='newsletter',
                                      utm_campaign='june', landing_page='https://x.com/lp2', referrer='https://news.example.com',
                                      occurred_at='2099-01-01T00:00:00')

        summ = repository.get_attribution_summary(lead.id)
        check('first_touch source is the form', summ['first_touch']['source'] == 'benchmark_form')
        check('first_touch utm_source is google', summ['first_touch']['utm_source'] == 'google')
        check('latest_touch is the later website touch', summ['latest_touch']['source'] == 'website')
        check('conversion_source is the form submission', summ['conversion_source'] == 'benchmark_form')
        check('utm_history has both touches', len(summ['utm_history']) == 2)
        check('landing_page_history captured both pages', summ['landing_page_history'] == ['https://x.com/lp1', 'https://x.com/lp2'])
        check('referrer_history captured both referrers', len(summ['referrer_history']) == 2)

        # signal-based source view in source performance
        perf = repository.get_source_performance()
        check('source performance exposes total_signals', 'total_signals' in perf and perf['total_signals'] >= 1)
        check('signals_by_source includes benchmark_form', perf['signals_by_source'].get('benchmark_form', 0) >= 1)
        check('signals_by_type includes benchmark_form_submit', perf['signals_by_type'].get('benchmark_form_submit', 0) >= 1)

        # empty-lead summary shape
        empty = repository.get_attribution_summary('no-such-lead-xyz')
        check('summary for an unknown lead is well-formed', empty['first_touch'] is None and empty['touches'] == [])
    finally:
        for lid in _ids:
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All attribution/signal-view (Phase C) tests passed.')


if __name__ == '__main__':
    main()
