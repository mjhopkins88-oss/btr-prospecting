#!/usr/bin/env python
"""
Tests for Source Performance aggregation (multifamily/repository.py,
Part 8). Inserts a few real leads via the intake path, checks the
aggregates, and confirms rejected spam is excluded from operational
breakdowns. Cleans up after itself.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake import build_lead_from_intake

_FAILURES = []
_MARKER = '(SRCPERF TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, utm_source=None, utm_campaign=None, offer=None, landing=None, spam_status='clean'):
    payload = {
        'name': 'Tester', 'company': f'{company} {_MARKER}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
        'sourcePage': 'Multifamily Insurance Benchmark Review',
        'utmSource': utm_source, 'utmCampaign': utm_campaign, 'offerType': offer, 'landingPage': landing,
    }
    lead, errors = build_lead_from_intake(payload, spam_status=spam_status, spam_reason_codes=(['X'] if spam_status != 'clean' else []))
    assert not errors, errors
    repository.insert_lead(lead)
    _ids.append(lead.id)
    return lead


def main():
    try:
        _make('Alpha', utm_source='google', utm_campaign='q3', offer='benchmark_review', landing='https://x.com/lp1')
        _make('Beta', utm_source='google', utm_campaign='q3', offer='benchmark_review', landing='https://x.com/lp1')
        _make('Gamma', utm_source='linkedin', utm_campaign='fall', offer='guide', landing='https://x.com/lp2')
        _make('Delta')  # no attribution at all
        _make('Junk', utm_source='google', spam_status='rejected')  # rejected spam — excluded from ops

        perf = repository.get_source_performance()

        check('total_real_leads counts non-rejected leads (>=4)', perf['total_real_leads'] >= 4)
        check('leads_by_source aggregates utm_source (google present)', perf['leads_by_source'].get('google', 0) >= 2)
        check('leads_by_source has linkedin', perf['leads_by_source'].get('linkedin', 0) >= 1)
        check('rejected spam excluded from leads_by_source (google == 2, not 3)', perf['leads_by_source'].get('google') == 2)
        check('leads_by_source_page aggregates the benchmark page', any('Benchmark' in k for k in perf['leads_by_source_page']))
        check('leads_by_offer_type has benchmark_review', perf['leads_by_offer_type'].get('benchmark_review', 0) >= 2)
        check('leads_by_campaign has q3', perf['leads_by_campaign'].get('q3', 0) >= 2)
        check('by_source_category is populated', isinstance(perf['by_source_category'], dict) and len(perf['by_source_category']) > 0)
        check('best_landing_page is the most-used landing page (lp1)', perf['best_landing_page'] and perf['best_landing_page']['landing_page'] == 'https://x.com/lp1')
        check('leads_missing_attribution counts the unattributed lead (>=1)', perf['leads_missing_attribution'] >= 1)
        check('spam_rate_by_source includes google with a flagged count', perf['spam_rate_by_source'].get('google', {}).get('flagged', 0) >= 1)
    finally:
        for lid in _ids:
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All source-performance tests passed.')


if __name__ == '__main__':
    main()
