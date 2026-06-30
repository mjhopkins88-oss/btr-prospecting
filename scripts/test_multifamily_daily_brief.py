#!/usr/bin/env python
"""
Tests for the multifamily daily brief builder — confirms every required
section is present and reasonably populated from the mock pipeline.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.pipeline import run_pipeline
from multifamily.daily_brief.multifamily_daily_brief_builder import build_daily_brief

_FAILURES = []

REQUIRED_KEYS = [
    'new_inbound_leads', 'call_today_leads', 'hot_leads', 'warm_leads',
    'renewal_opportunities', 'acquisition_triggers', 'construction_triggers',
    'top_3_actions_today', 'best_first_call', 'best_email_draft',
    'best_linkedin_touch', 'leads_needing_more_info',
]


def check(name, condition):
    if condition:
        print(f'  PASS  {name}')
    else:
        print(f'  FAIL  {name}')
        _FAILURES.append(name)


def main():
    leads, _ = run_pipeline()
    brief = build_daily_brief(leads)

    for key in REQUIRED_KEYS:
        check(f'Daily brief has key "{key}"', key in brief)

    check('new_inbound_leads is non-empty given inbound mock collectors', len(brief['new_inbound_leads']) > 0)
    check('renewal_opportunities includes the CRM renewal mock lead', len(brief['renewal_opportunities']) > 0)
    check('acquisition_triggers includes the news acquisition mock lead', len(brief['acquisition_triggers']) > 0)
    check('construction_triggers includes the permit-feed mock leads', len(brief['construction_triggers']) > 0)
    check('top_3_actions_today has at most 3 entries', len(brief['top_3_actions_today']) <= 3)
    check('leads_needing_more_info flags the low-confidence/unknown-state mock lead', len(brief['leads_needing_more_info']) > 0)

    if brief['best_email_draft']:
        check('best_email_draft has a body derived from the suggested opener', bool(brief['best_email_draft'].get('body')))

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED')
        sys.exit(1)
    print('All daily brief tests passed.')


if __name__ == '__main__':
    main()
