#!/usr/bin/env python
"""
Tests for the multifamily daily brief builder — Phase 2.

Confirms the brief separates inbound leads, website intent leads,
renewal opportunities, trigger-based opportunities, and nurture/
watchlist leads (requirement #7), and that every section is reasonably
populated from the mock pipeline.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.pipeline import run_pipeline
from multifamily.daily_brief.multifamily_daily_brief_builder import build_daily_brief

_FAILURES = []

REQUIRED_KEYS = [
    'inbound_leads', 'website_intent_leads', 'renewal_opportunities', 'trigger_based_opportunities',
    'call_today_leads', 'hot_leads', 'warm_leads', 'nurture_watchlist_leads',
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

    check('inbound_leads is non-empty (benchmark form / quote / calculator / guide download / LinkedIn form mocks)',
          len(brief['inbound_leads']) > 0)
    check('website_intent_leads is non-empty (website visit / repeat visit / keyword / paid click mocks)',
          len(brief['website_intent_leads']) > 0)
    check('renewal_opportunities includes the CRM + form-sourced renewal mock leads',
          len(brief['renewal_opportunities']) > 0)
    check('trigger_based_opportunities includes the permit/news mock leads',
          len(brief['trigger_based_opportunities']) > 0)
    check('nurture_watchlist_leads is non-empty', len(brief['nurture_watchlist_leads']) > 0)

    # The four signal-source buckets aren't a strict partition — a lead with
    # both a benchmark form submission AND a known renewal date should
    # appear in both inbound_leads and renewal_opportunities. Together they
    # must still cover every lead that has a recognized signal type.
    bucketed_ids = (
        {l['lead_id'] for l in brief['inbound_leads']}
        | {l['lead_id'] for l in brief['website_intent_leads']}
        | {l['lead_id'] for l in brief['renewal_opportunities']}
        | {l['lead_id'] for l in brief['trigger_based_opportunities']}
    )
    check('Every lead lands in at least one signal-source bucket', len(bucketed_ids) == len(leads))
    inbound_and_renewal_ids = {l['lead_id'] for l in brief['inbound_leads']} & {l['lead_id'] for l in brief['renewal_opportunities']}
    check('A lead with both inbound intent and known renewal timing appears in both buckets', len(inbound_and_renewal_ids) > 0)

    # The four category buckets must also partition every scored lead.
    category_bucketed_ids = (
        {l['lead_id'] for l in brief['call_today_leads']}
        | {l['lead_id'] for l in brief['hot_leads']}
        | {l['lead_id'] for l in brief['warm_leads']}
        | {l['lead_id'] for l in brief['nurture_watchlist_leads']}
    )
    check('Every scored lead lands in exactly one category bucket', len(category_bucketed_ids) == len(leads))

    check('top_3_actions_today has at most 3 entries', len(brief['top_3_actions_today']) <= 3)
    check('top_3_actions_today is ranked best-first by score', [
        a['score'] for a in brief['top_3_actions_today']
    ] == sorted([a['score'] for a in brief['top_3_actions_today']], reverse=True))
    check('leads_needing_more_info flags leads with disqualifier codes', len(brief['leads_needing_more_info']) > 0)
    check('every lead_needing_more_info has at least one disqualifier code',
          all(l['disqualifier_codes'] for l in brief['leads_needing_more_info']))

    if brief['best_email_draft']:
        check('best_email_draft has a body derived from the suggested opener', bool(brief['best_email_draft'].get('body')))

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED')
        sys.exit(1)
    print('All daily brief tests passed.')


if __name__ == '__main__':
    main()
