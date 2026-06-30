#!/usr/bin/env python
"""
Quality/data-integrity tests for the Multifamily Command pipeline:
dedupe behavior and required-field completeness across the mock
collector output.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal,
    SIGNAL_SOURCES, SUPPORTED_STATES, new_id,
)
from multifamily.dedupe import dedupe_leads
from multifamily.pipeline import run_pipeline

_FAILURES = []


def check(name, condition):
    if condition:
        print(f'  PASS  {name}')
    else:
        print(f'  FAIL  {name}')
        _FAILURES.append(name)


def test_dedupe():
    company = MultifamilyCompany(id=new_id(), name='Dup Co')
    prop = MultifamilyProperty(id=new_id(), name='Dup Prop', city='Dallas', state='TX')
    s1 = MultifamilySignal(id=new_id(), signal_type='website_visit', source='website')
    s2 = MultifamilySignal(id=new_id(), signal_type='repeat_website_visit', source='website')

    lead_a = MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[s1],
        state='TX', city='Dallas', primary_signal_type='website_visit', primary_source='website',
    )
    lead_b = MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[s2],
        state='TX', city='Dallas', primary_signal_type='repeat_website_visit', primary_source='website',
    )

    merged = dedupe_leads([lead_a, lead_b])
    check('Duplicate leads (same company+property+city+state+source) are merged', len(merged) == 1)
    check('Merged lead retains signals from both duplicates', len(merged[0].signals) == 2)


def test_pipeline_required_fields():
    leads, source_runs = run_pipeline()

    check('Pipeline collectors all ran without raising (8 collectors)', len(source_runs) == 8)
    check('Pipeline produced at least one lead', len(leads) > 0)

    for lead in leads:
        check(
            f'{lead.company.name}: has a recognized source type',
            lead.primary_source in SIGNAL_SOURCES,
        )
        check(
            f'{lead.company.name}: has a confidence score in [0,1]',
            lead.confidence is not None and 0.0 <= lead.confidence <= 1.0,
        )
        check(
            f'{lead.company.name}: is scored',
            lead.score is not None,
        )
        check(
            f'{lead.company.name}: has a "why warm" reason',
            bool(lead.why_warm),
        )
        check(
            f'{lead.company.name}: has a last_verified_at timestamp',
            bool(lead.last_verified_at),
        )
        check(
            f'{lead.company.name}: score has reason_codes',
            bool(lead.score and lead.score.reason_codes) or bool(lead.score and lead.score.disqualified),
        )
        check(
            f'{lead.company.name}: reasons and reason_codes are 1:1',
            lead.score is not None and len(lead.score.reasons) == len(lead.score.reason_codes),
        )
        if lead.score and not lead.score.disqualified:
            check(
                f'{lead.company.name}: permit/news-only leads never reach Call Today',
                not (
                    lead.primary_source in ('permit', 'news')
                    and lead.score.category == 'call_today'
                ),
            )
        if lead.state:
            check(f'{lead.company.name}: state (if set) is CA or TX', lead.state in SUPPORTED_STATES)

    # At least one lead should demonstrate each disqualifier code given the
    # mock data's deliberately thin/edge-case scenarios (Phase 2 requirement #5).
    all_disqualifier_codes = {
        code for lead in leads if lead.score for code in lead.score.disqualifier_codes
    }
    for expected_code in ('LOW_CONFIDENCE', 'MISSING_STATE', 'UNKNOWN_ASSET_TYPE', 'MISSING_TIMING', 'NO_INBOUND_SIGNAL'):
        check(f'Mock data demonstrates disqualifier code {expected_code}', expected_code in all_disqualifier_codes)

    # The new "stronger" inbound examples (Phase 2 requirement #6) should
    # produce at least one Call Today/Hot lead, and it must be driven by
    # real inbound intent, not a generic trigger.
    call_today_or_hot = [l for l in leads if l.score and l.score.category in ('call_today', 'hot')]
    check('At least one lead reaches Call Today or Hot', len(call_today_or_hot) > 0)
    check('Every Call Today/Hot lead has real inbound intent (no NO_INBOUND_SIGNAL flag)',
          all('NO_INBOUND_SIGNAL' not in l.score.disqualifier_codes for l in call_today_or_hot))


def main():
    print('-- Dedupe --')
    test_dedupe()
    print('-- Pipeline required fields & quality rules --')
    test_pipeline_required_fields()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED')
        sys.exit(1)
    print('All quality tests passed.')


if __name__ == '__main__':
    main()
