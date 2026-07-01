#!/usr/bin/env python
"""
NEPQ Sales Intelligence Phase 4 tests: follow-up suggestions wired into
the activity dashboard / log-activity response.

Exercises multifamily/sales_intelligence/follow_up_suggestions.py directly
(Flask-independent — this module is imported by api/routes/multifamily.py
but has no Flask dependency itself, so it's testable with the plain
`python` interpreter like every other scripts/test_multifamily_*.py
script). Persists a real lead so repository.get_lead_by_id() resolves to
a full MultifamilyLead.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.sales_intelligence.nepq_types import FOLLOW_UP_TYPES
from multifamily.sales_intelligence.follow_up_suggestions import build_follow_up_suggestion as _follow_up_suggestion
from multifamily.sales_intelligence.follow_up_suggestions import attach_follow_up_suggestions as _attach_follow_up_suggestions

_FAILURES = []
_M = '(ACTFOLLOWUP TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _persist_lead(company, signal_type, source, lead_situation=None, pain=None):
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=f'{company} {_M} Property', state='TX', city='Austin',
                            asset_type='garden', unit_count=150)
    detail = {'lead_situation': lead_situation} if lead_situation else {}
    contacts = [MultifamilyContact(id=new_id(), full_name='Sam Rivera', title=None, email='ops@example.com')]
    signals = [MultifamilySignal(id=new_id(), signal_type=signal_type, source=source, detail=detail)]
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=signals, contacts=contacts, state='TX', city='Austin',
        primary_signal_type=signal_type, primary_source=source, is_demo=False, pain_flags=(pain or []),
    )
    lead.score = score_lead(lead)
    repository.insert_lead(lead)
    _ids.append(lead.id)
    return lead


def test_follow_up_suggestion_for_a_real_lead():
    lead = _persist_lead('ActFollow Website', 'website_visit', 'website')
    suggestion = _follow_up_suggestion(lead)
    check('suggestion is returned for a persisted lead', suggestion is not None)
    check('follow_up_type is a declared type', suggestion['follow_up_type'] in FOLLOW_UP_TYPES)
    check('suggestion carries a suggested_message', bool(suggestion['suggested_message']))
    check('suggestion carries reasoning', bool(suggestion['reasoning']))


def test_follow_up_suggestion_none_for_missing_lead():
    check('None lead returns no suggestion', _follow_up_suggestion(None) is None)
    check('unknown lead_id resolves to None lead and no suggestion',
          _follow_up_suggestion(repository.get_lead_by_id('does-not-exist-' + os.urandom(4).hex())) is None)


def test_info_request_lead_gets_reminder_suggestion():
    lead = _persist_lead('ActFollow Refi', 'refinance', 'crm', lead_situation='refinance', pain=['lender_requirement'])
    suggestion = _follow_up_suggestion(lead)
    check('lender/refinance lead gets an info_request_reminder suggestion',
          suggestion['follow_up_type'] == 'info_request_reminder')
    check('info_request_reminder points at the info_request_note field',
          suggestion['message_field'] == 'info_request_note')
    check('suggested_message text is non-empty', bool(suggestion['suggested_message']))


def test_attach_follow_up_suggestions_on_dashboard_rows():
    lead = _persist_lead('ActFollow Dashboard', 'website_visit', 'website')
    rows = [{'lead_id': lead.id, 'company_name': lead.company.name}]
    _attach_follow_up_suggestions(rows)
    check('dashboard row gains a suggested_follow_up key', 'suggested_follow_up' in rows[0])
    check('dashboard row suggestion is a valid follow-up type',
          rows[0]['suggested_follow_up']['follow_up_type'] in FOLLOW_UP_TYPES)

    rows_unknown = [{'lead_id': 'does-not-exist-' + os.urandom(4).hex()}]
    _attach_follow_up_suggestions(rows_unknown)
    check('dashboard row for an unknown lead gets a None suggestion, not a crash',
          rows_unknown[0]['suggested_follow_up'] is None)


def main():
    try:
        test_follow_up_suggestion_for_a_real_lead()
        test_follow_up_suggestion_none_for_missing_lead()
        test_info_request_lead_gets_reminder_suggestion()
        test_attach_follow_up_suggestions_on_dashboard_rows()
    finally:
        for lid in _ids:
            repository.delete_sales_intelligence_events_for_lead(lid)
            repository.delete_activities_for_lead(lid)
            repository.execute('DELETE FROM multifamily_leads WHERE id = ?', [lid])
        print(f'\nCleaned up {len(_ids)} test lead(s) and their derived rows.')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All activity/follow-up integration tests passed.')


if __name__ == '__main__':
    main()
