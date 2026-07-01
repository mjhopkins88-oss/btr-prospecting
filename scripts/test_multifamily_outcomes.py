#!/usr/bin/env python
"""
Outcome-tracking phase tests: real business-outcome events on real leads.

Confirms outcomes persist with all financial/date fields, current_outcome
on multifamily_leads always mirrors the latest event, history is ordered
newest-first, the bulk current-outcome lookup used by list views works,
and demo leads never accumulate outcomes. Inserts marker-tagged leads and
cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake import build_lead_from_intake
from multifamily.types import OUTCOME_TYPES, OUTCOME_TERMINAL_TYPES

_FAILURES = []
_M = '(OUTCOME TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, **over):
    payload = {
        'name': 'Outcome Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
    }
    payload.update(over)
    lead, errors = build_lead_from_intake(payload, spam_status='clean', spam_reason_codes=[])
    assert not errors, errors
    repository.insert_lead(lead)
    _ids.append(lead.id)
    return lead


def test_outcome_types_shape():
    check('OUTCOME_TYPES has all 12 required values', set(OUTCOME_TYPES) == {
        'meeting_booked', 'submission_received', 'sov_received', 'loss_runs_received',
        'application_received', 'quote_started', 'quote_sent', 'won', 'lost',
        'not_a_fit', 'nurture', 'dead',
    })
    check('terminal outcomes are a subset of OUTCOME_TYPES', OUTCOME_TERMINAL_TYPES <= set(OUTCOME_TYPES))


def test_creating_outcome_records():
    lead = _make('Createflow Partners')
    row = repository.record_outcome(
        lead.id, 'meeting_booked', estimated_premium=45000.0, estimated_revenue=6750.0,
        notes='Intro call scheduled', created_by='Rep@Example.com',
    )
    check('outcome row has an id', bool(row.get('id')))
    check('outcome_type persisted', row['outcome_type'] == 'meeting_booked')
    check('estimated_premium persisted', row['estimated_premium'] == 45000.0)
    check('estimated_revenue persisted', row['estimated_revenue'] == 6750.0)
    check('created_by lowercased', row['created_by'] == 'rep@example.com')
    check('notes persisted', row['notes'] == 'Intro call scheduled')

    fetched = repository.get_outcomes_for_lead(lead.id)
    check('outcome is queryable by lead', len(fetched) == 1 and fetched[0]['id'] == row['id'])

    lead_row = repository.get_lead_row(lead.id)
    check('current_outcome cache updated on the lead row', lead_row.get('current_outcome') == 'meeting_booked')
    check('current_outcome_at cache populated', bool(lead_row.get('current_outcome_at')))


def test_updating_outcome_records():
    lead = _make('Updateflow Capital')
    repository.record_outcome(lead.id, 'submission_received')
    repository.record_outcome(lead.id, 'quote_started', quoted_premium=30000.0)
    won = repository.record_outcome(
        lead.id, 'won', bound_premium=28500.0, effective_date='2026-09-01',
        renewal_date='2027-09-01', won_reason='Best combined program + faster turnaround',
    )
    history = repository.get_outcomes_for_lead(lead.id)
    check('all three outcome events retained (append-only)', len(history) == 3)
    check('history is newest-first', history[0]['id'] == won['id'])

    current = repository.get_current_outcome(lead.id)
    check('current outcome reflects the latest event (won)', current['outcome_type'] == 'won')
    check('bound_premium on the won event', current['bound_premium'] == 28500.0)
    check('won_reason on the won event', 'turnaround' in (current['won_reason'] or ''))

    lead_row = repository.get_lead_row(lead.id)
    check('lead cache updated to won', lead_row.get('current_outcome') == 'won')


def test_lost_reason_and_all_fields():
    lead = _make('Lostflow Holdings')
    row = repository.record_outcome(
        lead.id, 'lost', lost_reason='Went with incumbent broker',
        effective_date='2026-08-01', renewal_date='2027-08-01', notes='Price was close',
    )
    check('lost_reason persisted', row['lost_reason'] == 'Went with incumbent broker')
    check('effective_date persisted', row['effective_date'] == '2026-08-01')
    check('renewal_date persisted', row['renewal_date'] == '2027-08-01')


def test_bulk_current_outcome_lookup():
    a = _make('Bulkone Realty')
    b = _make('Bulktwo Realty')
    c = _make('Bulkthree Realty')  # no outcome recorded
    repository.record_outcome(a.id, 'meeting_booked')
    repository.record_outcome(b.id, 'quote_sent', quoted_premium=12000.0)

    outcome_map = repository.get_current_outcomes_for_leads([a.id, b.id, c.id])
    check('bulk lookup returns entries only for leads with an outcome', set(outcome_map.keys()) == {a.id, b.id})
    check('bulk lookup values carry the right outcome_type', outcome_map[a.id]['outcome_type'] == 'meeting_booked'
          and outcome_map[b.id]['outcome_type'] == 'quote_sent')
    check('bulk lookup on empty id list returns empty dict', repository.get_current_outcomes_for_leads([]) == {})


def test_delete_outcomes_clears_cache():
    lead = _make('Deleteflow Group')
    repository.record_outcome(lead.id, 'meeting_booked')
    check('current outcome set before delete', repository.get_current_outcome(lead.id) is not None)
    repository.delete_outcomes_for_lead(lead.id)
    check('outcome history cleared', repository.get_outcomes_for_lead(lead.id) == [])
    check('current outcome cleared', repository.get_current_outcome(lead.id) is None)
    lead_row = repository.get_lead_row(lead.id)
    check('lead cache columns cleared', lead_row.get('current_outcome') is None and lead_row.get('current_outcome_at') is None)


def test_demo_leads_never_accumulate_outcomes():
    from multifamily.pipeline import run_pipeline
    leads, _ = run_pipeline()
    demo_ids = [l.id for l in leads if l.is_demo]
    check('demo pipeline produced leads to check', len(demo_ids) > 0)
    outcome_map = repository.get_current_outcomes_for_leads(demo_ids)
    check('no demo lead ever has a persisted outcome', outcome_map == {})


def main():
    try:
        test_outcome_types_shape()
        test_creating_outcome_records()
        test_updating_outcome_records()
        test_lost_reason_and_all_fields()
        test_bulk_current_outcome_lookup()
        test_delete_outcomes_clears_cache()
        test_demo_leads_never_accumulate_outcomes()
    finally:
        for lid in _ids:
            repository.delete_outcomes_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All outcome-tracking tests passed.')


if __name__ == '__main__':
    main()
