#!/usr/bin/env python
"""
Phase A tests for the persisted signal architecture:
- signals persist as queryable rows and reload
- attribution touches persist
- source runs log with counts
- the lead_json -> multifamily_signals backfill is idempotent

Inserts test rows tagged with a unique marker and cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, new_id,
)

_FAILURES = []
_MARKER = '(SIGNALS TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_lead(signals):
    c = MultifamilyCompany(id=new_id(), name=f'Signal Co {_MARKER}')
    p = MultifamilyProperty(id=new_id(), name='Signal Prop', state='TX', city='Austin', asset_type='garden', unit_count=120)
    contact = MultifamilyContact(id=new_id(), full_name='Sam Lee', email='sam@example.com')
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=signals, contacts=[contact], state='TX', city='Austin',
        primary_signal_type=signals[0].signal_type, primary_source=signals[0].source, is_demo=False,
        utm_source='google', utm_campaign='q3', source_page='Benchmark', confidence=0.9,
    )
    return lead


def main():
    try:
        repository.ensure_schema()

        s1 = MultifamilySignal(id=new_id(), signal_type='benchmark_form_submit', source='benchmark_form', confidence=0.9, detail={'form': 'benchmark'})
        s2 = MultifamilySignal(id=new_id(), signal_type='renewal_date_known', source='form', confidence=0.85, detail={'days_until_renewal': 40})
        lead = _make_lead([s1, s2])
        _ids.append(lead.id)

        # Mirror what create_lead does.
        repository.insert_lead(lead)
        repository.persist_lead_signals(lead)
        repository.record_lead_attribution_touch(lead, touch_type='first')

        sigs = repository.get_signals_for_lead(lead.id)
        check('both signals persist as queryable rows', len(sigs) == 2)
        check('signal detail round-trips as JSON', any(s.get('detail', {}).get('days_until_renewal') == 40 for s in sigs))
        check('signals are ordered by occurred_at', sigs[0]['occurred_at'] <= sigs[1]['occurred_at'])

        att = repository.get_attribution_for_lead(lead.id)
        check('a first attribution touch persists', len(att) == 1 and att[0]['touch_type'] == 'first')
        check('attribution captures utm_source', att[0]['utm_source'] == 'google')

        # Source run accounting.
        run = repository.start_source_run('benchmark_form')
        _run_id = run['id']
        check('start_source_run returns a running run', run['status'] == 'running')
        repository.finish_source_run(_run_id, status='success', records_found=3, records_created=2, records_merged=1, records_rejected=0, warnings=['low_confidence_one'])
        runs = [r for r in repository.get_source_runs() if r['id'] == _run_id]
        check('finish_source_run records counts', len(runs) == 1 and runs[0]['records_created'] == 2 and runs[0]['records_merged'] == 1)
        check('source run warnings round-trip', runs[0]['warnings'] == ['low_confidence_one'])
        check('source run status is success', runs[0]['status'] == 'success')
        repository.delete_source_run(_run_id)

        # Backfill idempotency: wipe the projected rows, re-run ensure_schema twice.
        repository.delete_signals_for_lead(lead.id)
        check('signals wiped to simulate a pre-phase lead', len(repository.get_signals_for_lead(lead.id)) == 0)
        repository._SCHEMA_READY = False
        repository.ensure_schema()
        first = len(repository.get_signals_for_lead(lead.id))
        repository._SCHEMA_READY = False
        repository.ensure_schema()
        second = len(repository.get_signals_for_lead(lead.id))
        check('backfill restores the lead_json signals (2)', first == 2)
        check('backfill is idempotent (still 2 after a second run)', second == 2)

        # signal_count projection set on insert.
        row = repository.get_lead_row(lead.id)
        check('lead row records signal_count', row.get('signal_count') == 2)
        check('lead row is active (not merged)', (row.get('merge_status') or 'active') == 'active')
    finally:
        for lid in _ids:
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_ids)} test lead(s) and their signal rows.')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All signal-architecture (Phase A) tests passed.')


if __name__ == '__main__':
    main()
