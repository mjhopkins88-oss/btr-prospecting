#!/usr/bin/env python
"""
Score/timing snapshot tests (outcome/snapshot/notification phase).

Confirms a snapshot captures the already-computed score/timing/
attribution state (never recomputes scoring math), fires at each of the
five lifecycle hooks (created, signal_added, merged, outcome_changed,
manual_rerun), stays ordered newest-first, and is a no-op for demo leads.
Inserts marker-tagged leads and cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository, matching
from multifamily.intake import build_lead_from_intake
from multifamily.snapshots import snapshot_lead, SNAPSHOT_REASONS
from multifamily.ingest import ingest_signal
from multifamily.pipeline import run_pipeline
from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead

_FAILURES = []
_M = '(SNAPSHOT TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, **over):
    payload = {
        'name': 'Snap Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
    }
    payload.update(over)
    lead, errors = build_lead_from_intake(payload, spam_status='clean', spam_reason_codes=[])
    assert not errors, errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    _ids.append(lead.id)
    return lead


def mk_lead(company, prop=None, email=None, signal='benchmark_form_submit', source='benchmark_form'):
    """In-memory lead (mirrors test_multifamily_matching.py's mk()) for
    exercising the merge engine directly."""
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=(prop or f'{company} {_M} Property'), state='TX', city='Austin',
                            asset_type='garden', unit_count=120)
    contacts = [MultifamilyContact(id=new_id(), full_name='A Person', email=email)] if email else []
    s = MultifamilySignal(id=new_id(), signal_type=signal, source=source)
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=contacts, state='TX', city='Austin',
        primary_signal_type=signal, primary_source=source, is_demo=False,
    )
    lead.score = score_lead(lead)
    return lead


def test_snapshot_reasons_shape():
    check('SNAPSHOT_REASONS has all 5 lifecycle hooks', set(SNAPSHOT_REASONS) == {
        'created', 'signal_added', 'merged', 'outcome_changed', 'manual_rerun',
    })


def test_snapshot_captures_already_computed_state():
    lead = _make('Snapcapture Partners')
    row = snapshot_lead(lead, 'created')
    check('snapshot captures score_total matching lead.score', row['score_total'] == lead.score.total)
    check('snapshot captures score_category matching lead.score', row['score_category'] == lead.score.category)
    check('snapshot captures reason_codes matching lead.score', row['reason_codes'] == list(lead.score.reason_codes))
    check('snapshot captures a process_stage', bool(row['process_stage']))
    check('snapshot captures signal_count', row['signal_count'] == len(lead.signals))
    check('snapshot captures an attribution_summary dict', isinstance(row['attribution_summary'], dict))


def test_snapshot_on_creation():
    lead = _make('Createhook Realty')
    row = snapshot_lead(lead, 'created')
    history = repository.get_snapshots_for_lead(lead.id)
    check('creation snapshot recorded', len(history) == 1 and history[0]['reason'] == 'created')
    creation = repository.get_creation_snapshot(lead.id)
    check('get_creation_snapshot finds the created row', creation is not None and creation['id'] == row['id'])


def test_snapshot_on_merge_via_matching_module():
    survivor = _make('Mergehook Capital', email='ops@mergehook.com')
    snapshot_lead(survivor, 'created')
    before = len(repository.get_snapshots_for_lead(survivor.id))

    incoming = mk_lead('Mergehook Capital', email='ops@mergehook.com', signal='renewal_date_known', source='crm')
    result = matching.classify(incoming, repository.get_real_leads())
    check('classify finds the auto survivor', result['auto'] is not None)
    matching.merge_incoming_on_intake(result['auto'].lead, incoming)
    snapshot_lead(result['auto'].lead, 'merged')

    after = repository.get_snapshots_for_lead(survivor.id)
    check('a merged snapshot was added', len(after) == before + 1)
    check('latest snapshot reason is merged', after[0]['reason'] == 'merged')
    reloaded = repository.get_lead_by_id(survivor.id)
    check('merged snapshot score reflects the re-scored survivor', after[0]['score_total'] == reloaded.score.total)


def test_snapshot_on_signal_added_via_ingest():
    survivor = _make('Ingesthook Group', email='ops@ingesthook.com')
    snapshot_lead(survivor, 'created')
    before = len(repository.get_snapshots_for_lead(survivor.id))

    rec = ingest_signal({
        'name': 'Snap Tester', 'company': f'Ingesthook Group {_M}', 'email': 'ops@ingesthook.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal', 'source': 'crm',
    }, source='crm')
    check('ingest merged into the existing survivor', rec['action'] == 'merged' and rec['merged_into'] == survivor.id)

    after = repository.get_snapshots_for_lead(survivor.id)
    check('a signal_added snapshot was recorded by ingest', len(after) == before + 1 and after[0]['reason'] == 'signal_added')


def test_snapshot_on_outcome_changed():
    lead = _make('Outcomehook Holdings')
    snapshot_lead(lead, 'created')
    before = len(repository.get_snapshots_for_lead(lead.id))
    repository.record_outcome(lead.id, 'meeting_booked')
    # Outcome recording itself doesn't snapshot (that's the API route's job) —
    # simulate what the route does: snapshot after recording.
    snapshot_lead(lead, 'outcome_changed')
    after = repository.get_snapshots_for_lead(lead.id)
    check('an outcome_changed snapshot was added', len(after) == before + 1)
    check('latest snapshot reason is outcome_changed', after[0]['reason'] == 'outcome_changed')


def test_manual_rerun_snapshot():
    lead = _make('Manualhook Estates')
    snapshot_lead(lead, 'created')
    before = len(repository.get_snapshots_for_lead(lead.id))
    row = snapshot_lead(lead, 'manual_rerun')
    check('manual_rerun snapshot recorded', row is not None and row['reason'] == 'manual_rerun')
    after = repository.get_snapshots_for_lead(lead.id)
    check('history grew by one', len(after) == before + 1)


def test_history_ordered_newest_first():
    lead = _make('Orderhook Partners')
    snapshot_lead(lead, 'created')
    snapshot_lead(lead, 'manual_rerun')
    third = snapshot_lead(lead, 'manual_rerun')
    history = repository.get_snapshots_for_lead(lead.id)
    check('newest-first ordering', history[0]['id'] == third['id'])
    check('all three retained (append-only)', len(history) == 3)


def test_demo_leads_never_snapshot():
    leads, _ = run_pipeline()
    demo = next(l for l in leads if l.is_demo)
    row = snapshot_lead(demo, 'created')
    check('snapshot_lead is a no-op for demo leads', row is None)
    check('no snapshot rows exist for a demo lead id', repository.get_snapshots_for_lead(demo.id) == [])


def test_unknown_reason_rejected():
    lead = _make('Badreasonhook LLC')
    row = snapshot_lead(lead, 'not_a_real_reason')
    check('an unrecognized reason is rejected (no row inserted)', row is None)
    check('no snapshot rows were created', repository.get_snapshots_for_lead(lead.id) == [])


def main():
    try:
        test_snapshot_reasons_shape()
        test_snapshot_captures_already_computed_state()
        test_snapshot_on_creation()
        test_snapshot_on_merge_via_matching_module()
        test_snapshot_on_signal_added_via_ingest()
        test_snapshot_on_outcome_changed()
        test_manual_rerun_snapshot()
        test_history_ordered_newest_first()
        test_demo_leads_never_snapshot()
        test_unknown_reason_rejected()
    finally:
        for lid in _ids:
            repository.delete_snapshots_for_lead(lid)
            repository.delete_outcomes_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(SNAPSHOT TEST)%'")
            # test_snapshot_on_signal_added_via_ingest goes through
            # ingest_signal(), which always logs a source-run.
            conn.execute("DELETE FROM multifamily_source_runs")
            conn.commit(); conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All score/timing snapshot tests passed.')


if __name__ == '__main__':
    main()
