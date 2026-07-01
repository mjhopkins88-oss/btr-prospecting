#!/usr/bin/env python
"""
Phase E tests: generic signal ingest + source-run logging.

Confirms ingest_signal creates a real lead and logs a source-run, a second
same-email ingest auto-merges (no new card) and combines signals, a fuzzy
near-match creates a lead + a review candidate, rejected/honeypot payloads
are persisted but never merged/strengthened, and ingest_batch logs one run
with correct created/merged/rejected counts. Inserts marker-tagged rows and
cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.ingest import ingest_signal, ingest_batch, dry_run_collector
from multifamily.spam_guard import HONEYPOT_FIELD

_FAILURES = []
_M = '(INGEST TEST)'
_ids = set()


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _payload(company, **over):
    p = {
        'name': 'Ingest Tester', 'company': f'{company} {_M}',
        'email': f'{company.lower().replace(" ", "")}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark',
        'source': 'permit', 'sourcePage': 'Ingest',
    }
    p.update(over)
    return p


def _track(rec):
    if rec.get('lead_id'):
        _ids.add(rec['lead_id'])
    if rec.get('merged_into'):
        _ids.add(rec['merged_into'])
    return rec


def test_single_ingest_creates_and_logs_run():
    runs_before = len(repository.get_source_runs(limit=200))
    rec = _track(ingest_signal(_payload('Ingestflow Partners'), source='permit'))
    check('single ingest created a lead', rec['action'] == 'created' and rec['lead_id'])
    check('a source-run was logged', len(repository.get_source_runs(limit=200)) == runs_before + 1)
    run = next((r for r in repository.get_source_runs(limit=200) if r['id'] == rec['run_db_id']), None)
    check('source-run has finished status + counts', run and run['status'] == 'success'
          and run['records_found'] == 1 and run['records_created'] == 1)
    check('ingested signal is queryable', len(repository.get_signals_for_lead(rec['lead_id'])) >= 1)
    check('first attribution touch recorded', len(repository.get_attribution_for_lead(rec['lead_id'])) >= 1)


def test_same_email_auto_merges():
    first = _track(ingest_signal(_payload('Mergepath Capital', email='ops@mergepath.com'), source='permit'))
    pre = repository.get_lead_row(first['lead_id']).get('signal_count')
    second = _track(ingest_signal(
        _payload('Mergepath Capital', email='ops@mergepath.com', source='crm', leadSituation='renewal',
                 renewalDate='2026-09-01'),
        source='crm'))
    check('second same-email ingest auto-merged', second['action'] == 'merged' and second['merged_into'] == first['lead_id'])
    reloaded = repository.get_lead_by_id(first['lead_id'])
    check('merged survivor carries >1 signal type', len({s.signal_type for s in reloaded.signals}) >= 2)
    check('signal_count grew after merge', repository.get_lead_row(first['lead_id']).get('signal_count') > (pre or 0))
    active = [l for l in repository.get_real_leads() if l.company.name == f'Mergepath Capital {_M}']
    check('no duplicate card (one active lead for the company)', len(active) == 1)


def test_fuzzy_creates_review_candidate():
    a = _track(ingest_signal(_payload('Fuzzyingest Holdings Group', email='a@fuzzyingest.com'), source='permit'))
    b = _track(ingest_signal(_payload('Fuzzyingest Holdings', email='b@fuzzyingest2.com'), source='news'))
    check('fuzzy near-match created a separate lead (not merged)', b['action'] == 'created')
    check('fuzzy near-match raised a review candidate', b['review_candidates'] >= 1)


def test_rejected_never_merges():
    # Seed a clean lead, then a honeypot-filled payload for the SAME company+email.
    clean = _track(ingest_signal(_payload('Spamguard Realty', email='real@spamguard.com'), source='permit'))
    pre_signals = len(repository.get_signals_for_lead(clean['lead_id']))
    rejected = _track(ingest_signal(
        _payload('Spamguard Realty', email='real@spamguard.com', **{HONEYPOT_FIELD: 'i-am-a-bot'}),
        source='permit'))
    check('honeypot payload is rejected', rejected['action'] == 'rejected')
    check('rejected did NOT merge into the clean lead', rejected['merged_into'] is None
          and rejected['lead_id'] != clean['lead_id'])
    check('clean lead was NOT strengthened by the rejected signal',
          len(repository.get_signals_for_lead(clean['lead_id'])) == pre_signals)


def test_batch_logs_single_run_with_counts():
    payloads = [
        _payload('Batch Alpha', email='a@batchalpha.com'),
        _payload('Batch Alpha', email='a@batchalpha.com'),          # -> merge
        _payload('Batch Beta', email='b@batchbeta.com'),
        {'company': f'Broken {_M}'},                                  # -> invalid (missing required fields)
    ]
    summary = ingest_batch(payloads, source='permit')
    for rec in summary['records']:
        _track(rec)
    check('batch found all records', summary['records_found'] == 4)
    check('batch created 2 (alpha + beta)', summary['records_created'] == 2)
    check('batch merged 1 (duplicate alpha)', summary['records_merged'] == 1)
    check('batch rejected 1 (invalid)', summary['records_rejected'] == 1)
    run = next((r for r in repository.get_source_runs(limit=200) if r['id'] == summary['run_db_id']), None)
    check('batch logged one run with matching counts', run and run['records_created'] == 2
          and run['records_merged'] == 1 and run['records_rejected'] == 1)


def test_dry_run_collector_proves_path():
    from multifamily.signal_collectors import form_lead_ingestor
    summary = dry_run_collector(form_lead_ingestor.collect, source='form')
    for rec in summary['records']:
        _track(rec)
    check('dry-run routed collector output through ingest', summary['records_found'] >= 1)
    check('dry-run created/merged at least one lead',
          (summary['records_created'] + summary['records_merged']) >= 1)


def main():
    try:
        test_single_ingest_creates_and_logs_run()
        test_same_email_auto_merges()
        test_fuzzy_creates_review_candidate()
        test_rejected_never_merges()
        test_batch_logs_single_run_with_counts()
        test_dry_run_collector_proves_path()
    finally:
        # Delete every touched lead + its signals/attribution/candidates, then
        # sweep any marker-tagged leftovers and all source-runs we logged.
        for lid in list(_ids):
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
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(INGEST TEST)%'")
            conn.execute("DELETE FROM multifamily_source_runs")
            conn.commit()
            conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_ids)} tracked lead(s) + source-runs.')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All ingest (Phase E) tests passed.')


if __name__ == '__main__':
    main()
