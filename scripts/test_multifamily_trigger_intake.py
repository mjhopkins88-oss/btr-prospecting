#!/usr/bin/env python
"""
SERP Phase A tests: contactless trigger intake (multifamily/intake_trigger.py)
+ its ingest wiring (ingest_trigger_signal/ingest_trigger_batch).

Covers: validate_trigger requires only company/state/source/signalType (no
name/email — the whole reason this path exists separately from intake.py's
form-based build_lead_from_intake); build_lead_from_trigger produces a real,
scored, contactless lead; the new 'serp' source and zero-weight
insurance_market_pressure/market_mention signal types score/time safely
without ever reaching Call Today; ingest_trigger_signal/batch reuse the
exact same spam-gate/match/merge/source-run/snapshot pipeline as the
existing form-based ingest_signal/batch; and the existing form-based path
is unaffected by the builder-parameterization refactor. Inserts
marker-tagged rows and cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake_trigger import validate_trigger, build_lead_from_trigger
from multifamily.ingest import ingest_signal, ingest_trigger_signal, ingest_trigger_batch
from multifamily.spam_guard import HONEYPOT_FIELD
from multifamily.types import SIGNAL_SOURCES, SIGNAL_TYPES

_FAILURES = []
_M = '(TRIGGER TEST)'
_ids = set()


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _payload(company, **over):
    p = {
        'company': f'{company} {_M}', 'state': 'TX', 'city': 'Austin',
        'source': 'serp', 'signalType': 'acquisition', 'sourceUrl': 'https://example.com/a',
        'confidence': 0.6,
    }
    p.update(over)
    return p


def _track(rec):
    if rec.get('lead_id'):
        _ids.add(rec['lead_id'])
    if rec.get('merged_into'):
        _ids.add(rec['merged_into'])
    return rec


# ---- 1. types.py additions ----

def test_serp_source_and_zero_weight_signal_types_registered():
    check("'serp' is a recognized signal source", 'serp' in SIGNAL_SOURCES)
    check("'insurance_market_pressure' is a recognized signal type", 'insurance_market_pressure' in SIGNAL_TYPES)
    check("'market_mention' is a recognized signal type", 'market_mention' in SIGNAL_TYPES)


# ---- 2. validate_trigger: no name/email required ----

def test_validate_trigger_requires_no_contact_fields():
    errors = validate_trigger(_payload('Validflow Co'))
    check('a complete trigger payload with no name/email validates cleanly', errors == [])


def test_validate_trigger_rejects_missing_required_fields():
    errors = validate_trigger({'company': f'Missingflow {_M}'})
    check('missing state/source/signalType are all reported',
          any('state' in e for e in errors) and any('source' in e for e in errors)
          and any('signalType' in e for e in errors))


def test_validate_trigger_rejects_bad_enum_values():
    errors = validate_trigger(_payload('Badenum Co', state='ZZ', source='not_a_source', signalType='not_a_type'))
    check('bad state is rejected', any('state must be one of' in e for e in errors))
    check('bad source is rejected', any('source must be one of' in e for e in errors))
    check('bad signalType is rejected', any('signalType must be one of' in e for e in errors))


# ---- 3. build_lead_from_trigger: contactless, scored, real ----

def test_build_lead_from_trigger_is_contactless_and_scored():
    lead, errors = build_lead_from_trigger(_payload('Buildflow Partners'))
    check('build succeeds with no errors', errors == [] and lead is not None)
    check('lead has zero contacts (contactless by design)', lead.contacts == [])
    check('lead is not demo data', lead.is_demo is False)
    check('lead carries the acquisition signal', lead.primary_signal_type == 'acquisition')
    check('lead carries the serp source', lead.primary_source == 'serp')
    check('lead got scored', lead.score is not None and lead.score.total is not None)


def test_zero_weight_signal_types_never_reach_call_today():
    for signal_type in ('insurance_market_pressure', 'market_mention'):
        lead, errors = build_lead_from_trigger(_payload(f'Zeroweight {signal_type}', signalType=signal_type, confidence=0.4))
        check(f'{signal_type} builds cleanly', errors == [] and lead is not None)
        check(f'{signal_type} never reaches call_today', lead.score.category != 'call_today')
        check(f'{signal_type} contributes no inbound-intent reason code',
              not any('INBOUND' in code for code in (lead.score.reason_codes or [])))


def test_missing_fields_return_errors_not_a_lead():
    lead, errors = build_lead_from_trigger({'company': f'Incomplete {_M}'})
    check('incomplete payload returns no lead', lead is None)
    check('incomplete payload returns errors', len(errors) > 0)


# ---- 4. ingest_trigger_signal / ingest_trigger_batch reuse the shared pipeline ----

def test_ingest_trigger_signal_creates_and_logs_run():
    runs_before = len(repository.get_source_runs(limit=200))
    rec = _track(ingest_trigger_signal(_payload('Ingesttrigger Holdings'), source='serp'))
    check('ingest_trigger_signal created a lead', rec['action'] == 'created' and rec['lead_id'])
    check('a source-run was logged', len(repository.get_source_runs(limit=200)) == runs_before + 1)
    run = next((r for r in repository.get_source_runs(limit=200) if r['id'] == rec['run_db_id']), None)
    check('source-run has finished status + counts', run and run['status'] == 'success'
          and run['records_found'] == 1 and run['records_created'] == 1)
    reloaded = repository.get_lead_by_id(rec['lead_id'])
    check('persisted lead is contactless', reloaded is not None and reloaded.contacts == [])
    check('ingested signal is queryable', len(repository.get_signals_for_lead(rec['lead_id'])) >= 1)


def test_ingest_trigger_same_company_property_auto_merges():
    first = _track(ingest_trigger_signal(
        _payload('Triggermerge Group', propertyName='Triggermerge Gardens', sourceUrl='https://example.com/1'),
        source='serp'))
    second = _track(ingest_trigger_signal(
        _payload('Triggermerge Group', propertyName='Triggermerge Gardens', signalType='financing',
                  sourceUrl='https://example.com/2'),
        source='serp'))
    check('same company+property trigger auto-merges', second['action'] == 'merged' and second['merged_into'] == first['lead_id'])
    reloaded = repository.get_lead_by_id(first['lead_id'])
    check('merged survivor carries both signal types', {'acquisition', 'financing'} <= {s.signal_type for s in reloaded.signals})


def test_ingest_trigger_rejected_never_merges():
    clean = _track(ingest_trigger_signal(_payload('Triggerspam Realty', sourceUrl='https://example.com/clean'), source='serp'))
    pre_signals = len(repository.get_signals_for_lead(clean['lead_id']))
    rejected = _track(ingest_trigger_signal(
        _payload('Triggerspam Realty', sourceUrl='https://example.com/spam', **{HONEYPOT_FIELD: 'i-am-a-bot'}),
        source='serp'))
    check('honeypot trigger payload is rejected', rejected['action'] == 'rejected')
    check('rejected trigger did not merge into the clean lead', rejected['merged_into'] is None
          and rejected['lead_id'] != clean['lead_id'])
    check('clean trigger lead was not strengthened by the rejected one',
          len(repository.get_signals_for_lead(clean['lead_id'])) == pre_signals)


def test_ingest_trigger_batch_logs_counts():
    from multifamily.ingest import ingest_trigger_batch
    payloads = [
        _payload('Triggerbatch Alpha', propertyName='Alpha Towers', sourceUrl='https://example.com/ba1'),
        _payload('Triggerbatch Alpha', propertyName='Alpha Towers', signalType='financing', sourceUrl='https://example.com/ba2'),
        _payload('Triggerbatch Beta', propertyName='Beta Court', sourceUrl='https://example.com/bb1'),
        {'company': f'Triggerbroken {_M}'},  # invalid — missing state/source/signalType
    ]
    summary = ingest_trigger_batch(payloads, source='serp')
    for rec in summary['records']:
        _track(rec)
    check('trigger batch found all records', summary['records_found'] == 4)
    check('trigger batch created 2 (alpha + beta)', summary['records_created'] == 2)
    check('trigger batch merged 1 (duplicate alpha property)', summary['records_merged'] == 1)
    check('trigger batch rejected 1 (invalid)', summary['records_rejected'] == 1)


# ---- 5. form-based ingest is unaffected by the builder parameterization ----

def test_form_based_ingest_signal_still_defaults_correctly():
    rec = _track(ingest_signal({
        'name': 'Formcheck Tester', 'company': f'Formcheck Co {_M}', 'email': 'formcheck@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'permit',
    }, source='permit'))
    check('form-based ingest_signal still creates a lead with a real contact', rec['action'] == 'created')
    lead = repository.get_lead_by_id(rec['lead_id'])
    check('form-based lead still gets a contact (unlike trigger leads)', len(lead.contacts) == 1
          and lead.contacts[0].email == 'formcheck@example.com')


def main():
    try:
        test_serp_source_and_zero_weight_signal_types_registered()
        test_validate_trigger_requires_no_contact_fields()
        test_validate_trigger_rejects_missing_required_fields()
        test_validate_trigger_rejects_bad_enum_values()
        test_build_lead_from_trigger_is_contactless_and_scored()
        test_zero_weight_signal_types_never_reach_call_today()
        test_missing_fields_return_errors_not_a_lead()
        test_ingest_trigger_signal_creates_and_logs_run()
        test_ingest_trigger_same_company_property_auto_merges()
        test_ingest_trigger_rejected_never_merges()
        test_ingest_trigger_batch_logs_counts()
        test_form_based_ingest_signal_still_defaults_correctly()
    finally:
        for lid in list(_ids):
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            repository.delete_snapshots_for_lead(lid)
            repository.delete_outcomes_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(TRIGGER TEST)%'")
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
    print('All trigger-intake (SERP Phase A) tests passed.')


if __name__ == '__main__':
    main()
