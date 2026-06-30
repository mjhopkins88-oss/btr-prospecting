#!/usr/bin/env python
"""
Tests for the real multifamily lead ingestion foundation (intake +
repository + demo fallback).

Inserts real test leads into the local DB (tagged with a unique company
name marker) and always cleans them up afterward, so this is safe to run
repeatedly against the shared dev database.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.intake import build_lead_from_intake
from multifamily import repository
from multifamily.pipeline import run_pipeline, with_demo_fallback, inbound_leads

_FAILURES = []
_MARKER = '(SCRIPT TEST)'
_inserted_ids = []


def check(name, condition):
    if condition:
        print(f'  PASS  {name}')
    else:
        print(f'  FAIL  {name}')
        _FAILURES.append(name)


def _benchmark_payload(**overrides):
    payload = {
        'name': 'Script Test Contact', 'company': f'Script Test Multifamily {_MARKER}',
        'email': 'scripttest@example.com', 'phone': '555-0199', 'role': 'Director of Risk',
        'state': 'TX', 'city': 'Austin', 'assetType': 'garden', 'numberOfUnits': '150',
        'leadSituation': 'renewal', 'renewalDate': '2026-08-01', 'primaryConcern': 'premium_increase',
        'notes': 'Created by test_multifamily_intake.py', 'source': 'benchmark_form',
        'sourcePage': 'Multifamily Insurance Benchmark Review', 'sourceUrl': 'https://example.com/benchmark',
    }
    payload.update(overrides)
    return payload


def _manual_payload(**overrides):
    payload = {
        'name': 'Script Test Manual Contact', 'company': f'Script Test Manual Co {_MARKER}',
        'email': 'manualtest@example.com', 'phone': '555-0188', 'role': 'Owner',
        'state': 'CA', 'city': 'Oakland', 'assetType': 'mid_rise', 'numberOfUnits': '90',
        'leadSituation': 'acquisition', 'primaryConcern': 'lender_requirement',
        'notes': 'Logged by an internal team member.', 'source': 'manual',
        'sourcePage': 'Internal — Manual Entry', 'sourceUrl': '',
    }
    payload.update(overrides)
    return payload


def test_benchmark_form_submission_creates_lead():
    lead, errors = build_lead_from_intake(_benchmark_payload())
    check('Benchmark form payload has no validation errors', errors == [])
    check('Benchmark form submission builds a lead', lead is not None)
    if lead is None:
        return
    check('Benchmark form lead has signal_type benchmark_form_submit', lead.primary_signal_type == 'benchmark_form_submit')
    check('Benchmark form lead source is benchmark_form', lead.primary_source == 'benchmark_form')
    check('Benchmark form lead is not demo', lead.is_demo is False)

    repository.insert_lead(lead)
    _inserted_ids.append(lead.id)
    stored = [l for l in repository.get_real_leads() if l.id == lead.id]
    check('Benchmark form lead is retrievable after insert', len(stored) == 1)
    if stored:
        check('Retrieved lead round-trips company name', stored[0].company.name == lead.company.name)
        check('Retrieved lead round-trips score', stored[0].score.total == lead.score.total)


def test_manual_entry_creates_lead():
    lead, errors = build_lead_from_intake(_manual_payload())
    check('Manual entry payload has no validation errors', errors == [])
    check('Manual entry builds a lead', lead is not None)
    if lead is None:
        return
    check('Manual entry lead source is manual', lead.primary_source == 'manual')
    check('Manual entry lead picks up acquisition timing signal', any(s.signal_type == 'acquisition' for s in lead.signals))

    repository.insert_lead(lead)
    _inserted_ids.append(lead.id)
    stored = [l for l in repository.get_real_leads() if l.id == lead.id]
    check('Manual entry lead is retrievable after insert', len(stored) == 1)


def test_score_engine_runs_after_submission():
    lead, errors = build_lead_from_intake(_benchmark_payload(company=f'Score Engine Test {_MARKER}'))
    check('Score engine ran (lead.score is set)', lead is not None and lead.score is not None)
    if lead and lead.score:
        check('Score has a total', isinstance(lead.score.total, int))
        check('Score has a category', lead.score.category in ('call_today', 'hot', 'warm', 'nurture', 'watchlist'))
        check('Score has reason_codes', len(lead.score.reason_codes) > 0)
        check('Lead has why_warm generated', bool(lead.why_warm))
        check('Lead has likely_pain generated', bool(lead.likely_pain))
        check('Lead has next_best_action generated', bool(lead.next_best_action))
        check('Lead has suggested_opener generated', bool(lead.suggested_opener))


def test_incomplete_submission_is_rejected():
    incomplete = {'name': 'Only A Name'}
    lead, errors = build_lead_from_intake(incomplete)
    check('Incomplete submission returns no lead', lead is None)
    check('Incomplete submission returns validation errors', len(errors) > 0)
    check('Missing company is reported', any('company' in e for e in errors))
    check('Missing email is reported', any('email' in e for e in errors))

    bad_state = _benchmark_payload(state='NY', company=f'Bad State Co {_MARKER}')
    _, errors2 = build_lead_from_intake(bad_state)
    check('Out-of-footprint state is rejected', any('state' in e for e in errors2))

    bad_source = _benchmark_payload(source='not_a_real_source', company=f'Bad Source Co {_MARKER}')
    _, errors3 = build_lead_from_intake(bad_source)
    check('Invalid source is rejected', any('source' in e for e in errors3))


def test_real_leads_display_before_mock():
    lead, errors = build_lead_from_intake(_benchmark_payload(company=f'Priority Test Co {_MARKER}'))
    assert not errors, errors
    repository.insert_lead(lead)
    _inserted_ids.append(lead.id)

    mock_leads, _ = run_pipeline()
    real_leads = [l for l in repository.get_real_leads() if l.id == lead.id]

    combined = with_demo_fallback(real_leads, mock_leads, inbound_leads)
    check('Real lead appears when a real lead exists for this view', any(l.id == lead.id for l in combined))
    check('No demo leads are mixed in when a real lead exists for this view', all(not l.is_demo for l in combined))


def test_mock_leads_labeled_as_demo():
    mock_leads, _ = run_pipeline()
    combined = with_demo_fallback([], mock_leads, inbound_leads)
    check('Mock fallback returns leads when there are zero real leads', len(combined) > 0)
    check('Every mock fallback lead is labeled is_demo=True', all(l.is_demo for l in combined))


def main():
    try:
        test_benchmark_form_submission_creates_lead()
        test_manual_entry_creates_lead()
        test_score_engine_runs_after_submission()
        test_incomplete_submission_is_rejected()
        test_real_leads_display_before_mock()
        test_mock_leads_labeled_as_demo()
    finally:
        for lead_id in _inserted_ids:
            try:
                repository.delete_lead(lead_id)
            except Exception:
                pass
        print(f'\nCleaned up {len(_inserted_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All intake tests passed.')


if __name__ == '__main__':
    main()
