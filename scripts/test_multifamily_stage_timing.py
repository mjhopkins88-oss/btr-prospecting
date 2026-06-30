#!/usr/bin/env python
"""
Tests for Phase 5: construction process-stage timing intelligence
(multifamily/stage_timing.py).

Confirms the on_track/due_soon/overdue/completed/unknown classification,
that non-construction leads are unaffected (return None), that it never
touches the scoring engine, and that the demo data shows off both a
stalled (overdue) and an approaching (due_soon) example.
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.stage_timing import compute_stage_timing, EXPECTED_DAYS_TO_NEXT_STAGE, DUE_SOON_THRESHOLD
from multifamily.pipeline import run_pipeline

_FAILURES = []


def check(name, condition):
    if condition:
        print(f'  PASS  {name}')
    else:
        print(f'  FAIL  {name}')
        _FAILURES.append(name)


def _lead_with_stage(signal_type, days_ago, **lead_overrides):
    company = MultifamilyCompany(id=new_id(), name='Stage Timing Test Co')
    prop = MultifamilyProperty(id=new_id(), name='Stage Timing Test Prop', state='TX', asset_type='garden')
    occurred_at = (datetime.utcnow() - timedelta(days=days_ago)).isoformat()
    signal = MultifamilySignal(id=new_id(), signal_type=signal_type, source='permit', occurred_at=occurred_at)
    defaults = dict(
        id=new_id(), company=company, property=prop, signals=[signal],
        state='TX', primary_signal_type=signal_type, primary_source='permit',
    )
    defaults.update(lead_overrides)
    return MultifamilyLead(**defaults)


def test_on_track_classification():
    expected = EXPECTED_DAYS_TO_NEXT_STAGE['permit_filed']
    lead = _lead_with_stage('permit_filed', days_ago=5)
    timing = compute_stage_timing(lead)
    check('Well within expected window classifies as on_track', timing['timing_status'] == 'on_track')
    check('days_in_stage reported correctly', timing['days_in_stage'] == 5)
    check('expected_days_to_next_stage reported correctly', timing['expected_days_to_next_stage'] == expected)


def test_due_soon_classification():
    expected = EXPECTED_DAYS_TO_NEXT_STAGE['groundbreaking']
    days_ago = int(expected * DUE_SOON_THRESHOLD) + 1
    lead = _lead_with_stage('groundbreaking', days_ago=days_ago)
    timing = compute_stage_timing(lead)
    check(f'{days_ago} of {expected} expected days classifies as due_soon', timing['timing_status'] == 'due_soon')
    check('due_soon explanation mentions "checking in"', 'checking in' in timing['explanation'])


def test_overdue_classification():
    expected = EXPECTED_DAYS_TO_NEXT_STAGE['vertical_construction']
    lead = _lead_with_stage('vertical_construction', days_ago=expected + 30)
    timing = compute_stage_timing(lead)
    check('Past the expected window classifies as overdue', timing['timing_status'] == 'overdue')
    check('overdue explanation flags it may be stalled', 'stalled' in timing['explanation'])


def test_completed_status():
    lead = _lead_with_stage('completion', days_ago=400)
    timing = compute_stage_timing(lead)
    check('Completion stage classifies as completed regardless of elapsed time', timing['timing_status'] == 'completed')
    check('No expected_days_to_next_stage for completed', timing['expected_days_to_next_stage'] is None)


def test_unknown_status_for_unmeasurable_timestamp():
    lead = _lead_with_stage('permit_filed', days_ago=5)
    lead.signals[0].occurred_at = ''  # unparseable/missing
    timing = compute_stage_timing(lead)
    check('Missing/unparseable occurred_at classifies as unknown', timing['timing_status'] == 'unknown')


def test_non_construction_lead_returns_none():
    lead = _lead_with_stage('acquisition', days_ago=10)
    check('Non-construction signal type returns None (purely additive)', compute_stage_timing(lead) is None)

    lead_no_signals = MultifamilyLead(
        id=new_id(), company=MultifamilyCompany(id=new_id(), name='No Signals Co'),
        property=MultifamilyProperty(id=new_id(), name='No Signals Prop'), signals=[],
    )
    check('Lead with zero signals returns None', compute_stage_timing(lead_no_signals) is None)


def test_most_advanced_stage_wins():
    company = MultifamilyCompany(id=new_id(), name='Multi-Stage Co')
    prop = MultifamilyProperty(id=new_id(), name='Multi-Stage Prop', state='TX')
    s1 = MultifamilySignal(id=new_id(), signal_type='permit_filed', source='permit',
                            occurred_at=(datetime.utcnow() - timedelta(days=120)).isoformat())
    s2 = MultifamilySignal(id=new_id(), signal_type='groundbreaking', source='permit',
                            occurred_at=(datetime.utcnow() - timedelta(days=5)).isoformat())
    lead = MultifamilyLead(id=new_id(), company=company, property=prop, signals=[s1, s2],
                            state='TX', primary_signal_type='groundbreaking', primary_source='permit')
    timing = compute_stage_timing(lead)
    check('Most advanced of multiple stage signals is used', timing['current_stage'] == 'groundbreaking')
    check('days_in_stage reflects the advanced signal, not the earliest one', timing['days_in_stage'] == 5)


def test_does_not_affect_scoring():
    fresh = _lead_with_stage('permit_filed', days_ago=1, pain_flags=['builders_risk_need'])
    stale = _lead_with_stage('permit_filed', days_ago=400, pain_flags=['builders_risk_need'])
    score_fresh = score_lead(fresh)
    score_stale = score_lead(stale)
    check('Stage timing (occurred_at) does not change the score total', score_fresh.total == score_stale.total)
    check('Stage timing (occurred_at) does not change the score category', score_fresh.category == score_stale.category)
    check('compute_stage_timing reports different timing_status for the same score', compute_stage_timing(fresh)['timing_status'] != compute_stage_timing(stale)['timing_status'])


def test_demo_data_shows_both_overdue_and_due_soon():
    leads, _ = run_pipeline()
    timings = {l.company.name: compute_stage_timing(l) for l in leads}
    timed = {name: t for name, t in timings.items() if t}
    check('At least one demo construction lead is present', len(timed) > 0)
    check('Demo data includes an overdue example', any(t['timing_status'] == 'overdue' for t in timed.values()))
    check('Demo data includes a due_soon example', any(t['timing_status'] == 'due_soon' for t in timed.values()))


def main():
    test_on_track_classification()
    test_due_soon_classification()
    test_overdue_classification()
    test_completed_status()
    test_unknown_status_for_unmeasurable_timestamp()
    test_non_construction_lead_returns_none()
    test_most_advanced_stage_wins()
    test_does_not_affect_scoring()
    test_demo_data_shows_both_overdue_and_due_soon()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All stage timing tests passed.')


if __name__ == '__main__':
    main()
