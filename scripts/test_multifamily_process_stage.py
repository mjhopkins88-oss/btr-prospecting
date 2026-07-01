#!/usr/bin/env python
"""
Tests for the process-stage timing engine (multifamily/timing/).

Covers stage detection across all major lifecycle stages, outreach-window
assignment, the per-lead result fields (reason / roles / angle /
confidence / urgency), and confirms the engine never affects scoring.
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.timing import detect_process_stage, PROCESS_STAGES, OUTREACH_WINDOWS

_FAILURES = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _lead(signal_type, source='form', detail=None, pain=None, primary_source=None, contact=False):
    c = MultifamilyCompany(id=new_id(), name='T Co', decision_maker_role='VP Risk')
    p = MultifamilyProperty(id=new_id(), name='T Prop', state='TX', asset_type='garden', unit_count=150)
    s = MultifamilySignal(id=new_id(), signal_type=signal_type, source=source, detail=detail or {})
    contacts = [MultifamilyContact(id=new_id(), full_name='Pat Lee', email='p@e.com')] if contact else []
    return MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=contacts, state='TX',
        primary_signal_type=signal_type, primary_source=primary_source or source, pain_flags=pain or [],
    )


def test_stage_detection():
    cases = [
        ('benchmark_form_submit', {}, 'inbound_request', 'immediate'),
        ('quote_request', {}, 'inbound_request', 'immediate'),
        ('renewal_date_known', {'days_until_renewal': 30}, 'renewal_window', 'this_week'),
        ('renewal_date_known', {'days_until_renewal': 90}, 'renewal_window', 'next_30_days'),
        ('renewal_date_known', {'days_until_renewal': 140}, 'renewal_window', 'next_90_days'),
        ('renewal_date_known', {'days_until_renewal': 170}, 'renewal_window', 'next_90_days'),
        ('renewal_date_known', {'days_until_renewal': -10}, 'post_renewal_active', 'next_30_days'),
        ('renewal_date_known', {'days_until_renewal': -60}, 'post_renewal', 'nurture'),
        ('acquisition', {}, 'acquisition_due_diligence', 'this_week'),
        ('refinance', {}, 'refinance_or_financing', 'this_week'),
        ('permit_filed', {}, 'entitlement_or_permit', 'next_30_days'),
        ('planning_approval', {}, 'entitlement_or_permit', 'nurture'),
        ('groundbreaking', {}, 'construction_start', 'this_week'),
        ('completion', {}, 'completion_or_lease_up', None),  # window depends on recency
        ('portfolio_growth', {}, 'general_watchlist', 'nurture'),
    ]
    for signal_type, detail, exp_stage, exp_window in cases:
        src = 'crm' if signal_type == 'renewal_date_known' else ('permit' if signal_type in (
            'permit_filed', 'planning_approval', 'groundbreaking', 'completion') else (
            'news' if signal_type in ('acquisition', 'refinance', 'portfolio_growth') else 'form'))
        r = detect_process_stage(_lead(signal_type, src, detail))
        check(f'{signal_type} -> stage {exp_stage}', r.process_stage == exp_stage)
        if exp_window is not None:
            check(f'{signal_type} -> window {exp_window}', r.outreach_window == exp_window)


def test_construction_loan_with_builders_risk():
    # Permit + builder's-risk pain -> construction_loan_closing (Rule 6).
    r = detect_process_stage(_lead('permit_filed', 'permit', pain=['builders_risk_need']))
    check('permit + builders_risk_need -> construction_loan_closing', r.process_stage == 'construction_loan_closing')
    check('construction_loan_closing -> this_week', r.outreach_window == 'this_week')


def test_result_fields_present():
    r = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 40, 'self_reported': True}))
    check('process_stage is a known stage', r.process_stage in PROCESS_STAGES)
    check('outreach_window is a known window', r.outreach_window in OUTREACH_WINDOWS)
    check('has urgency_label', bool(r.urgency_label))
    check('has timing_reason', bool(r.timing_reason) and 'days' in r.timing_reason.lower())
    check('has recommended_contact_roles', len(r.recommended_contact_roles) > 0)
    check('renewal angle is the renewal copy', 'pressure test' in r.recommended_message_angle)
    check('self-reported renewal -> high confidence', r.timing_confidence == 'high')


def test_inbound_uses_underlying_context_angle():
    # Inbound benchmark form that also carries a renewal date should open
    # with the renewal angle (refinement in message_angle_recommender).
    lead = _lead('benchmark_form_submit', 'form')
    lead.signals.append(MultifamilySignal(id=new_id(), signal_type='renewal_date_known', source='form', detail={'days_until_renewal': 50}))
    r = detect_process_stage(lead)
    check('inbound lead stage is inbound_request', r.process_stage == 'inbound_request')
    check('inbound+renewal uses the renewal angle', 'renewal' in r.recommended_message_angle.lower())


def test_renewal_band_and_message_posture():
    rescue = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 30}))
    check('rescue band for <=45 days', rescue.renewal_band == 'rescue')
    check('rescue message angle uses speed/market-access posture, not the standard pressure-test copy',
          'capacity' in rescue.recommended_message_angle.lower() or 'options' in rescue.recommended_message_angle.lower())

    decision = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 70}))
    check('decision band for 46-90 days', decision.renewal_band == 'decision')
    check('decision message angle uses the standard analysis/benchmarking copy',
          'pressure test' in decision.recommended_message_angle.lower())

    open_band = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 120}))
    check('open band for >90 days', open_band.renewal_band == 'open')
    check('open message angle uses the standard analysis/benchmarking copy',
          'pressure test' in open_band.recommended_message_angle.lower())

    check('boundary: exactly 45 days is rescue',
          detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 45})).renewal_band == 'rescue')
    check('boundary: exactly 46 days is decision',
          detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 46})).renewal_band == 'decision')
    check('boundary: exactly 90 days is decision',
          detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 90})).renewal_band == 'decision')
    check('boundary: exactly 91 days is open',
          detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': 91})).renewal_band == 'open')

    non_renewal = detect_process_stage(_lead('quote_request', 'form'))
    check('renewal_band is None for non-renewal stages', non_renewal.renewal_band is None)


def test_post_renewal_active_window_and_softer_reason():
    just_signed = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': -5}))
    check('just-signed (day 5) is post_renewal_active', just_signed.process_stage == 'post_renewal_active')
    check('just-signed (day 5) outreach_window is next_30_days (active, not nurture)',
          just_signed.outreach_window == 'next_30_days')
    check('just-signed gets the softer "light touch" reason', 'light touch' in just_signed.timing_reason.lower())

    boundary_soft = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': -13}))
    check('day 13 still gets the softer reason', 'light touch' in boundary_soft.timing_reason.lower())

    past_soft = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': -14}))
    check('day 14 gets the more assertive (but still gentle) reason, not the softest one',
          'light touch' not in past_soft.timing_reason.lower())
    check('day 14 is still post_renewal_active (within the 42-day window)',
          past_soft.process_stage == 'post_renewal_active')

    boundary_active = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': -42}))
    check('day 42 is the last day of the active window', boundary_active.process_stage == 'post_renewal_active')

    stale = detect_process_stage(_lead('renewal_date_known', 'crm', {'days_until_renewal': -43}))
    check('day 43 falls back to the stale post_renewal stage', stale.process_stage == 'post_renewal')
    check('stale post_renewal outreach_window is nurture', stale.outreach_window == 'nurture')


def test_does_not_affect_scoring():
    base = _lead('quote_request', 'form', pain=['premium_increase'])
    before = score_lead(base)
    detect_process_stage(base)  # compute timing
    after = score_lead(base)
    check('scoring unchanged by process-stage detection (total)', before.total == after.total)
    check('scoring unchanged by process-stage detection (category)', before.category == after.category)


def main():
    test_stage_detection()
    test_construction_loan_with_builders_risk()
    test_result_fields_present()
    test_inbound_uses_underlying_context_angle()
    test_renewal_band_and_message_posture()
    test_post_renewal_active_window_and_softer_reason()
    test_does_not_affect_scoring()
    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All process-stage tests passed.')


if __name__ == '__main__':
    main()
