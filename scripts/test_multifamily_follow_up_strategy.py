#!/usr/bin/env python
"""
Follow-Up Strategy Engine tests (NEPQ Sales Intelligence Engine, Phase 2).

Covers next-touch type/timing selection based on prior activity + the
current conversation strategy, and its wiring into engine.build_sales_intelligence.
Plain assert-based script (matches the repo's existing test_*.py convention).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.sales_intelligence.nepq_types import FOLLOW_UP_TYPES
from multifamily.sales_intelligence.lead_context_builder import build_lead_context
from multifamily.sales_intelligence.conversation_strategy_engine import select_strategy
from multifamily.sales_intelligence.follow_up_strategy_engine import select_follow_up_strategy
from multifamily.sales_intelligence.engine import build_sales_intelligence
from multifamily import repository

_FAILURES = []
_M = '(FOLLOWUP TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def mk_lead(company, signal_type, source, lead_situation=None, pain=None, activities=None, outcomes=None):
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
    _ids.append(lead.id)
    return lead, (activities or []), (outcomes or [])


# ---- 1. No prior activity -> first_follow_up (unless the ask was for specific info) ----

def test_no_activity_gets_first_follow_up():
    lead, activities, outcomes = mk_lead('Followflow Website', 'website_visit', 'website')
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    strategy = select_strategy(context)
    follow_up = select_follow_up_strategy(context, strategy)
    check('no activity yet gets first_follow_up', follow_up.follow_up_type == 'first_follow_up')
    check('first_follow_up points at follow_up_1', follow_up.message_field == 'follow_up_1')
    check('first_follow_up is not a final attempt', not follow_up.is_final_attempt)


# ---- 2. Info-request scenario (refinance/lender) with no activity -> info_request_reminder ----

def test_info_request_action_gets_reminder_not_generic_followup():
    lead, activities, outcomes = mk_lead('Followflow Refi', 'refinance', 'crm', lead_situation='refinance', pain=['lender_requirement'])
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    strategy = select_strategy(context)
    check('strategy asks for lender requirements', strategy.recommended_action == 'ask_for_lender_requirements')
    follow_up = select_follow_up_strategy(context, strategy)
    check('lender-info ask gets info_request_reminder', follow_up.follow_up_type == 'info_request_reminder')
    check('info_request_reminder points at info_request_note', follow_up.message_field == 'info_request_note')
    check('info_request_reminder has a short wait', follow_up.recommended_wait_days <= 5)


# ---- 3. One prior touch, no reply -> second_follow_up ----

def test_one_touch_gets_second_follow_up():
    lead, activities, outcomes = mk_lead(
        'Followflow OneTouch', 'website_visit', 'website',
        activities=[{'activity_type': 'emailed', 'next_follow_up_date': None}],
    )
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    strategy = select_strategy(context)
    follow_up = select_follow_up_strategy(context, strategy)
    check('one prior touch gets second_follow_up', follow_up.follow_up_type == 'second_follow_up')
    check('second_follow_up points at follow_up_2', follow_up.message_field == 'follow_up_2')


# ---- 4. Two+ touches, no reply -> soft_bump, final attempt ----

def test_multiple_touches_gets_soft_bump_final_attempt():
    lead, activities, outcomes = mk_lead(
        'Followflow MultiTouch', 'website_visit', 'website',
        activities=[
            {'activity_type': 'emailed', 'next_follow_up_date': None},
            {'activity_type': 'emailed', 'next_follow_up_date': None},
        ],
    )
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    strategy = select_strategy(context)
    follow_up = select_follow_up_strategy(context, strategy)
    check('2+ touches gets soft_bump', follow_up.follow_up_type == 'soft_bump')
    check('soft_bump is a final attempt', follow_up.is_final_attempt)


# ---- 5. Replied -> meeting_confirmation_follow_up regardless of activity count ----

def test_replied_lead_gets_meeting_confirmation():
    lead, activities, outcomes = mk_lead(
        'Followflow Replied', 'website_visit', 'website',
        activities=[{'activity_type': 'replied', 'next_follow_up_date': None}],
    )
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    check('context reflects replied', context.replied)
    strategy = select_strategy(context)
    follow_up = select_follow_up_strategy(context, strategy)
    check('replied lead gets meeting_confirmation_follow_up', follow_up.follow_up_type == 'meeting_confirmation_follow_up')
    check('meeting confirmation is not a final attempt', not follow_up.is_final_attempt)


# ---- 6. Closed outcome -> no_further_action ----

def test_closed_outcome_gets_no_further_action():
    lead, activities, outcomes = mk_lead(
        'Followflow Closed', 'website_visit', 'website',
        outcomes=[{'outcome_type': 'not_a_fit'}],
    )
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    strategy = select_strategy(context)
    follow_up = select_follow_up_strategy(context, strategy)
    check('closed outcome gets no_further_action', follow_up.follow_up_type == 'no_further_action')
    check('no_further_action has no message field', follow_up.message_field is None)
    check('no_further_action is a final attempt', follow_up.is_final_attempt)


# ---- 7. Trigger-only / nurture leads always get nurture_reconnect, never a hard push ----

def test_trigger_only_gets_nurture_reconnect():
    lead, activities, outcomes = mk_lead('Followflow Permit', 'permit_filed', 'permit')
    context = build_lead_context(lead, activities=activities, outcomes=outcomes)
    strategy = select_strategy(context)
    check('rule 8 selected', strategy.rule_applied == 'rule_8_permit_news_soft_relevance_check')
    follow_up = select_follow_up_strategy(context, strategy)
    check('trigger-only lead gets nurture_reconnect', follow_up.follow_up_type == 'nurture_reconnect')
    check('nurture_reconnect has a long wait', follow_up.recommended_wait_days >= 30)


# ---- 8. Wired into the full engine + logged on the decision log ----

def test_engine_returns_and_logs_follow_up_strategy():
    lead, activities, outcomes = mk_lead('Followflow EngineWire', 'website_visit', 'website')
    pkg = build_sales_intelligence(lead, activities=activities, outcomes=outcomes, log=True)
    check('package exposes a follow_up_strategy', pkg.follow_up_strategy is not None)
    check('follow_up_strategy.follow_up_type is a declared type', pkg.follow_up_strategy.follow_up_type in FOLLOW_UP_TYPES)
    latest = repository.get_latest_sales_intelligence_event(lead.id)
    check('decision log captures follow_up_type', latest is not None and latest.get('follow_up_type') == pkg.follow_up_strategy.follow_up_type)


def main():
    try:
        test_no_activity_gets_first_follow_up()
        test_info_request_action_gets_reminder_not_generic_followup()
        test_one_touch_gets_second_follow_up()
        test_multiple_touches_gets_soft_bump_final_attempt()
        test_replied_lead_gets_meeting_confirmation()
        test_closed_outcome_gets_no_further_action()
        test_trigger_only_gets_nurture_reconnect()
        test_engine_returns_and_logs_follow_up_strategy()
    finally:
        for lid in _ids:
            repository.delete_sales_intelligence_events_for_lead(lid)
        print(f'\nCleaned up sales-intelligence log rows for {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All follow-up strategy tests passed.')


if __name__ == '__main__':
    main()
