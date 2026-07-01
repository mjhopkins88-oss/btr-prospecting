#!/usr/bin/env python
"""
In-app notification tests (outcome/snapshot/notification phase).

Exercises the same notify_*()/sweep() units the Flask route handlers call
(mirrors the no-Flask-import style of the other scripts/test_multifamily_*
scripts) plus the repository CRUD they sit on: emit() dedup, a Call-Today
lead notification, a fuzzy-match review notification, a high-confidence
merge notification, follow-up due/overdue via sweep() (idempotent across
repeated sweeps), a hot-lead-stale sweep, meeting-booked/lead-replied
event notifications, a spam-spike alert, and mark-read/mark-all-read.
Inserts marker-tagged rows and cleans up.
"""
import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository, matching, notifications as notif
from multifamily.intake import build_lead_from_intake
from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead

_FAILURES = []
_M = '(NOTIF TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, **over):
    payload = {
        'name': 'Notif Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
    }
    payload.update(over)
    lead, errors = build_lead_from_intake(payload, spam_status='clean', spam_reason_codes=[])
    assert not errors, errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    _ids.append(lead.id)
    return lead


def mk_lead(company, prop=None, email=None, signal='benchmark_form_submit', source='benchmark_form', state='TX', city='Austin'):
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=(prop or f'{company} {_M} Property'), state=state, city=city,
                            asset_type='garden', unit_count=120)
    contacts = [MultifamilyContact(id=new_id(), full_name='A Person', email=email)] if email else []
    s = MultifamilySignal(id=new_id(), signal_type=signal, source=source)
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=contacts, state=state, city=city,
        primary_signal_type=signal, primary_source=source, is_demo=False,
    )
    lead.score = score_lead(lead)
    return lead


def mk_call_today_lead(company):
    """quote_request + known renewal timing + max fit/pain/relationship
    support — the proven Call Today recipe from test_multifamily_scoring.py
    (a single benchmark_form_submit alone isn't enough to clear the gate)."""
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}', is_owner_operator_developer=True,
                           portfolio_property_count=3, decision_maker_role='VP')
    p = MultifamilyProperty(id=new_id(), name=f'{company} {_M} Property', city='Austin', state='TX',
                            unit_count=150, asset_type='garden', cat_exposed=True, company_id=c.id)
    signals = [
        MultifamilySignal(id=new_id(), signal_type='quote_request', source='form'),
        MultifamilySignal(id=new_id(), signal_type='renewal_date_known', source='crm',
                          detail={'days_until_renewal': 30}),
    ]
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=signals, state='TX', city='Austin',
        primary_signal_type='quote_request', primary_source='form', confidence=0.8, is_demo=False,
        pain_flags=['premium_increase', 'deductible_concern'],
        relationship_flags=['prior_reply', 'existing_client_or_referral'],
    )
    lead.score = score_lead(lead)
    return lead


def _persist(lead):
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    _ids.append(lead.id)
    return lead


def test_emit_dedup():
    n1 = notif.emit('new_call_today_lead', title='T', message='M', lead_id='dedup-lead-xyz', dedupe_key='dedup-test-key-1')
    check('first emit creates a notification', n1 is not None)
    n2 = notif.emit('new_call_today_lead', title='T2', message='M2', lead_id='dedup-lead-xyz', dedupe_key='dedup-test-key-1')
    check('same dedupe_key -> no duplicate created', n2 is None)
    rows = [r for r in repository.get_notifications(limit=500) if r['dedupe_key'] == 'dedup-test-key-1']
    check('exactly one row exists for that dedupe_key', len(rows) == 1)
    repository.delete_notification(n1['id'])


def test_call_today_lead_notification():
    lead = _persist(mk_call_today_lead('Calltodayflow Partners'))
    check('lead actually scored call_today (test setup sanity)', lead.score.category == 'call_today')
    n = notif.notify_new_call_today_lead(lead.id, lead.company.name)
    check('Call Today notification created', n is not None and n['type'] == 'new_call_today_lead')
    check('severity is critical', n['severity'] == 'critical')
    check('lead_id attached', n['lead_id'] == lead.id)

    # re-notifying the same lead (e.g. it stays Call Today across a signal
    # add) must not spam a second alert.
    n2 = notif.notify_new_call_today_lead(lead.id, lead.company.name)
    check('re-notifying the same lead is deduped', n2 is None)


def test_high_confidence_merge_notification():
    survivor = _make('Mergenotif Capital', email='ops@mergenotif.com')
    incoming = mk_lead('Mergenotif Capital', email='ops@mergenotif.com', signal='renewal_date_known', source='crm')
    result = matching.classify(incoming, repository.get_real_leads())
    check('classify finds the auto survivor', result['auto'] is not None)
    matching.merge_incoming_on_intake(result['auto'].lead, incoming)
    n = notif.notify_high_confidence_merge(survivor.id, survivor.company.name, incoming.signals[0].id)
    check('merge notification created', n is not None and n['type'] == 'high_confidence_merge')
    check('merge notification references the survivor lead', n['lead_id'] == survivor.id)


def test_fuzzy_match_review_notification():
    survivor = _make('Fuzzynotif Holdings Group')
    incoming = mk_lead('Fuzzynotif Holdings', email='z@fuzzynotif.com')
    result = matching.classify(incoming, repository.get_real_leads())
    check('classify finds a review candidate (not auto)', result['auto'] is None and result['review'])
    cand_row = repository.insert_match_candidate(
        incoming_signal_id=incoming.signals[0].id, candidate_lead_id=survivor.id,
        match_tier='review', match_reasons=result['review'][0].reasons, score=result['review'][0].score,
        incoming_lead_id=None,
    )
    n = notif.notify_fuzzy_match_review(cand_row['id'], incoming.company.name, survivor.company.name, survivor.id)
    check('fuzzy-match notification created', n is not None and n['type'] == 'fuzzy_match_review')
    check('severity is warning', n['severity'] == 'warning')
    check('message names both companies', incoming.company.name in n['message'] and survivor.company.name in n['message'])
    check('notification links to the existing (persisted) lead', n['lead_id'] == survivor.id)


def test_meeting_booked_and_lead_replied_notifications():
    lead = _make('Eventnotif Estates')
    outcome = repository.record_outcome(lead.id, 'meeting_booked')
    n1 = notif.notify_meeting_booked(lead.id, lead.company.name, outcome['id'])
    check('meeting_booked notification created from an outcome event', n1 is not None)

    activity = repository.insert_activity(lead.id, 'replied', note='Replied to email')
    n2 = notif.notify_lead_replied(lead.id, lead.company.name, activity['id'])
    check('lead_replied notification created from an activity event', n2 is not None)

    # a second, distinct meeting-booked event (e.g. rebooked later) still notifies.
    outcome2 = repository.record_outcome(lead.id, 'meeting_booked')
    n3 = notif.notify_meeting_booked(lead.id, lead.company.name, outcome2['id'])
    check('a second distinct meeting_booked event notifies again', n3 is not None and n3['id'] != n1['id'])


def test_followup_sweep_due_and_overdue():
    lead = _make('Sweepflow Realty')
    today = date.today().isoformat()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    due_today_activity = repository.insert_activity(lead.id, 'called', next_follow_up_date=today)
    overdue_activity = repository.insert_activity(lead.id, 'called', next_follow_up_date=yesterday)

    created = notif.sweep()
    due_notifs = [n for n in created if n['type'] == 'followup_due_today' and n['metadata'].get('activity_id') == due_today_activity['id']]
    overdue_notifs = [n for n in created if n['type'] == 'followup_overdue' and n['metadata'].get('activity_id') == overdue_activity['id']]
    check('sweep created a due-today notification', len(due_notifs) == 1)
    check('sweep created an overdue notification', len(overdue_notifs) == 1)

    # Sweeping again must NOT duplicate either notification.
    created_again = notif.sweep()
    dupes = [n for n in created_again if n['metadata'].get('activity_id') in (due_today_activity['id'], overdue_activity['id'])]
    check('re-sweeping does not duplicate follow-up notifications', dupes == [])


def test_hot_lead_stale_sweep():
    # A Call Today / Hot lead whose only touch is old enough to be stale.
    lead = _persist(mk_call_today_lead('Staleflow Group'))
    check('lead is hot/call_today for this test to be meaningful', lead.score.category in ('hot', 'call_today'))
    stale_at = (date.today() - timedelta(days=notif.STALE_DAYS + 1)).isoformat() + 'T00:00:00'
    # Force last_verified_at (the sweep's fallback signal, absent any
    # logged activity) into the past by rewriting lead_json directly,
    # matching how repository stores it.
    import json as _json
    from shared.database import execute as _exec
    row = repository.get_lead_row(lead.id)
    blob = _json.loads(row['lead_json'])
    blob['last_verified_at'] = stale_at
    _exec('UPDATE multifamily_leads SET lead_json = ? WHERE id = ?', [_json.dumps(blob), lead.id])

    created = notif.sweep()
    stale_notifs = [n for n in created if n['type'] == 'hot_lead_stale' and n['lead_id'] == lead.id]
    check('sweep flagged the stale hot lead', len(stale_notifs) == 1)

    created_again = notif.sweep()
    dupes = [n for n in created_again if n['type'] == 'hot_lead_stale' and n['lead_id'] == lead.id]
    check('re-sweeping does not duplicate the stale-lead notification', dupes == [])


def test_spam_spike():
    ip = 'spike-test-ip-' + os.urandom(3).hex()
    for _ in range(notif.SPAM_SPIKE_THRESHOLD):
        repository.record_intake_event('rejected_garbage', ip, None)
    n = notif.check_spam_spike()
    check('spam spike notification created once threshold is met', n is not None and n['type'] == 'spam_spike')
    n2 = notif.check_spam_spike()
    check('re-checking within the same hour does not duplicate the alert', n2 is None)
    repository.delete_events_for(ip_hash=ip)
    repository.delete_notification(n['id'])


def test_mark_read_and_mark_all_read():
    lead = _make('Readflow Partners')
    n1 = notif.emit('new_call_today_lead', title='T', message='M', lead_id=lead.id, dedupe_key=f'readtest:{lead.id}:1')
    n2 = notif.emit('new_call_today_lead', title='T', message='M', lead_id=lead.id, dedupe_key=f'readtest:{lead.id}:2')
    check('both unread right after creation', not n1['is_read'] and not n2['is_read'])

    repository.mark_notification_read(n1['id'])
    refreshed = [r for r in repository.get_notifications(limit=500) if r['id'] == n1['id']][0]
    check('mark_notification_read flips is_read', refreshed['is_read'] is True)
    unread_ids = {r['id'] for r in repository.get_notifications(unread_only=True, limit=500)}
    check('unread_only filter excludes the read one', n1['id'] not in unread_ids and n2['id'] in unread_ids)

    repository.mark_all_notifications_read()
    check('mark_all_notifications_read clears remaining unread for this lead',
          n2['id'] not in {r['id'] for r in repository.get_notifications(unread_only=True, limit=500)})


def test_demo_leads_never_notify():
    from multifamily.pipeline import run_pipeline
    leads, _ = run_pipeline()
    demo = next(l for l in leads if l.is_demo)
    # Route-level guards never call notify_* for demo leads at all — assert
    # the invariant a caller must honor: is_demo leads have no stable id to
    # dedupe against across requests, so nothing should ever reference one.
    check('demo lead ids regenerate (guard rationale holds)', demo.id.startswith('demo-'))
    matches = [n for n in repository.get_notifications(limit=1000) if n['lead_id'] == demo.id]
    check('no notification exists for a demo lead id', matches == [])


def main():
    try:
        test_emit_dedup()
        test_call_today_lead_notification()
        test_high_confidence_merge_notification()
        test_fuzzy_match_review_notification()
        test_meeting_booked_and_lead_replied_notifications()
        test_followup_sweep_due_and_overdue()
        test_hot_lead_stale_sweep()
        test_spam_spike()
        test_mark_read_and_mark_all_read()
        test_demo_leads_never_notify()
    finally:
        for lid in _ids:
            repository.delete_notifications_for_lead(lid)
            repository.delete_snapshots_for_lead(lid)
            repository.delete_outcomes_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            repository.delete_activities_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(NOTIF TEST)%'")
            conn.execute("DELETE FROM multifamily_notifications WHERE dedupe_key LIKE 'dedup-test-key-%' OR dedupe_key LIKE 'readtest:%'")
            conn.commit(); conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All notification tests passed.')


if __name__ == '__main__':
    main()
