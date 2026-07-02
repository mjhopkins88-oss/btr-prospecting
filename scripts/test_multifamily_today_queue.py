#!/usr/bin/env python
"""
Phase D — Today Queue tests.

Covers multifamily/campaigns/today_queue.py's pure day-math
(compute_queue_item, get_today_queue, compute_sequence_adherence) plus
the two new API endpoints (GET /api/multifamily/today-queue and
GET /api/multifamily/campaigns/<id>/sequence-adherence), following the
same conventions as sibling scripts:
  - Direct repository-backed tests run against the real prospects.db
    (like test_multifamily_campaign_sequence.py/_scorecard.py do),
    always cleaning up via a `finally` block, tagged with a unique
    marker so any accidental leftovers are easy to spot/remove.
  - The live-HTTP auth/shape checks spin up an isolated Flask instance
    against a TEMP COPY of prospects.db (never the real file), exactly
    like test_multifamily_workbench_handoff.py's
    test_outreach_endpoint_shape_live().
"""
import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.forms.form_variants import FORM_VARIANTS
from multifamily.types import utc_now_iso
from multifamily.campaigns.today_queue import (
    SEQUENCE_DAY_OFFSETS, compute_queue_item, get_today_queue, compute_sequence_adherence,
)
from shared.database import execute

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FAILURES = []
_M = '(TODAYQUEUE TEST)'
_campaign_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _iso_days_ago(n):
    """A created_at-shaped string n days before today, matching the
    format multifamily.types.utc_now_iso() actually produces
    (datetime.utcnow().isoformat() — no 'Z'/offset)."""
    from datetime import datetime
    return (datetime.utcnow() - timedelta(days=n)).isoformat()


# ---------------------------------------------------------------------
# Pure function-level tests — no DB access at all; target rows are
# hand-built dicts matching list_campaign_targets()'s shape.
# ---------------------------------------------------------------------

def _target(**overrides):
    base = {
        'id': 't-1', 'campaign_id': 'c-1', 'company': 'Acme Co', 'contact_name': 'Jane Doe',
        'email': 'jane@example.com', 'phone': '5125551234', 'linkedin_url': None, 'lead_id': None,
        'status': 'contacted', 'created_at': utc_now_iso(),
        'touch_1_sent_at': None, 'connected_at': None, 'touch_2_sent_at': None,
        'called_at': None, 'breakup_sent_at': None, 'bounced_at': None,
    }
    base.update(overrides)
    return base


def test_offsets_config():
    check('SEQUENCE_DAY_OFFSETS has exactly the 5 sequence steps (bounced excluded)',
          list(SEQUENCE_DAY_OFFSETS.keys()) == ['touch_1_sent', 'connected', 'touch_2_sent', 'called', 'breakup_sent'])
    check('Day 0/2/5/9/16 cadence matches Section 7', list(SEQUENCE_DAY_OFFSETS.values()) == [0, 2, 5, 9, 16])


def test_touch_1_only_created_6_days_ago_owes_connected_and_is_overdue():
    today = date.today()
    t = _target(created_at=_iso_days_ago(6), touch_1_sent_at=_iso_days_ago(6))
    item = compute_queue_item(t, today=today)
    check('item returned (not None)', item is not None)
    if item:
        check("next_step is 'connected' (Day 2, the first unmarked step)", item['next_step'] == 'connected')
        check('due_date is created_at + 2 days', item['due_date'] == (today - timedelta(days=4)).isoformat())
        check('days_overdue is 4 (6 days old, due at day 2)', item['days_overdue'] == 4)
        check('is_overdue is True', item['is_overdue'] is True)
        check('is_due_today is False', item['is_due_today'] is False)


def test_fresh_target_created_today_owes_touch_1_sent_due_today():
    today = date.today()
    t = _target(created_at=today.isoformat() + 'T00:00:00', touch_1_sent_at=None, status='planned')
    item = compute_queue_item(t, today=today)
    check('item returned (not None)', item is not None)
    if item:
        check("next_step is 'touch_1_sent' (Day 0)", item['next_step'] == 'touch_1_sent')
        check('days_overdue is 0', item['days_overdue'] == 0)
        check('is_due_today is True', item['is_due_today'] is True)
        check('is_overdue is False', item['is_overdue'] is False)


def test_future_due_target_is_excluded():
    """A target created today whose touch_1 already went out is next due
    for 'connected' at Day 2 — not part of TODAY's queue."""
    today = date.today()
    t = _target(created_at=today.isoformat() + 'T00:00:00', touch_1_sent_at=today.isoformat() + 'T00:00:00')
    item = compute_queue_item(t, today=today)
    check('a target not yet due (due in the future) returns None', item is None)


def test_bounced_target_excluded():
    t = _target(created_at=_iso_days_ago(30), bounced_at=_iso_days_ago(1))
    check('a bounced target returns None regardless of sequence state', compute_queue_item(t) is None)


def test_converted_target_excluded():
    t = _target(created_at=_iso_days_ago(30), status='converted')
    check("a 'converted' target returns None", compute_queue_item(t) is None)


def test_not_fit_target_excluded():
    t = _target(created_at=_iso_days_ago(30), status='not_fit')
    check("a 'not_fit' target returns None", compute_queue_item(t) is None)


def test_fully_sequenced_target_returns_none():
    t = _target(
        created_at=_iso_days_ago(40), touch_1_sent_at=_iso_days_ago(40), connected_at=_iso_days_ago(38),
        touch_2_sent_at=_iso_days_ago(35), called_at=_iso_days_ago(31), breakup_sent_at=_iso_days_ago(24),
    )
    check('a target with every sequence step marked returns None (nothing owed)', compute_queue_item(t) is None)


# ---------------------------------------------------------------------
# Repository-backed tests — real prospects.db, cleaned up in `finally`.
# ---------------------------------------------------------------------

def _make_campaign(name_suffix, page_variant='renewal-pressure'):
    variant = FORM_VARIANTS[page_variant]
    campaign = repository.create_campaign(
        name=f'{name_suffix} {_M}', page_variant=page_variant, offer_type=variant.offer_type,
    )
    _campaign_ids.append(campaign['id'])
    return campaign


def _backdate_created_at(target_id, iso_ts):
    execute('UPDATE multifamily_campaign_targets SET created_at = ? WHERE id = ?', [iso_ts, target_id])


def test_get_today_queue_ordering_and_scoping():
    c1 = _make_campaign('QueueOrderingCampaign')
    c2 = _make_campaign('QueueScopingCampaign')

    # c1: one badly overdue target (created 25 days ago, untouched -- owes
    # Day 0 touch_1_sent, so it's 25 days overdue), one due-today target
    # (created today, untouched), one not-due-yet target (touch_1 already
    # sent today, next step due at Day 2), one bounced (excluded), one
    # converted (excluded).
    overdue_target = repository.create_campaign_target(c1['id'], company=f'Overdue Co {_M}')
    _backdate_created_at(overdue_target['id'], _iso_days_ago(25))

    due_today_target = repository.create_campaign_target(c1['id'], company=f'DueToday Co {_M}')

    not_due_target = repository.create_campaign_target(c1['id'], company=f'NotDueYet Co {_M}')
    repository.mark_campaign_target_touch(not_due_target['id'], 'touch_1_sent')

    bounced_target = repository.create_campaign_target(c1['id'], company=f'Bounced Co {_M}')
    repository.mark_campaign_target_touch(bounced_target['id'], 'bounced')

    converted_target = repository.create_campaign_target(c1['id'], company=f'Converted Co {_M}')
    repository.update_campaign_target_status(converted_target['id'], 'converted')

    # c2: a moderately overdue target (created 10 days ago, untouched).
    c2_target = repository.create_campaign_target(c2['id'], company=f'C2 Overdue Co {_M}')
    _backdate_created_at(c2_target['id'], _iso_days_ago(10))

    all_queue = get_today_queue()
    ids_in_queue = {item['id'] for item in all_queue}
    check('the badly overdue c1 target is in the all-campaigns queue', overdue_target['id'] in ids_in_queue)
    check('the due-today c1 target is in the all-campaigns queue', due_today_target['id'] in ids_in_queue)
    check('the not-yet-due c1 target is EXCLUDED', not_due_target['id'] not in ids_in_queue)
    check('the bounced c1 target is EXCLUDED', bounced_target['id'] not in ids_in_queue)
    check('the converted c1 target is EXCLUDED', converted_target['id'] not in ids_in_queue)
    check('the c2 overdue target is in the all-campaigns queue', c2_target['id'] in ids_in_queue)

    our_items = [it for it in all_queue if it['id'] in
                 (overdue_target['id'], due_today_target['id'], c2_target['id'])]
    days_overdue_seq = [it['days_overdue'] for it in our_items]
    check('queue is ordered most-overdue-first (descending days_overdue)',
          days_overdue_seq == sorted(days_overdue_seq, reverse=True))
    overdue_item = next(it for it in all_queue if it['id'] == overdue_target['id'])
    check('the 25-day-old target shows 25 days overdue', overdue_item['days_overdue'] == 25)
    check('the 25-day-old target carries its campaign_name', overdue_item['campaign_name'] == c1['name'])

    c1_only_queue = get_today_queue(campaign_id=c1['id'])
    c1_only_ids = {item['id'] for item in c1_only_queue}
    check('scoping to c1 excludes the c2 target', c2_target['id'] not in c1_only_ids)
    check('scoping to c1 still includes the c1 overdue target', overdue_target['id'] in c1_only_ids)


def test_compute_sequence_adherence():
    campaign = _make_campaign('AdherenceCampaign')

    empty_result = compute_sequence_adherence(campaign['id'])
    check('adherence is 0% with zero completed touches (no ZeroDivisionError)', empty_result['adherence_pct'] == 0.0)
    check('completed_count is 0', empty_result['completed_count'] == 0)

    # On-schedule target: touch_1_sent exactly on Day 0.
    on_time = repository.create_campaign_target(campaign['id'], company=f'OnTime Co {_M}')
    now_iso = utc_now_iso()
    _backdate_created_at(on_time['id'], now_iso)
    repository.mark_campaign_target_touch(on_time['id'], 'touch_1_sent', occurred_at=now_iso)

    # Late target: created 20 days ago, 'called' (expected Day 9) actually
    # happened at day 20 -- 11 days past tolerance, clearly late.
    late = repository.create_campaign_target(campaign['id'], company=f'Late Co {_M}')
    created_20_ago = _iso_days_ago(20)
    _backdate_created_at(late['id'], created_20_ago)
    from datetime import datetime
    called_at = (datetime.fromisoformat(created_20_ago) + timedelta(days=20)).isoformat()
    repository.mark_campaign_target_touch(late['id'], 'called', occurred_at=called_at)

    result = compute_sequence_adherence(campaign['id'])
    check('completed_count is 2 (one touch each on 2 targets)', result['completed_count'] == 2)
    check('on_schedule_count is 1 (only the Day-0 touch)', result['on_schedule_count'] == 1)
    check('adherence_pct is 50.0', result['adherence_pct'] == 50.0)


# ---------------------------------------------------------------------
# Live Flask + isolated DB copy — auth gating + endpoint shape.
# ---------------------------------------------------------------------

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _python_with_flask():
    _APP_PY_DEPS = ('flask', 'flask_cors', 'anthropic', 'dotenv', 'apscheduler', 'pytz', 'bcrypt')
    candidates = [sys.executable, '/tmp/mf_venv4/bin/python',
                  os.path.join(REPO_ROOT, 'venv', 'bin', 'python'),
                  os.path.join(REPO_ROOT, '.venv', 'bin', 'python')]
    check_cmd = '; '.join(f'import {mod}' for mod in _APP_PY_DEPS)
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            subprocess.run([candidate, '-c', check_cmd], check=True, capture_output=True, timeout=10)
            return candidate
        except Exception:
            continue
    return sys.executable


def _request(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    headers = {'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    set_cookie = resp.getheader('Set-Cookie')
    cookie_out = set_cookie.split(';')[0] if set_cookie else cookie
    try:
        parsed = json.loads(raw) if raw else None
    except Exception:
        parsed = None
    conn.close()
    return resp.status, parsed, cookie_out


def _wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _, _ = _request(port, 'GET', '/health')
            if status:
                return True
        except Exception:
            time.sleep(0.5)
    return False


def test_today_queue_endpoints_live():
    import shutil
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix='mf_today_queue_')
    real_db = os.path.join(REPO_ROOT, 'prospects.db')
    iso_db = os.path.join(tmpdir, 'prospects.db')
    if os.path.exists(real_db):
        shutil.copy(real_db, iso_db)

    proc = None
    try:
        port = _free_port()
        env = dict(os.environ)
        env['PYTHONPATH'] = REPO_ROOT
        env['PORT'] = str(port)
        env['SUPER_ADMIN_EMAIL'] = 'today-queue-test-super@example.com'
        proc = subprocess.Popen(
            [_python_with_flask(), os.path.join(REPO_ROOT, 'app.py')],
            cwd=tmpdir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server_up = _wait_for_server(port)
        check('isolated Flask instance started', server_up)
        if not server_up:
            return

        status, _, _ = _request(port, 'GET', '/api/multifamily/today-queue')
        check('GET /today-queue requires auth (401 unauthenticated)', status == 401)

        # Need a real campaign id for the path; content doesn't matter for
        # the auth check since require_auth runs before the lookup.
        status2, _, _ = _request(port, 'GET', '/api/multifamily/campaigns/nonexistent-id/sequence-adherence')
        check('GET .../sequence-adherence requires auth (401 unauthenticated)', status2 == 401)

        _, _, cookie = _request(port, 'POST', '/api/auth/bootstrap', body={
            'email': 'today-queue-test-super@example.com', 'password': 'TestPass123!',
            'name': 'Today Queue Test', 'workspace_name': 'TodayQueueTestWS',
        })
        check('bootstrap session cookie captured', bool(cookie))

        status3, campaign_body, _ = _request(port, 'POST', '/api/multifamily/campaigns', body={
            'name': f'Live Today Queue Campaign {_M}', 'pageVariant': 'renewal-pressure',
        }, cookie=cookie)
        check('campaign creation succeeds', status3 == 201)
        campaign = (campaign_body or {}).get('campaign') or {}
        campaign_id = campaign.get('id')
        check('campaign id captured', bool(campaign_id))

        status4, target_body, _ = _request(port, 'POST', f'/api/multifamily/campaigns/{campaign_id}/targets', body={
            'company': f'Live Queue Target Co {_M}',
        }, cookie=cookie)
        check('target creation succeeds', status4 == 201)
        target = (target_body or {}).get('target') or {}
        target_id = target.get('id')
        check('target id captured', bool(target_id))

        # Backdate the target's created_at directly on the isolated DB
        # file so it reads as badly overdue -- a short, closed connection,
        # never touching the real prospects.db.
        conn = sqlite3.connect(iso_db)
        try:
            conn.execute(
                'UPDATE multifamily_campaign_targets SET created_at = ? WHERE id = ?',
                [(time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(time.time() - 15 * 86400))), target_id],
            )
            conn.commit()
        finally:
            conn.close()

        status5, queue_body, _ = _request(port, 'GET', '/api/multifamily/today-queue', cookie=cookie)
        check('GET /today-queue succeeds once authenticated', status5 == 200)
        queue = (queue_body or {}).get('queue') or []
        check('generated_at present on the response', bool((queue_body or {}).get('generated_at')))
        our_item = next((it for it in queue if it['id'] == target_id), None)
        check('the backdated target appears in the live queue', our_item is not None)
        if our_item:
            check("its next_step is 'touch_1_sent' (nothing sent yet)", our_item['next_step'] == 'touch_1_sent')
            check('it is overdue by roughly 15 days', 14 <= our_item['days_overdue'] <= 16)

        status6, scoped_body, _ = _request(
            port, 'GET', f'/api/multifamily/today-queue?campaign_id={campaign_id}', cookie=cookie,
        )
        check('campaign-scoped GET /today-queue succeeds', status6 == 200)
        scoped_queue = (scoped_body or {}).get('queue') or []
        check('scoped queue contains only this campaign\'s targets',
              all(it['campaign_id'] == campaign_id for it in scoped_queue))

        status7, adherence_body, _ = _request(
            port, 'GET', f'/api/multifamily/campaigns/{campaign_id}/sequence-adherence', cookie=cookie,
        )
        check('GET .../sequence-adherence succeeds once authenticated', status7 == 200)
        check("adherence response carries 'adherence_pct'", 'adherence_pct' in (adherence_body or {}))
        check("adherence_pct is 0 (no touches marked yet on this live campaign)",
              (adherence_body or {}).get('adherence_pct') == 0.0)

        status8, campaigns_list_body, _ = _request(port, 'GET', '/api/multifamily/campaigns', cookie=cookie)
        check('GET /campaigns still succeeds (no regression)', status8 == 200)
        listed = next((c for c in (campaigns_list_body or {}).get('campaigns', []) if c['id'] == campaign_id), None)
        check('the campaign list response now carries a sequence_adherence field', bool(listed) and 'sequence_adherence' in listed)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f'\nTorn down isolated Flask instance and temp DB copy ({tmpdir}) — real prospects.db was never touched.')


def main():
    try:
        test_offsets_config()
        test_touch_1_only_created_6_days_ago_owes_connected_and_is_overdue()
        test_fresh_target_created_today_owes_touch_1_sent_due_today()
        test_future_due_target_is_excluded()
        test_bounced_target_excluded()
        test_converted_target_excluded()
        test_not_fit_target_excluded()
        test_fully_sequenced_target_returns_none()
        test_get_today_queue_ordering_and_scoping()
        test_compute_sequence_adherence()
        test_today_queue_endpoints_live()
    finally:
        for cid in _campaign_ids:
            try:
                repository.delete_campaign(cid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_campaign_ids)} tracked campaign(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Today Queue (Phase D) tests passed.')


if __name__ == '__main__':
    main()
