"""
API Routes: Prospecting Dashboard

Exposes the task engine data for the Prospecting page tabs:
Summary, Schedule, Feed, Groups, Sequences.
"""
from flask import Blueprint, request, jsonify, make_response

from datetime import datetime, timedelta

from services.task_engine import (
    get_summary_stats, get_task_buckets, get_schedule,
    get_groups_list, get_sequences_list, get_feed,
    complete_task, run_daily_scheduler,
    rule_new_group, rule_meeting_followup, rule_proposal_followup,
    rule_signal, get_todays_focus, get_followup_queue
)
from services.prospecting_rules import (
    rule_initial_followup, rule_task_complete, compute_next_best_action,
    build_signalstack_payload, ingest_signal, run_daily_rules,
    VALID_STAGES
)
from shared.database import fetch_all, fetch_one, execute, new_id
from db import is_postgres as _is_postgres

prospecting_bp = Blueprint(
    'prospecting', __name__, url_prefix='/api/prospecting'
)


@prospecting_bp.route('/summary', methods=['GET'])
def summary():
    return jsonify({
        'snapshot': get_summary_stats(),
        'buckets': get_task_buckets()
    })


@prospecting_bp.route('/todays-focus', methods=['GET'])
def todays_focus():
    limit = request.args.get('limit', 10, type=int)
    return jsonify(get_todays_focus(limit=min(limit, 25)))


@prospecting_bp.route('/followup-queue', methods=['GET'])
def followup_queue():
    limit = request.args.get('limit', 30, type=int)
    return jsonify(get_followup_queue(limit=min(limit, 30)))


@prospecting_bp.route('/schedule', methods=['GET'])
def schedule():
    days = request.args.get('days', 5, type=int)
    return jsonify(get_schedule(days=min(days, 14)))


@prospecting_bp.route('/feed', methods=['GET'])
def feed():
    type_filter = request.args.get('type', '')
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_feed(type_filter=type_filter, limit=min(limit, 200)))


@prospecting_bp.route('/groups', methods=['GET'])
def groups():
    search = request.args.get('search', '')
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')
    sort_by = request.args.get('sort', 'warmth')
    return jsonify(get_groups_list(search=search, type_filter=type_filter, status_filter=status_filter, sort_by=sort_by))


@prospecting_bp.route('/sequences', methods=['GET'])
def sequences():
    return jsonify(get_sequences_list())


@prospecting_bp.route('/sequences', methods=['POST'])
def create_sequence():
    data = request.get_json(force=True)
    sid = new_id()
    steps = data.get('steps', [])
    execute(
        "INSERT INTO prospecting_sequences (id, name, description, status, total_steps, step_definitions, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
        [sid, data.get('name', 'Untitled'), data.get('description', ''), data.get('status', 'draft'),
         len(steps), str(steps) if steps else '[]']
    )
    return jsonify({'id': sid}), 201


@prospecting_bp.route('/sequences/<sid>/enroll', methods=['POST'])
def enroll_in_sequence(sid):
    data = request.get_json(force=True)
    group_id = data.get('capital_group_id')
    if not group_id:
        return jsonify({'error': 'capital_group_id required'}), 400
    eid = new_id()
    execute(
        "INSERT INTO prospecting_enrollments (id, sequence_id, capital_group_id, current_step, status, enrolled_at) "
        "VALUES (?, ?, ?, 1, 'active', datetime('now'))",
        [eid, sid, group_id]
    )
    group = fetch_one("SELECT name FROM capital_groups WHERE id = ?", [group_id])
    seq = fetch_one("SELECT name FROM prospecting_sequences WHERE id = ?", [sid])
    from services.task_engine import _log_feed
    _log_feed(group_id, 'sequence',
              f"Enrolled in {seq['name'] if seq else 'sequence'}",
              f"{group['name'] if group else 'Group'} enrolled in sequence")
    return jsonify({'id': eid}), 201


@prospecting_bp.route('/tasks/<task_id>/complete', methods=['POST'])
def mark_complete(task_id):
    task = complete_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify({'status': 'completed'})


@prospecting_bp.route('/tasks', methods=['GET'])
def list_tasks():
    status = request.args.get('status', 'pending')
    group_id = request.args.get('group_id', '')
    contact_id = request.args.get('contact_id', '')
    where = ["status = ?"]
    params = [status]
    if group_id:
        where.append("capital_group_id = ?")
        params.append(group_id)
    if contact_id:
        where.append("contact_id = ?")
        params.append(contact_id)
    tasks = fetch_all(
        f"SELECT * FROM prospecting_tasks WHERE {' AND '.join(where)} ORDER BY priority DESC, due_at ASC",
        params
    )
    return jsonify(tasks)


@prospecting_bp.route('/scheduler/run', methods=['POST'])
def run_scheduler():
    result = run_daily_scheduler()
    return jsonify(result)


@prospecting_bp.route('/trigger/new-group', methods=['POST'])
def trigger_new_group():
    data = request.get_json(force=True)
    rule_new_group(data['capital_group_id'], data['group_name'])
    return jsonify({'status': 'ok'})


@prospecting_bp.route('/trigger/meeting', methods=['POST'])
def trigger_meeting():
    data = request.get_json(force=True)
    rule_meeting_followup(data['capital_group_id'], data['group_name'], data.get('notes', ''))
    return jsonify({'status': 'ok'})


@prospecting_bp.route('/trigger/proposal', methods=['POST'])
def trigger_proposal():
    data = request.get_json(force=True)
    rule_proposal_followup(data['capital_group_id'], data['group_name'], data.get('detail', ''))
    return jsonify({'status': 'ok'})


@prospecting_bp.route('/trigger/signal', methods=['POST'])
def trigger_signal():
    data = request.get_json(force=True)
    rule_signal(data['capital_group_id'], data['group_name'], data.get('detail', ''))
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# CONTACTS — relationship-first prospecting
# ---------------------------------------------------------------------------

@prospecting_bp.route('/contacts', methods=['GET'])
def list_contacts():
    group_id = request.args.get('group_id', '')
    stage = request.args.get('stage', '')
    search = request.args.get('search', '')
    where = ["1=1"]
    params = []
    if group_id:
        where.append("c.group_id = ?")
        params.append(group_id)
    if stage:
        where.append("c.relationship_stage = ?")
        params.append(stage)
    if search:
        where.append("(LOWER(c.first_name) LIKE ? OR LOWER(c.last_name) LIKE ? OR LOWER(c.email) LIKE ?)")
        like = f'%{search.lower()}%'
        params.extend([like, like, like])

    rows = fetch_all(
        "SELECT c.*, g.name AS group_name, g.type AS group_type "
        "FROM prospecting_contacts c LEFT JOIN capital_groups g ON g.id = c.group_id "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY COALESCE(c.is_favorite, 0) DESC, COALESCE(c.last_touch_at, c.first_reached_out_at, c.created_at) DESC",
        params
    )
    for r in rows:
        r['next_best_action'] = compute_next_best_action(contact_id=r['id'])
        conv = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_touchpoints "
            "WHERE contact_id = ? AND channel IN ('call', 'meeting', 'conversation')",
            [r['id']]
        )
        r['has_conversation'] = (conv['cnt'] > 0) if conv else False
    return jsonify(rows)


@prospecting_bp.route('/contacts', methods=['POST'])
def create_contact():
    data = request.get_json(force=True)
    if not (data.get('first_name') or data.get('last_name')):
        return jsonify({'error': 'first_name or last_name required'}), 400

    stage = data.get('relationship_stage') or 'cold'
    if stage not in VALID_STAGES:
        return jsonify({'error': f'invalid relationship_stage'}), 400

    cid = new_id()
    now = datetime.utcnow().isoformat()
    execute(
        "INSERT INTO prospecting_contacts "
        "(id, group_id, first_name, last_name, title, linkedin_url, email, phone, "
        "first_reached_out_at, last_touch_at, relationship_stage, owner_user_id, notes, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [cid, data.get('group_id'), data.get('first_name', ''), data.get('last_name', ''),
         data.get('title'), data.get('linkedin_url'), data.get('email'), data.get('phone'),
         data.get('first_reached_out_at'), data.get('last_touch_at'), stage,
         data.get('owner_user_id'), data.get('notes'), now, now]
    )

    if data.get('first_reached_out_at'):
        rule_initial_followup(cid)

    created = fetch_one("SELECT * FROM prospecting_contacts WHERE id = ?", [cid])
    return jsonify(created), 201


@prospecting_bp.route('/contacts/<cid>', methods=['GET'])
def get_contact(cid):
    row = fetch_one(
        "SELECT c.*, g.name AS group_name, g.type AS group_type "
        "FROM prospecting_contacts c LEFT JOIN capital_groups g ON g.id = c.group_id WHERE c.id = ?",
        [cid]
    )
    if not row:
        return jsonify({'error': 'not found'}), 404
    row['touchpoints'] = fetch_all(
        "SELECT * FROM prospecting_touchpoints WHERE contact_id = ? ORDER BY occurred_at DESC LIMIT 50",
        [cid]
    )
    row['tasks'] = fetch_all(
        "SELECT * FROM prospecting_tasks WHERE contact_id = ? AND status = 'pending' ORDER BY priority DESC, due_at ASC",
        [cid]
    )
    row['next_best_action'] = compute_next_best_action(contact_id=cid)
    return jsonify(row)


@prospecting_bp.route('/contacts/<cid>', methods=['PATCH'])
def update_contact(cid):
    existing = fetch_one("SELECT id, first_reached_out_at FROM prospecting_contacts WHERE id = ?", [cid])
    if not existing:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json(force=True)

    allowed = ['group_id', 'first_name', 'last_name', 'title', 'linkedin_url', 'email', 'phone',
               'first_reached_out_at', 'last_touch_at', 'relationship_stage', 'owner_user_id', 'notes', 'is_favorite']
    sets = []
    params = []
    for k in allowed:
        if k in data:
            if k == 'relationship_stage' and data[k] not in VALID_STAGES:
                return jsonify({'error': f'invalid relationship_stage'}), 400
            sets.append(f'{k} = ?')
            params.append(data[k])
    if not sets:
        return jsonify({'error': 'no fields'}), 400
    sets.append('updated_at = ?')
    params.append(datetime.utcnow().isoformat())
    params.append(cid)
    execute(f"UPDATE prospecting_contacts SET {', '.join(sets)} WHERE id = ?", params)

    if 'first_reached_out_at' in data and data['first_reached_out_at'] and not existing.get('first_reached_out_at'):
        rule_initial_followup(cid)

    updated = fetch_one("SELECT * FROM prospecting_contacts WHERE id = ?", [cid])
    return jsonify(updated)


@prospecting_bp.route('/contacts/<cid>', methods=['DELETE'])
def delete_contact(cid):
    execute("DELETE FROM prospecting_contacts WHERE id = ?", [cid])
    return jsonify({'status': 'deleted'})


@prospecting_bp.route('/contacts/<cid>/favorite', methods=['PATCH'])
def toggle_favorite(cid):
    row = fetch_one("SELECT is_favorite FROM prospecting_contacts WHERE id = ?", [cid])
    if not row:
        return jsonify({'error': 'not found'}), 404
    new_val = 0 if row.get('is_favorite') else 1
    execute("UPDATE prospecting_contacts SET is_favorite = ?, updated_at = ? WHERE id = ?",
            [new_val, datetime.utcnow().isoformat(), cid])
    return jsonify({'is_favorite': new_val})


@prospecting_bp.route('/contacts/<cid>/touchpoints', methods=['POST'])
def log_contact_touchpoint(cid):
    contact = fetch_one("SELECT group_id FROM prospecting_contacts WHERE id = ?", [cid])
    if not contact:
        return jsonify({'error': 'contact not found'}), 404
    data = request.get_json(force=True)
    tp_id = new_id()
    now = datetime.utcnow().isoformat()
    execute(
        "INSERT INTO prospecting_touchpoints "
        "(id, contact_id, group_id, property_id, channel, direction, subject, summary, occurred_at, outcome, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [tp_id, cid, contact.get('group_id'), data.get('property_id'),
         data.get('channel', 'email'), data.get('direction', 'outbound'),
         data.get('subject'), data.get('summary'),
         data.get('occurred_at') or now, data.get('outcome'), now]
    )
    execute("UPDATE prospecting_contacts SET last_touch_at = ?, updated_at = ? WHERE id = ?", [now, now, cid])
    if contact.get('group_id'):
        execute("UPDATE capital_groups SET last_touch_at = ?, last_contacted_at = ?, updated_at = ? WHERE id = ?",
                [now, now, now, contact['group_id']])
    return jsonify({'id': tp_id}), 201


@prospecting_bp.route('/contacts/<cid>/touchpoints', methods=['GET'])
def list_contact_touchpoints(cid):
    rows = fetch_all(
        "SELECT * FROM prospecting_touchpoints WHERE contact_id = ? ORDER BY occurred_at DESC LIMIT 200",
        [cid]
    )
    return jsonify({'touchpoints': rows, 'count': len(rows)})


@prospecting_bp.route('/touchpoints/<tp_id>', methods=['PUT'])
def edit_touchpoint(tp_id):
    existing = fetch_one("SELECT * FROM prospecting_touchpoints WHERE id = ?", [tp_id])
    if not existing:
        existing = fetch_one("SELECT * FROM capital_group_touchpoints WHERE id = ?", [tp_id])
        if not existing:
            return jsonify({'error': 'not found'}), 404
        data = request.get_json(force=True)
        sets, params = [], []
        for k in ['type', 'outcome', 'notes', 'contact_id', 'occurred_at']:
            if k in data:
                sets.append(f'{k} = ?')
                params.append(data[k])
        if not sets:
            return jsonify({'error': 'no fields'}), 400
        params.append(tp_id)
        execute(f"UPDATE capital_group_touchpoints SET {', '.join(sets)} WHERE id = ?", params)
        updated = fetch_one("SELECT * FROM capital_group_touchpoints WHERE id = ?", [tp_id])
        return jsonify(updated)

    data = request.get_json(force=True)
    sets, params = [], []
    for k in ['channel', 'direction', 'subject', 'summary', 'occurred_at', 'outcome', 'contact_id']:
        if k in data:
            sets.append(f'{k} = ?')
            params.append(data[k])
    if not sets:
        return jsonify({'error': 'no fields'}), 400
    params.append(tp_id)
    execute(f"UPDATE prospecting_touchpoints SET {', '.join(sets)} WHERE id = ?", params)
    updated = fetch_one("SELECT * FROM prospecting_touchpoints WHERE id = ?", [tp_id])
    return jsonify(updated)


FOLLOWUP_INTERVALS = {
    '1w': 7, '2w': 14, '3w': 21, '1m': 30, '6wk': 42, '2m': 60
}


@prospecting_bp.route('/contacts/<cid>/schedule-followup', methods=['POST'])
def schedule_followup(cid):
    contact = fetch_one("SELECT id, group_id, first_name, last_name FROM prospecting_contacts WHERE id = ?", [cid])
    if not contact:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json(force=True)
    interval = data.get('interval', '2w')
    days = FOLLOWUP_INTERVALS.get(interval, 14)
    due_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    name = ' '.join(filter(None, [contact.get('first_name'), contact.get('last_name')])) or 'contact'
    task_id = new_id()
    execute(
        "INSERT INTO prospecting_tasks (id, capital_group_id, contact_id, type, title, description, "
        "status, priority, due_at, trigger_rule, created_at) "
        "VALUES (?, ?, ?, 'follow_up', ?, ?, 'pending', 6, ?, 'manual_followup', ?)",
        [task_id, contact.get('group_id'), cid,
         f'Follow up with {name}', f'Scheduled {interval} follow-up',
         due_at, datetime.utcnow().isoformat()]
    )
    return jsonify({'task_id': task_id, 'due_at': due_at, 'days': days}), 201


# ---------------------------------------------------------------------------
# CANVAS — portfolio-wide touchpoint aggregation for Relationship Canvas
# ---------------------------------------------------------------------------

@prospecting_bp.route('/canvas-stats', methods=['GET'])
def canvas_stats():
    prosp_cnt = fetch_one("SELECT COUNT(*) AS cnt FROM prospecting_touchpoints", []) or {}
    crm_cnt = fetch_one("SELECT COUNT(*) AS cnt FROM crm_touchpoints", []) or {}
    cg_cnt = fetch_one("SELECT COUNT(*) AS cnt FROM capital_group_touchpoints", []) or {}
    total_touchpoints = prosp_cnt.get('cnt', 0) + crm_cnt.get('cnt', 0) + cg_cnt.get('cnt', 0)
    print(f"[Canvas] total_touchpoints={total_touchpoints} (prospecting={prosp_cnt.get('cnt',0)} crm={crm_cnt.get('cnt',0)} capital_group={cg_cnt.get('cnt',0)})")

    contacts_touched = fetch_one(
        "SELECT COUNT(DISTINCT contact_id) AS cnt FROM prospecting_touchpoints WHERE contact_id IS NOT NULL", []
    )
    groups_engaged = fetch_one(
        "SELECT COUNT(DISTINCT group_id) AS cnt FROM prospecting_touchpoints WHERE group_id IS NOT NULL", []
    )
    replies = fetch_one(
        "SELECT COUNT(*) AS cnt FROM prospecting_touchpoints WHERE direction = 'inbound'", []
    )
    mtgs = fetch_one(
        "SELECT COUNT(*) AS cnt FROM prospecting_touchpoints WHERE channel IN ('meeting', 'call')", []
    )
    last_tp = fetch_one(
        "SELECT occurred_at FROM prospecting_touchpoints ORDER BY occurred_at DESC LIMIT 1", []
    )

    if _is_postgres():
        daily = fetch_all(
            "SELECT TO_CHAR(occurred_at::date, 'YYYY-MM-DD') AS day, COUNT(*) AS cnt "
            "FROM prospecting_touchpoints "
            "WHERE occurred_at >= CURRENT_DATE - INTERVAL '30 days' "
            "GROUP BY occurred_at::date ORDER BY occurred_at::date", []
        )
        channels = fetch_all(
            "SELECT COALESCE(channel, 'other') AS channel, COUNT(*) AS cnt "
            "FROM prospecting_touchpoints "
            "GROUP BY COALESCE(channel, 'other') ORDER BY cnt DESC", []
        )
        weekly = fetch_all(
            "SELECT TO_CHAR(DATE_TRUNC('week', occurred_at::date), 'YYYY-MM-DD') AS week, COUNT(*) AS cnt "
            "FROM prospecting_touchpoints "
            "WHERE occurred_at >= CURRENT_DATE - INTERVAL '56 days' "
            "GROUP BY DATE_TRUNC('week', occurred_at::date) "
            "ORDER BY DATE_TRUNC('week', occurred_at::date)", []
        )
    else:
        daily = fetch_all(
            "SELECT DATE(occurred_at) AS day, COUNT(*) AS cnt "
            "FROM prospecting_touchpoints "
            "WHERE occurred_at >= DATE('now', '-30 days') "
            "GROUP BY DATE(occurred_at) ORDER BY day", []
        )
        channels = fetch_all(
            "SELECT COALESCE(channel, 'other') AS channel, COUNT(*) AS cnt "
            "FROM prospecting_touchpoints "
            "GROUP BY COALESCE(channel, 'other') ORDER BY cnt DESC", []
        )
        weekly = fetch_all(
            "SELECT DATE(occurred_at, 'weekday 0', '-6 days') AS week, COUNT(*) AS cnt "
            "FROM prospecting_touchpoints "
            "WHERE occurred_at >= DATE('now', '-56 days') "
            "GROUP BY DATE(occurred_at, 'weekday 0', '-6 days') ORDER BY week", []
        )

    return jsonify({
        'total_touchpoints': total_touchpoints,
        'contacts_touched': (contacts_touched or {}).get('cnt', 0),
        'groups_engaged': (groups_engaged or {}).get('cnt', 0),
        'replies': (replies or {}).get('cnt', 0),
        'meetings': (mtgs or {}).get('cnt', 0),
        'last_touchpoint_at': (last_tp or {}).get('occurred_at'),
        'daily_activity': daily or [],
        'channel_mix': channels or [],
        'weekly_activity': weekly or []
    })


# ---------------------------------------------------------------------------
# NOTICES — Daily Discovery matches awaiting user action
# ---------------------------------------------------------------------------

@prospecting_bp.route('/notices', methods=['GET'])
def list_notices():
    status = request.args.get('status', 'new')
    rows = fetch_all(
        "SELECT n.*, g.name AS group_name, c.first_name, c.last_name, "
        "s.signal_scope, s.source_url, s.importance "
        "FROM prospecting_notices n "
        "LEFT JOIN capital_groups g ON g.id = n.group_id "
        "LEFT JOIN prospecting_contacts c ON c.id = n.contact_id "
        "LEFT JOIN prospecting_signals s ON s.id = n.signal_id "
        "WHERE n.status = ? ORDER BY n.created_at DESC LIMIT 200",
        [status]
    )
    return jsonify(rows)


@prospecting_bp.route('/notices/<nid>', methods=['PATCH'])
def update_notice(nid):
    data = request.get_json(force=True)
    new_status = data.get('status')
    if new_status not in ('new', 'converted', 'dismissed'):
        return jsonify({'error': 'invalid status'}), 400
    execute("UPDATE prospecting_notices SET status = ? WHERE id = ?", [new_status, nid])
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# RELATIONSHIP-AWARE TASK LIFECYCLE
# ---------------------------------------------------------------------------

@prospecting_bp.route('/tasks/<task_id>', methods=['PATCH'])
def update_task(task_id):
    task = fetch_one("SELECT id, status FROM prospecting_tasks WHERE id = ?", [task_id])
    if not task:
        return jsonify({'error': 'task not found'}), 404
    data = request.get_json(force=True)
    allowed = ['status', 'due_at', 'priority', 'notes', 'channel']
    valid_statuses = ('pending', 'completed', 'snoozed', 'cancelled', 'skipped')
    sets = []
    params = []
    for k in allowed:
        if k in data:
            if k == 'status' and data[k] not in valid_statuses:
                return jsonify({'error': f'invalid status, must be one of {valid_statuses}'}), 400
            sets.append(f'{k} = ?')
            params.append(data[k])
    if not sets:
        return jsonify({'error': 'no updatable fields provided'}), 400
    sets.append("updated_at = CURRENT_TIMESTAMP")
    params.append(task_id)
    execute(f"UPDATE prospecting_tasks SET {', '.join(sets)} WHERE id = ?", params)
    updated = fetch_one("SELECT * FROM prospecting_tasks WHERE id = ?", [task_id])
    return jsonify(updated)


@prospecting_bp.route('/tasks/<task_id>/complete-with-touchpoint', methods=['POST'])
def complete_task_with_touchpoint(task_id):
    data = request.get_json(silent=True) or {}
    result = rule_task_complete(task_id, touchpoint_data=data or None)
    if not result:
        return jsonify({'error': 'task not found'}), 404
    return jsonify(result)


@prospecting_bp.route('/tasks/<task_id>/signalstack-payload', methods=['GET'])
def get_signalstack_payload(task_id):
    payload = build_signalstack_payload(task_id)
    if not payload:
        return jsonify({'error': 'task not found'}), 404
    return jsonify(payload)


@prospecting_bp.route('/signalstack/contact/<cid>', methods=['GET'])
def signalstack_by_contact(cid):
    task = fetch_one(
        "SELECT id FROM prospecting_tasks WHERE contact_id = ? AND status = 'pending' "
        "ORDER BY priority DESC, due_at ASC LIMIT 1",
        [cid]
    )
    if not task:
        return jsonify({'error': 'no pending task for contact'}), 404
    payload = build_signalstack_payload(task['id'])
    if not payload:
        return jsonify({'error': 'payload build failed'}), 404
    return jsonify(payload)


@prospecting_bp.route('/signalstack/group/<gid>', methods=['GET'])
def signalstack_by_group(gid):
    task = fetch_one(
        "SELECT id FROM prospecting_tasks WHERE capital_group_id = ? AND status = 'pending' "
        "ORDER BY priority DESC, due_at ASC LIMIT 1",
        [gid]
    )
    if not task:
        return jsonify({'error': 'no pending task for group'}), 404
    payload = build_signalstack_payload(task['id'])
    if not payload:
        return jsonify({'error': 'payload build failed'}), 404
    return jsonify(payload)


@prospecting_bp.route('/next-best-action', methods=['GET'])
def next_best_action():
    contact_id = request.args.get('contact_id')
    group_id = request.args.get('group_id')
    nba = compute_next_best_action(contact_id=contact_id, group_id=group_id)
    return jsonify(nba or {})


# ---------------------------------------------------------------------------
# SIGNAL INGESTION (manual + industry match)
# ---------------------------------------------------------------------------

@prospecting_bp.route('/signals', methods=['POST'])
def create_signal():
    data = request.get_json(force=True)
    scope = data.get('signal_scope') or 'industry'
    sid = ingest_signal(
        scope=scope, title=data.get('title', ''), summary=data.get('summary', ''),
        source_url=data.get('source_url', ''), signal_type=data.get('signal_type', ''),
        importance=int(data.get('importance', 5)),
        group_id=data.get('group_id'), contact_id=data.get('contact_id'),
        property_id=data.get('property_id'),
        match_types=data.get('match_types'), match_stages=data.get('match_stages')
    )
    if not sid:
        return jsonify({'error': 'signal ingestion failed'}), 400
    return jsonify({'id': sid}), 201


@prospecting_bp.route('/rules/daily', methods=['POST'])
def run_relationship_rules():
    return jsonify(run_daily_rules())


# ---------------------------------------------------------------------------
# PROPERTIES (manual property entry linked to a group)
# ---------------------------------------------------------------------------

@prospecting_bp.route('/properties', methods=['GET'])
def list_properties():
    group_id = request.args.get('group_id', '')
    if group_id:
        rows = fetch_all(
            "SELECT * FROM prospecting_properties WHERE group_id = ? ORDER BY updated_at DESC",
            [group_id]
        )
    else:
        rows = fetch_all("SELECT * FROM prospecting_properties ORDER BY updated_at DESC LIMIT 200")
    return jsonify(rows)


@prospecting_bp.route('/properties', methods=['POST'])
def create_property():
    data = request.get_json(force=True)
    if not data.get('name'):
        return jsonify({'error': 'name required'}), 400
    pid = new_id()
    now = datetime.utcnow().isoformat()
    execute(
        "INSERT INTO prospecting_properties (id, group_id, name, market, state, stage, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [pid, data.get('group_id'), data.get('name'), data.get('market'),
         data.get('state'), data.get('stage'), now, now]
    )
    return jsonify({'id': pid}), 201


@prospecting_bp.route('/engagement', methods=['GET'])
def engagement_data():
    now = datetime.utcnow()
    today_str = now.strftime('%Y-%m-%d')
    day_of_week = now.weekday()  # 0=Mon, 6=Sun

    # Streak: count consecutive WEEKDAYS with at least one touchpoint
    # Weekends (Sat/Sun) are skipped — they don't count and don't break streaks
    streak = 0
    for days_ago in range(0, 180):
        d = now - timedelta(days=days_ago)
        if d.weekday() >= 5:  # Saturday or Sunday — skip
            continue
        row = fetch_one(
            "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ?",
            [d.strftime('%Y-%m-%d')]
        )
        if row and row['cnt'] > 0:
            streak += 1
        else:
            if days_ago == 0 and day_of_week < 5:
                streak = 0
            break

    # Today's touchpoints count
    today_tp = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ?",
        [today_str]
    )
    today_count = today_tp['cnt'] if today_tp else 0

    # Weekly touchpoints: Monday through Sunday of current week
    days_since_monday = day_of_week  # Monday=0 so this is correct
    week_start = (now - timedelta(days=days_since_monday)).strftime('%Y-%m-%d')
    week_end = (now - timedelta(days=days_since_monday) + timedelta(days=6)).strftime('%Y-%m-%d')
    week_tp_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) >= ? AND DATE(occurred_at) <= ?",
        [week_start, week_end]
    )
    week_tp_count = week_tp_row['cnt'] if week_tp_row else 0

    # Weekly goal and pace
    weekly_goal = 40
    # Expected progress: proportional to weekday position (Mon=1/5, Tue=2/5, ..., Fri=5/5)
    # Weekend days don't advance the target
    if day_of_week >= 5:
        expected_pct = 1.0
    else:
        expected_pct = (day_of_week + 1) / 5.0
    expected_count = int(weekly_goal * expected_pct)
    actual_pct = week_tp_count / weekly_goal if weekly_goal > 0 else 0

    if week_tp_count >= expected_count + 3:
        week_pace = 'ahead'
    elif week_tp_count >= expected_count - 3:
        week_pace = 'on_track'
    else:
        week_pace = 'behind'

    # Loss signals: relationships going cold (last_contacted > 45 days, status not dormant/cold)
    cold_rows = fetch_all(
        """SELECT id, name, last_contacted_at, relationship_status, warmth_score
           FROM capital_groups
           WHERE last_contacted_at IS NOT NULL
             AND last_contacted_at < ?
             AND relationship_status NOT IN ('dormant', 'cold')
           ORDER BY last_contacted_at ASC LIMIT 5""",
        [(now - timedelta(days=45)).isoformat()]
    )
    going_cold = []
    for r in cold_rows:
        days_silent = (now - datetime.fromisoformat(str(r['last_contacted_at']).replace('Z', ''))).days
        going_cold.append({
            'id': r['id'], 'name': r['name'],
            'days_silent': days_silent,
            'status': r['relationship_status']
        })

    # Stalled opportunities (opportunity_stage set but no touchpoint in 14+ days)
    stalled_rows = fetch_all(
        """SELECT id, name, opportunity_stage, last_contacted_at
           FROM capital_groups
           WHERE opportunity_stage IS NOT NULL
             AND opportunity_stage NOT IN ('won', 'lost')
             AND (last_contacted_at IS NULL OR last_contacted_at < ?)
           ORDER BY last_contacted_at ASC LIMIT 5""",
        [(now - timedelta(days=14)).isoformat()]
    )
    stalled = [{'id': r['id'], 'name': r['name'], 'stage': r['opportunity_stage']} for r in stalled_rows]

    # Open loops: contacted 2-14 days ago with no follow-up touchpoint since
    open_loop_row = fetch_one(
        """SELECT COUNT(*) as cnt FROM capital_groups
           WHERE last_contacted_at IS NOT NULL
             AND last_contacted_at > ?
             AND last_contacted_at < ?
             AND relationship_status IN ('active', 'warm', 'hot')""",
        [(now - timedelta(days=14)).isoformat(), (now - timedelta(days=2)).isoformat()]
    )
    open_loops = open_loop_row['cnt'] if open_loop_row else 0

    # Momentum: based on activity volume over last 7 days
    week_tp = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE occurred_at > ?",
        [(now - timedelta(days=7)).isoformat()]
    )
    week_count = week_tp['cnt'] if week_tp else 0

    prev_week_tp = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE occurred_at > ? AND occurred_at <= ?",
        [(now - timedelta(days=14)).isoformat(), (now - timedelta(days=7)).isoformat()]
    )
    prev_week_count = prev_week_tp['cnt'] if prev_week_tp else 0

    if week_count >= 15:
        momentum = 'high'
    elif week_count >= 5:
        momentum = 'building'
    else:
        momentum = 'low'

    if prev_week_count > 0 and week_count < prev_week_count * 0.6:
        momentum_trend = 'slipping'
    elif week_count > prev_week_count:
        momentum_trend = 'rising'
    else:
        momentum_trend = 'steady'

    # Daily checklist: count completed types today
    today_followups = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ? AND type IN ('call', 'email', 'follow_up')",
        [today_str]
    )
    today_outreach = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ? AND type IN ('outreach', 'linkedin', 'intro')",
        [today_str]
    )
    today_relationship = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ? AND type IN ('meeting', 'note', 'referral')",
        [today_str]
    )

    daily_checklist = {
        'followups': today_followups['cnt'] if today_followups else 0,
        'outreach': today_outreach['cnt'] if today_outreach else 0,
        'relationship': today_relationship['cnt'] if today_relationship else 0
    }

    remaining_for_pace = max(0, expected_count - week_tp_count)

    return jsonify({
        'streak': streak,
        'today_touchpoints': today_count,
        'going_cold': going_cold,
        'stalled_opportunities': stalled,
        'open_loops': open_loops,
        'momentum': momentum,
        'momentum_trend': momentum_trend,
        'week_touchpoints': week_count,
        'week_tp_count': week_tp_count,
        'weekly_goal': weekly_goal,
        'week_pace': week_pace,
        'week_pct': round(actual_pct * 100),
        'remaining_for_pace': remaining_for_pace,
        'daily_checklist': daily_checklist,
        'expected_count': expected_count
    })


@prospecting_bp.route('/brief', methods=['GET'])
def prospecting_brief():
    """Generate a downloadable Prospecting Brief as printable HTML."""
    now = datetime.utcnow()
    day_of_week = now.weekday()

    # --- Core counts ---
    total_groups_row = fetch_one("SELECT COUNT(*) AS c FROM capital_groups") or {}
    total_groups = total_groups_row.get('c', 0)

    total_contacts_row = fetch_one("SELECT COUNT(*) AS c FROM prospecting_contacts") or {}
    total_contacts = total_contacts_row.get('c', 0)

    total_tp_cg = fetch_one("SELECT COUNT(*) AS c FROM capital_group_touchpoints") or {}
    total_tp_prosp = fetch_one("SELECT COUNT(*) AS c FROM prospecting_touchpoints") or {}
    total_touchpoints = total_tp_cg.get('c', 0) + total_tp_prosp.get('c', 0)

    # --- Relationship breakdown ---
    warm_row = fetch_one("SELECT COUNT(*) AS c FROM capital_groups WHERE relationship_status IN ('warm', 'engaged', 'partner')") or {}
    warm_active = warm_row.get('c', 0)

    prospect_row = fetch_one("SELECT COUNT(*) AS c FROM capital_groups WHERE relationship_status = 'prospect'") or {}
    prospect_count = prospect_row.get('c', 0)

    dormant_row = fetch_one("SELECT COUNT(*) AS c FROM capital_groups WHERE relationship_status IN ('dormant', 'cold')") or {}
    dormant_count = dormant_row.get('c', 0)

    # --- Activity breakdown by type ---
    tp_types = fetch_all(
        "SELECT COALESCE(type, 'other') AS tp_type, COUNT(*) AS cnt "
        "FROM capital_group_touchpoints GROUP BY COALESCE(type, 'other') ORDER BY cnt DESC", []
    ) or []
    type_map = {r['tp_type']: r['cnt'] for r in tp_types}
    calls_count = type_map.get('call', 0)
    meetings_count = type_map.get('meeting', 0)
    emails_count = type_map.get('email', 0)
    linkedin_count = type_map.get('linkedin', 0) + type_map.get('outreach', 0)
    followups_count = type_map.get('follow_up', 0)

    # --- Opportunities ---
    active_opps_row = fetch_one(
        "SELECT COUNT(*) AS c FROM capital_groups WHERE opportunity_stage IS NOT NULL AND opportunity_stage NOT IN ('won', 'lost')"
    ) or {}
    active_opps = active_opps_row.get('c', 0)

    won_opps_row = fetch_one("SELECT COUNT(*) AS c FROM capital_groups WHERE opportunity_stage = 'won'") or {}
    won_opps = won_opps_row.get('c', 0)

    # --- Weekly metrics ---
    days_since_monday = day_of_week
    week_start = (now - timedelta(days=days_since_monday)).strftime('%Y-%m-%d')
    week_end = (now - timedelta(days=days_since_monday) + timedelta(days=6)).strftime('%Y-%m-%d')
    week_tp_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) >= ? AND DATE(occurred_at) <= ?",
        [week_start, week_end]
    )
    week_tp_count = week_tp_row['cnt'] if week_tp_row else 0
    weekly_goal = 40
    if day_of_week >= 5:
        expected_pct = 1.0
    else:
        expected_pct = (day_of_week + 1) / 5.0
    expected_count = int(weekly_goal * expected_pct)
    week_pct = round((week_tp_count / weekly_goal) * 100) if weekly_goal > 0 else 0

    if week_tp_count >= expected_count + 3:
        week_pace = 'Ahead of pace'
    elif week_tp_count >= expected_count - 3:
        week_pace = 'On track'
    else:
        week_pace = 'Behind pace'

    # Streak
    streak = 0
    for days_ago in range(0, 180):
        d = now - timedelta(days=days_ago)
        if d.weekday() >= 5:
            continue
        row = fetch_one(
            "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ?",
            [d.strftime('%Y-%m-%d')]
        )
        if row and row['cnt'] > 0:
            streak += 1
        else:
            if days_ago == 0 and day_of_week < 5:
                streak = 0
            break

    # --- Momentum ---
    week_7d = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE occurred_at > ?",
        [(now - timedelta(days=7)).isoformat()]
    )
    week_7d_count = week_7d['cnt'] if week_7d else 0
    prev_7d = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE occurred_at > ? AND occurred_at <= ?",
        [(now - timedelta(days=14)).isoformat(), (now - timedelta(days=7)).isoformat()]
    )
    prev_7d_count = prev_7d['cnt'] if prev_7d else 0

    if week_7d_count >= 15:
        momentum_label = 'Strong'
        momentum_desc = 'High activity volume with consistent engagement across the pipeline.'
    elif week_7d_count >= 5:
        momentum_label = 'Building'
        momentum_desc = 'Activity is growing. Continued consistency will compound results.'
    else:
        momentum_label = 'Mixed'
        momentum_desc = 'Activity has been lighter than typical. Focus on core daily actions to rebuild cadence.'

    if prev_7d_count > 0 and week_7d_count < prev_7d_count * 0.6:
        momentum_trend = 'Slipping week-over-week'
    elif week_7d_count > prev_7d_count:
        momentum_trend = 'Trending up from prior week'
    else:
        momentum_trend = 'Holding steady'

    # --- Areas to Watch ---
    cold_rows = fetch_all(
        """SELECT name, last_contacted_at FROM capital_groups
           WHERE last_contacted_at IS NOT NULL AND last_contacted_at < ?
             AND relationship_status NOT IN ('dormant', 'cold')
           ORDER BY last_contacted_at ASC LIMIT 5""",
        [(now - timedelta(days=45)).isoformat()]
    ) or []
    going_cold = []
    for r in cold_rows:
        days_s = (now - datetime.fromisoformat(str(r['last_contacted_at']).replace('Z', ''))).days
        going_cold.append({'name': r['name'], 'days': days_s})

    stalled_rows = fetch_all(
        """SELECT name, opportunity_stage FROM capital_groups
           WHERE opportunity_stage IS NOT NULL AND opportunity_stage NOT IN ('won', 'lost')
             AND (last_contacted_at IS NULL OR last_contacted_at < ?)
           ORDER BY last_contacted_at ASC LIMIT 5""",
        [(now - timedelta(days=14)).isoformat()]
    ) or []

    followup_queue_count = fetch_one(
        "SELECT COUNT(*) AS c FROM capital_groups WHERE last_contacted_at IS NULL OR last_contacted_at < ?",
        [(now - timedelta(days=30)).isoformat()]
    ) or {}
    overdue_followups = followup_queue_count.get('c', 0)

    # --- Contacts with real conversations ---
    real_convos_row = fetch_one(
        "SELECT COUNT(DISTINCT contact_id) AS c FROM prospecting_touchpoints "
        "WHERE channel IN ('call', 'meeting', 'conversation') AND contact_id IS NOT NULL"
    ) or {}
    real_convos = real_convos_row.get('c', 0)

    # --- Top highlights ---
    most_active = fetch_all(
        """SELECT g.name, COUNT(t.id) AS cnt FROM capital_group_touchpoints t
           JOIN capital_groups g ON g.id = t.capital_group_id
           WHERE t.occurred_at > ?
           GROUP BY g.id, g.name ORDER BY cnt DESC LIMIT 5""",
        [(now - timedelta(days=30)).isoformat()]
    ) or []

    most_engaged_contacts = fetch_all(
        """SELECT c.first_name, c.last_name, g.name AS group_name, COUNT(t.id) AS cnt
           FROM prospecting_touchpoints t
           JOIN prospecting_contacts c ON c.id = t.contact_id
           LEFT JOIN capital_groups g ON g.id = c.group_id
           WHERE t.occurred_at > ?
           GROUP BY c.id, c.first_name, c.last_name, g.name ORDER BY cnt DESC LIMIT 5""",
        [(now - timedelta(days=30)).isoformat()]
    ) or []

    recent_stage_ups = fetch_all(
        """SELECT name, relationship_status FROM capital_groups
           WHERE relationship_status IN ('warm', 'engaged', 'partner')
             AND updated_at > ?
           ORDER BY updated_at DESC LIMIT 5""",
        [(now - timedelta(days=30)).isoformat()]
    ) or []

    # --- Executive Summary ---
    exec_lines = []
    exec_lines.append(
        f"The prospecting operation is actively managing {total_groups} capital group{'s' if total_groups != 1 else ''} "
        f"with {total_contacts} contact{'s' if total_contacts != 1 else ''} across the pipeline."
    )
    if total_touchpoints > 0:
        exec_lines.append(
            f"A total of {total_touchpoints} touchpoints have been logged, "
            f"including {calls_count} call{'s' if calls_count != 1 else ''} and {meetings_count} meeting{'s' if meetings_count != 1 else ''}."
        )
    if warm_active > 0:
        exec_lines.append(
            f"{warm_active} relationship{'s' if warm_active != 1 else ''} {'are' if warm_active != 1 else 'is'} "
            f"at warm or active status, reflecting sustained engagement effort."
        )
    if active_opps > 0:
        exec_lines.append(f"{active_opps} active opportunit{'ies' if active_opps != 1 else 'y'} {'are' if active_opps != 1 else 'is'} in the pipeline.")
    exec_summary = ' '.join(exec_lines)

    # --- Opportunities to Accelerate ---
    accelerators = []
    if dormant_count > 0:
        accelerators.append(f"Re-engage {dormant_count} dormant relationship{'s' if dormant_count != 1 else ''} to recover pipeline coverage.")
    if overdue_followups > 5:
        accelerators.append(f"Address the {overdue_followups} groups overdue for follow-up to prevent relationship decay.")
    if linkedin_count < calls_count and linkedin_count < 5:
        accelerators.append("Increase LinkedIn activity to diversify outreach channels.")
    if real_convos < total_contacts * 0.3 and total_contacts > 5:
        accelerators.append(f"Only {real_convos} of {total_contacts} contacts have had a real conversation. "
                            "Prioritize converting initial outreach into calls or meetings.")
    if week_7d_count < 10:
        accelerators.append("Boost daily activity volume to sustain momentum above the 10-per-week baseline.")

    # --- Build HTML ---
    generated = now.strftime('%B %d, %Y at %I:%M %p UTC')
    week_label = f"Week of {(now - timedelta(days=days_since_monday)).strftime('%b %d')} – {(now - timedelta(days=days_since_monday) + timedelta(days=6)).strftime('%b %d, %Y')}"

    bar_color = '#10b981' if week_pct >= 100 else ('#f59e0b' if week_pace == 'Behind pace' else '#3b82f6')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prospecting Brief — {now.strftime('%b %d, %Y')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; color: #1e293b; background: #fff; line-height: 1.6; padding: 2rem; max-width: 820px; margin: 0 auto; }}
  @media print {{ body {{ padding: 0.5in; max-width: none; }} .no-print {{ display: none !important; }} }}
  .header {{ text-align: center; margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 2px solid #e2e8f0; }}
  .header h1 {{ font-size: 1.6rem; font-weight: 700; color: #0f172a; letter-spacing: 0.02em; margin-bottom: 0.25rem; }}
  .header .sub {{ font-size: 0.8rem; color: #64748b; }}
  .section {{ margin-bottom: 1.5rem; }}
  .section-title {{ font-size: 0.85rem; font-weight: 700; color: #0f172a; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.6rem; padding-bottom: 0.35rem; border-bottom: 1px solid #e2e8f0; }}
  .exec-summary {{ font-size: 0.88rem; color: #334155; line-height: 1.7; padding: 0.75rem 1rem; background: #f8fafc; border-radius: 0.5rem; border-left: 3px solid #3b82f6; }}
  .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; }}
  .metric-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 0.75rem; text-align: center; }}
  .metric-card .value {{ font-size: 1.4rem; font-weight: 700; color: #0f172a; line-height: 1.2; }}
  .metric-card .label {{ font-size: 0.68rem; color: #64748b; font-weight: 500; margin-top: 0.15rem; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
  .list-item {{ display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0; border-bottom: 1px solid #f1f5f9; font-size: 0.8rem; }}
  .list-item:last-child {{ border-bottom: none; }}
  .list-item .name {{ color: #334155; font-weight: 500; }}
  .list-item .badge {{ color: #64748b; font-size: 0.72rem; }}
  .progress-container {{ background: #e2e8f0; border-radius: 4px; height: 8px; overflow: hidden; margin: 0.5rem 0; }}
  .progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
  .status-pill {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; }}
  .callout {{ padding: 0.65rem 0.85rem; border-radius: 0.5rem; font-size: 0.8rem; margin-bottom: 0.5rem; }}
  .callout-blue {{ background: #eff6ff; border-left: 3px solid #3b82f6; color: #1e40af; }}
  .callout-amber {{ background: #fffbeb; border-left: 3px solid #f59e0b; color: #92400e; }}
  .callout-green {{ background: #f0fdf4; border-left: 3px solid #10b981; color: #065f46; }}
  .callout-red {{ background: #fef2f2; border-left: 3px solid #ef4444; color: #991b1b; }}
  .toolbar {{ text-align: center; margin-bottom: 1.5rem; }}
  .toolbar button {{ padding: 0.5rem 1.25rem; font-size: 0.8rem; font-weight: 600; border: 1px solid #e2e8f0; border-radius: 0.4rem; cursor: pointer; background: #0f172a; color: #fff; font-family: inherit; }}
  .toolbar button:hover {{ background: #1e293b; }}
  .footer {{ text-align: center; padding-top: 1.5rem; margin-top: 2rem; border-top: 1px solid #e2e8f0; font-size: 0.7rem; color: #94a3b8; }}
</style>
</head>
<body>

<div class="toolbar no-print">
  <button onclick="window.print()">Print / Save as PDF</button>
</div>

<div class="header">
  <h1>Prospecting Brief</h1>
  <div class="sub">BTR Prospecting &middot; Generated {generated}</div>
  <div class="sub" style="margin-top:0.15rem">{week_label}</div>
</div>

<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="exec-summary">{exec_summary}</div>
</div>

<div class="section">
  <div class="section-title">Core Metrics</div>
  <div class="metrics-grid">
    <div class="metric-card"><div class="value">{total_groups}</div><div class="label">Capital Groups</div></div>
    <div class="metric-card"><div class="value">{total_contacts}</div><div class="label">Contacts</div></div>
    <div class="metric-card"><div class="value">{total_touchpoints}</div><div class="label">Total Touchpoints</div></div>
    <div class="metric-card"><div class="value">{week_tp_count}</div><div class="label">This Week</div></div>
    <div class="metric-card"><div class="value">{calls_count}</div><div class="label">Calls</div></div>
    <div class="metric-card"><div class="value">{meetings_count}</div><div class="label">Meetings</div></div>
    <div class="metric-card"><div class="value">{warm_active}</div><div class="label">Active Relationships</div></div>
    <div class="metric-card"><div class="value">{active_opps}</div><div class="label">Active Opportunities</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">Pipeline Health</div>
  <div class="two-col">
    <div>
      <div class="list-item"><span class="name">Groups actively managed</span><span class="badge" style="font-weight:700;color:#0f172a">{total_groups}</span></div>
      <div class="list-item"><span class="name">Contacts with conversations</span><span class="badge" style="font-weight:700;color:#0f172a">{real_convos}</span></div>
      <div class="list-item"><span class="name">Warm / active relationships</span><span class="badge" style="font-weight:700;color:#10b981">{warm_active}</span></div>
      <div class="list-item"><span class="name">Prospects in pipeline</span><span class="badge" style="font-weight:700;color:#3b82f6">{prospect_count}</span></div>
    </div>
    <div>
      <div class="list-item"><span class="name">Dormant / cold</span><span class="badge" style="font-weight:700;color:#94a3b8">{dormant_count}</span></div>
      <div class="list-item"><span class="name">Overdue for follow-up</span><span class="badge" style="font-weight:700;color:#f59e0b">{overdue_followups}</span></div>
      <div class="list-item"><span class="name">Active opportunities</span><span class="badge" style="font-weight:700;color:#6366f1">{active_opps}</span></div>
      <div class="list-item"><span class="name">Won opportunities</span><span class="badge" style="font-weight:700;color:#10b981">{won_opps}</span></div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Activity Breakdown</div>
  <div class="metrics-grid" style="grid-template-columns: repeat(5, 1fr);">
    <div class="metric-card"><div class="value">{calls_count}</div><div class="label">Calls</div></div>
    <div class="metric-card"><div class="value">{meetings_count}</div><div class="label">Meetings</div></div>
    <div class="metric-card"><div class="value">{emails_count}</div><div class="label">Emails</div></div>
    <div class="metric-card"><div class="value">{linkedin_count}</div><div class="label">LinkedIn</div></div>
    <div class="metric-card"><div class="value">{followups_count}</div><div class="label">Follow-ups</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">Weekly Progress</div>
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:0.4rem">
    <span style="font-size:1.1rem;font-weight:700">{week_tp_count} / {weekly_goal}</span>
    <span class="status-pill" style="background:{'#f0fdf4' if week_pace == 'Ahead of pace' else '#eff6ff' if week_pace == 'On track' else '#fef3c7'};color:{'#065f46' if week_pace == 'Ahead of pace' else '#1e40af' if week_pace == 'On track' else '#92400e'}">{week_pace}</span>
  </div>
  <div class="progress-container">
    <div class="progress-fill" style="width:{min(week_pct, 100)}%;background:{bar_color}"></div>
  </div>
  <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:#64748b;margin-top:0.25rem">
    <span>{week_pct}% of weekly goal</span>
    <span>{'Streak: ' + str(streak) + ' day' + ('s' if streak != 1 else '') if streak > 0 else 'No active streak'}</span>
  </div>
</div>

<div class="section">
  <div class="section-title">Momentum</div>
  <div class="callout {'callout-green' if momentum_label == 'Strong' else 'callout-blue' if momentum_label == 'Building' else 'callout-amber'}">
    <strong>{momentum_label}</strong> &mdash; {momentum_desc}<br>
    <span style="font-size:0.75rem">{momentum_trend} &middot; {week_7d_count} touchpoints in the last 7 days (prior 7 days: {prev_7d_count})</span>
  </div>
</div>"""

    # Areas to Watch
    watch_items = []
    if going_cold:
        names = ', '.join([g['name'] + ' (' + str(g['days']) + 'd)' for g in going_cold[:3]])
        watch_items.append(f"Relationships going cold: {names}")
    if stalled_rows:
        names = ', '.join([s['name'] for s in stalled_rows[:3]])
        watch_items.append(f"Stalled opportunities: {names}")
    if overdue_followups > 5:
        watch_items.append(f"{overdue_followups} groups are overdue for follow-up (30+ days since last touch)")
    if week_7d_count < prev_7d_count * 0.6 and prev_7d_count > 0:
        watch_items.append(f"Activity volume dropped from {prev_7d_count} to {week_7d_count} touchpoints week-over-week")

    if watch_items:
        html += '\n<div class="section">\n  <div class="section-title">Areas to Watch</div>\n'
        for item in watch_items:
            html += f'  <div class="callout callout-amber" style="margin-bottom:0.4rem">{item}</div>\n'
        html += '</div>\n'

    # Opportunities to Accelerate
    if accelerators:
        html += '\n<div class="section">\n  <div class="section-title">Opportunities to Accelerate</div>\n'
        for acc in accelerators:
            html += f'  <div class="callout callout-blue" style="margin-bottom:0.4rem">{acc}</div>\n'
        html += '</div>\n'

    # Top Highlights
    html += '\n<div class="section">\n  <div class="section-title">Top Highlights</div>\n  <div class="two-col">\n'

    # Most active groups
    html += '    <div>\n      <div style="font-size:0.72rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.4rem">Most Active Groups (30d)</div>\n'
    if most_active:
        for g in most_active:
            html += f'      <div class="list-item"><span class="name">{g["name"]}</span><span class="badge">{g["cnt"]} touchpoints</span></div>\n'
    else:
        html += '      <div style="font-size:0.78rem;color:#94a3b8">No group activity in the last 30 days</div>\n'
    html += '    </div>\n'

    # Most engaged contacts
    html += '    <div>\n      <div style="font-size:0.72rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.4rem">Most Engaged Contacts (30d)</div>\n'
    if most_engaged_contacts:
        for c in most_engaged_contacts:
            cname = ((c.get('first_name') or '') + ' ' + (c.get('last_name') or '')).strip() or 'Unnamed'
            gname = c.get('group_name') or ''
            html += f'      <div class="list-item"><span class="name">{cname}{" — " + gname if gname else ""}</span><span class="badge">{c["cnt"]} touches</span></div>\n'
    else:
        html += '      <div style="font-size:0.78rem;color:#94a3b8">No contact activity in the last 30 days</div>\n'
    html += '    </div>\n  </div>\n'

    # Recent relationship progress
    if recent_stage_ups:
        html += '  <div style="margin-top:0.75rem"><div style="font-size:0.72rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.4rem">Recent Relationship Progress</div>\n'
        for r in recent_stage_ups:
            status_label = {'warm': 'Warm', 'engaged': 'Engaged', 'partner': 'Partner'}.get(r['relationship_status'], r['relationship_status'])
            html += f'    <div class="list-item"><span class="name">{r["name"]}</span><span class="status-pill" style="background:#f0fdf4;color:#065f46">{status_label}</span></div>\n'
        html += '  </div>\n'

    html += '</div>\n'

    html += f"""
<div class="footer">
  BTR Prospecting &middot; Confidential &middot; {now.strftime('%Y')}
</div>
</body>
</html>"""

    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp
