"""
API Routes: Prospecting Dashboard

Exposes the task engine data for the Prospecting page tabs:
Summary, Schedule, Feed, Groups, Sequences.
"""
from flask import Blueprint, request, jsonify

from datetime import datetime

from services.task_engine import (
    get_summary_stats, get_task_buckets, get_schedule,
    get_groups_list, get_sequences_list, get_feed,
    complete_task, run_daily_scheduler,
    rule_new_group, rule_meeting_followup, rule_proposal_followup,
    rule_signal
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
        "ORDER BY COALESCE(c.last_touch_at, c.first_reached_out_at, c.created_at) DESC",
        params
    )
    for r in rows:
        r['next_best_action'] = compute_next_best_action(contact_id=r['id'])
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
               'first_reached_out_at', 'last_touch_at', 'relationship_stage', 'owner_user_id', 'notes']
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


# ---------------------------------------------------------------------------
# CANVAS — portfolio-wide touchpoint aggregation for Relationship Canvas
# ---------------------------------------------------------------------------

@prospecting_bp.route('/canvas-stats', methods=['GET'])
def canvas_stats():
    total = fetch_one(
        "SELECT COUNT(*) AS cnt FROM prospecting_touchpoints", []
    )
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
        'total_touchpoints': (total or {}).get('cnt', 0),
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
