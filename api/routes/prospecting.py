"""
API Routes: Prospecting Dashboard

Exposes the task engine data for the Prospecting page tabs:
Summary, Schedule, Feed, Groups, Sequences.
"""
from flask import Blueprint, request, jsonify

from services.task_engine import (
    get_summary_stats, get_task_buckets, get_schedule,
    get_groups_list, get_sequences_list, get_feed,
    complete_task, run_daily_scheduler,
    rule_new_group, rule_meeting_followup, rule_proposal_followup,
    rule_signal
)
from shared.database import fetch_all, fetch_one, execute, new_id

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
    where = ["status = ?"]
    params = [status]
    if group_id:
        where.append("capital_group_id = ?")
        params.append(group_id)
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
