"""
Prospecting Task Engine

Generates tasks from relationship data using 8 trigger rules,
computes next-best-action per group, and provides the daily schedule.
"""
import json
from datetime import datetime, timedelta
from shared.database import fetch_all, fetch_one, execute, new_id


def _now():
    return datetime.utcnow()


def _iso(dt):
    return dt.isoformat() if dt else None


def _has_open_task(capital_group_id, trigger_rule):
    row = fetch_one(
        "SELECT id FROM prospecting_tasks "
        "WHERE capital_group_id = ? AND trigger_rule = ? AND status IN ('pending', 'in_progress')",
        [capital_group_id, trigger_rule]
    )
    return row is not None


def _create_task(capital_group_id, task_type, title, description, due_at, trigger_rule, priority=5, enrollment_id=None):
    if capital_group_id and _has_open_task(capital_group_id, trigger_rule):
        return None
    tid = new_id()
    execute(
        "INSERT INTO prospecting_tasks (id, capital_group_id, type, title, description, status, priority, due_at, trigger_rule, enrollment_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
        [tid, capital_group_id, task_type, title, description, priority, _iso(due_at), trigger_rule, enrollment_id, _iso(_now())]
    )
    return tid


def _log_feed(capital_group_id, feed_type, action, detail=None):
    execute(
        "INSERT INTO prospecting_feed (id, capital_group_id, type, action, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [new_id(), capital_group_id, feed_type, action, detail, _iso(_now())]
    )


# ── Rule 1: New group created → research + LinkedIn touch ────────────
def rule_new_group(capital_group_id, group_name):
    now = _now()
    _create_task(capital_group_id, 'research', f'Research {group_name}',
                 f'Pull background intel on {group_name} — strategy, markets, recent deals.',
                 now + timedelta(days=1), 'new_group_research', priority=7)
    _create_task(capital_group_id, 'linkedin', f'Initial LinkedIn touch — {group_name}',
                 f'Send connection request or intro message to key contact at {group_name}.',
                 now + timedelta(days=2), 'new_group_linkedin', priority=6)
    _log_feed(capital_group_id, 'group_added', 'New group added', f'{group_name} added to prospecting pipeline')


# ── Rule 2: No touch 30 days → check-in task ─────────────────────────
def rule_stale_30d(groups):
    now = _now()
    threshold = now - timedelta(days=30)
    for g in groups:
        last = g.get('last_contacted_at')
        if last and last < threshold.isoformat():
            _create_task(g['id'], 'check_in', f'30-day check-in — {g["name"]}',
                         f'No touchpoint logged in 30+ days. Schedule a brief check-in.',
                         now + timedelta(days=1), 'stale_30d', priority=6)


# ── Rule 3: No touch 60 days → reconnect call ────────────────────────
def rule_stale_60d(groups):
    now = _now()
    threshold = now - timedelta(days=60)
    for g in groups:
        last = g.get('last_contacted_at')
        if last and last < threshold.isoformat():
            _create_task(g['id'], 'call', f'Reconnect call — {g["name"]}',
                         f'No activity in 60+ days. Re-engage with a direct call.',
                         now, 'stale_60d', priority=8)


# ── Rule 4: New high-priority signal → signal review + outreach ──────
def rule_signal(capital_group_id, group_name, signal_detail):
    now = _now()
    _create_task(capital_group_id, 'research', f'Signal review — {group_name}',
                 f'New market signal: {signal_detail}',
                 now + timedelta(hours=4), 'signal_review', priority=8)
    _create_task(capital_group_id, 'email', f'Signal outreach — {group_name}',
                 f'Share signal with contact: {signal_detail}',
                 now + timedelta(days=1), 'signal_outreach', priority=7)
    _log_feed(capital_group_id, 'signal', 'Market signal detected', signal_detail)


# ── Rule 5: Meeting logged → follow-up task due 24h ──────────────────
def rule_meeting_followup(capital_group_id, group_name, meeting_notes=''):
    now = _now()
    _create_task(capital_group_id, 'follow_up', f'Meeting follow-up — {group_name}',
                 f'Follow up from meeting. {meeting_notes}'.strip(),
                 now + timedelta(hours=24), 'meeting_followup', priority=7)
    _log_feed(capital_group_id, 'touchpoint', 'Meeting completed', meeting_notes or f'Meeting with {group_name}')


# ── Rule 6: Proposal/coverage discussion → follow-up 3 days ─────────
def rule_proposal_followup(capital_group_id, group_name, proposal_detail=''):
    now = _now()
    _create_task(capital_group_id, 'follow_up', f'Proposal follow-up — {group_name}',
                 f'Check in on proposal/coverage discussion. {proposal_detail}'.strip(),
                 now + timedelta(days=3), 'proposal_followup', priority=6)


# ── Rule 7: Active sequence with due step → sequence_step task ───────
def rule_sequence_steps():
    now = _now()
    enrollments = fetch_all(
        "SELECT e.id, e.sequence_id, e.capital_group_id, e.current_step, e.last_step_at, "
        "s.name AS seq_name, s.total_steps, s.step_definitions, g.name AS group_name "
        "FROM prospecting_enrollments e "
        "JOIN prospecting_sequences s ON s.id = e.sequence_id "
        "JOIN capital_groups g ON g.id = e.capital_group_id "
        "WHERE e.status = 'active'"
    )
    for e in enrollments:
        last = e.get('last_step_at') or e.get('enrolled_at')
        if not last:
            continue
        try:
            last_dt = datetime.fromisoformat(last)
        except (ValueError, TypeError):
            continue
        if last_dt + timedelta(days=3) <= now and e['current_step'] <= e['total_steps']:
            steps = []
            try:
                steps = json.loads(e.get('step_definitions') or '[]')
            except (json.JSONDecodeError, TypeError):
                pass
            step_label = steps[e['current_step'] - 1] if steps and len(steps) >= e['current_step'] else f"Step {e['current_step']}"
            _create_task(
                e['capital_group_id'], 'sequence_step',
                f"{e['seq_name']} — {step_label}",
                f"Sequence step {e['current_step']}/{e['total_steps']} for {e['group_name']}",
                now, 'sequence_step', priority=5, enrollment_id=e['id']
            )


# ── Rule 8: Active property with no recent touch → relationship task ─
def rule_property_touchpoints():
    now = _now()
    threshold = (now - timedelta(days=21)).isoformat()
    groups_with_props = fetch_all(
        "SELECT g.id, g.name, COUNT(p.id) AS prop_count, MAX(t.occurred_at) AS last_touch "
        "FROM capital_groups g "
        "JOIN li_projects p ON p.capital_group_id = g.id "
        "LEFT JOIN capital_group_touchpoints t ON t.capital_group_id = g.id "
        "GROUP BY g.id, g.name "
        "HAVING prop_count > 0"
    )
    for gp in groups_with_props:
        lt = gp.get('last_touch')
        if not lt or lt < threshold:
            _create_task(gp['id'], 'check_in', f'Property relationship touch — {gp["name"]}',
                         f'{gp["name"]} has {gp["prop_count"]} linked properties but no recent touchpoint.',
                         now + timedelta(days=1), 'property_touch', priority=5)


# ── Daily scheduler: run all time-based rules ────────────────────────
def run_daily_scheduler():
    groups = fetch_all("SELECT id, name, last_contacted_at FROM capital_groups")
    rule_stale_30d(groups)
    rule_stale_60d(groups)
    rule_sequence_steps()
    rule_property_touchpoints()
    return {'rules_checked': 4, 'groups_scanned': len(groups)}


# ── Next-best-action: ranked task list per group ─────────────────────
def get_next_best_action(capital_group_id):
    tasks = fetch_all(
        "SELECT id, type, title, priority, due_at FROM prospecting_tasks "
        "WHERE capital_group_id = ? AND status = 'pending' "
        "ORDER BY priority DESC, due_at ASC LIMIT 1",
        [capital_group_id]
    )
    return tasks[0] if tasks else None


# ── Dashboard aggregation queries ────────────────────────────────────

def get_summary_stats():
    now = _now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    today_end = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).isoformat()

    total_groups = fetch_one("SELECT COUNT(*) AS c FROM capital_groups") or {}
    warm = fetch_one("SELECT COUNT(*) AS c FROM capital_groups WHERE warmth_score >= 5") or {}
    due_today = fetch_one(
        "SELECT COUNT(*) AS c FROM prospecting_tasks WHERE status = 'pending' AND due_at >= ? AND due_at < ?",
        [today_start, today_end]
    ) or {}
    overdue = fetch_one(
        "SELECT COUNT(*) AS c FROM prospecting_tasks WHERE status = 'pending' AND due_at < ?",
        [today_start]
    ) or {}
    threshold_30 = (now - timedelta(days=30)).isoformat()
    inactive = fetch_one(
        "SELECT COUNT(*) AS c FROM capital_groups WHERE last_contacted_at IS NOT NULL AND last_contacted_at < ?",
        [threshold_30]
    ) or {}
    no_contact = fetch_one(
        "SELECT COUNT(*) AS c FROM capital_groups WHERE last_contacted_at IS NULL"
    ) or {}
    active_seqs = fetch_one(
        "SELECT COUNT(*) AS c FROM prospecting_sequences WHERE status = 'active'"
    ) or {}

    return [
        {'label': 'Active Groups', 'value': total_groups.get('c', 0), 'accent': '#34d399', 'sub': 'total tracked'},
        {'label': 'Warm Relationships', 'value': warm.get('c', 0), 'accent': '#22d3ee', 'sub': 'warmth \u2265 5'},
        {'label': 'Due Today', 'value': due_today.get('c', 0), 'accent': '#fbbf24', 'sub': 'tasks pending'},
        {'label': 'Overdue', 'value': overdue.get('c', 0), 'accent': '#ef4444', 'sub': 'needs attention'},
        {'label': 'Inactive 30d+', 'value': (inactive.get('c', 0) + no_contact.get('c', 0)), 'accent': '#a78bfa', 'sub': 'no recent touch'},
        {'label': 'Active Campaigns', 'value': active_seqs.get('c', 0), 'accent': '#60a5fa', 'sub': 'live sequences'},
    ]


def get_task_buckets():
    now = _now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    today_end = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).isoformat()
    week_end = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=7)).isoformat()

    type_keys = ['linkedin', 'email', 'call', 'meeting', 'research', 'check_in', 'follow_up', 'sequence_step']

    def bucket_counts(where_clause, params):
        total_row = fetch_one(f"SELECT COUNT(*) AS c FROM prospecting_tasks WHERE status = 'pending' AND {where_clause}", params) or {}
        total = total_row.get('c', 0)
        counts = {}
        for tk in type_keys:
            r = fetch_one(f"SELECT COUNT(*) AS c FROM prospecting_tasks WHERE status = 'pending' AND type = ? AND {where_clause}", [tk] + params) or {}
            counts[tk] = r.get('c', 0)
        return {'total': total, 'counts': counts}

    today = bucket_counts("due_at >= ? AND due_at < ?", [today_start, today_end])
    overdue = bucket_counts("due_at < ?", [today_start])
    week = bucket_counts("due_at >= ? AND due_at < ?", [today_start, week_end])

    return [
        {'id': 'today', 'title': 'Due Today', 'accent': '#fbbf24', **today},
        {'id': 'overdue', 'title': 'Overdue', 'accent': '#ef4444', **overdue},
        {'id': 'week', 'title': 'This Week', 'accent': '#60a5fa', **week},
    ]


def get_schedule(days=5):
    now = _now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    result = []
    day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    for offset in range(days):
        day_dt = today_start + timedelta(days=offset)
        day_end = day_dt + timedelta(days=1)
        label = 'Today' if offset == 0 else 'Tomorrow' if offset == 1 else day_dt.strftime('%a, %b %d')
        date_str = day_dt.strftime('%a, %b %d') if offset <= 1 else ''

        tasks = fetch_all(
            "SELECT t.id, t.type, t.title, t.due_at, t.description, g.name AS group_name "
            "FROM prospecting_tasks t "
            "LEFT JOIN capital_groups g ON g.id = t.capital_group_id "
            "WHERE t.status = 'pending' AND t.due_at >= ? AND t.due_at < ? "
            "ORDER BY t.due_at ASC",
            [day_dt.isoformat(), day_end.isoformat()]
        )
        items = []
        for tk in tasks:
            due = tk.get('due_at', '')
            try:
                time_str = datetime.fromisoformat(due).strftime('%-I:%M %p') if due else '--'
            except (ValueError, TypeError):
                time_str = '--'
            items.append({
                'id': tk['id'],
                'time': time_str,
                'type': tk['type'],
                'title': tk['title'],
                'group': tk.get('group_name') or '\u2014',
                'duration': '\u2014'
            })

        if items:
            result.append({
                'id': f'd{offset}',
                'day': label,
                'date': date_str,
                'items': items
            })
    return result


def get_groups_list(search='', type_filter='', status_filter='', sort_by='warmth'):
    where_parts = ["1=1"]
    params = []
    if search:
        where_parts.append("LOWER(name) LIKE ?")
        params.append(f'%{search.lower()}%')
    if type_filter:
        where_parts.append("type = ?")
        params.append(type_filter)
    if status_filter:
        where_parts.append("relationship_status = ?")
        params.append(status_filter)

    order = 'warmth_score DESC'
    if sort_by == 'name':
        order = 'name ASC'

    where_sql = ' AND '.join(where_parts)
    groups = fetch_all(
        f"SELECT id, name, type, markets, relationship_status, warmth_score, last_contacted_at "
        f"FROM capital_groups WHERE {where_sql} ORDER BY {order}",
        params
    )

    now = _now()

    followup_map = {}
    for fq in get_followup_queue(limit=30):
        followup_map[fq['capital_group_id']] = fq['label']

    result = []
    for g in groups:
        markets = []
        try:
            markets = json.loads(g.get('markets') or '[]')
        except (json.JSONDecodeError, TypeError):
            if g.get('markets'):
                markets = [g['markets']]

        props = fetch_one(
            "SELECT COUNT(*) AS c FROM li_projects WHERE capital_group_id = ?", [g['id']]
        ) or {}

        last_touch = g.get('last_contacted_at')
        if last_touch:
            try:
                lt_dt = datetime.fromisoformat(last_touch)
                delta = (now - lt_dt).days
                if delta == 0:
                    lt_label = 'today'
                elif delta == 1:
                    lt_label = 'yesterday'
                else:
                    lt_label = f'{delta}d ago'
            except (ValueError, TypeError):
                lt_label = 'unknown'
        else:
            lt_label = 'never'

        if g['id'] in followup_map:
            next_action = followup_map[g['id']]
        else:
            nba = get_next_best_action(g['id'])
            if nba and not nba['title'].startswith('Research '):
                next_action = nba['title']
            else:
                next_action = 'No pending tasks'

        result.append({
            'id': g['id'],
            'name': g['name'],
            'type': g.get('type', 'developer'),
            'markets': markets,
            'status': g.get('relationship_status', 'prospect'),
            'warmth': g.get('warmth_score', 1),
            'lastTouch': lt_label,
            'communities': props.get('c', 0),
            'nextAction': next_action
        })
    return result


def get_sequences_list():
    seqs = fetch_all("SELECT * FROM prospecting_sequences ORDER BY status ASC, updated_at DESC")
    result = []
    for s in seqs:
        enrolled = fetch_one(
            "SELECT COUNT(*) AS c FROM prospecting_enrollments WHERE sequence_id = ? AND status = 'active'",
            [s['id']]
        ) or {}
        avg_step = fetch_one(
            "SELECT AVG(current_step) AS avg_s FROM prospecting_enrollments WHERE sequence_id = ? AND status = 'active'",
            [s['id']]
        ) or {}

        result.append({
            'id': s['id'],
            'name': s['name'],
            'status': s.get('status', 'draft'),
            'enrolled': enrolled.get('c', 0),
            'step': round(avg_step.get('avg_s') or 0),
            'totalSteps': s.get('total_steps', 0),
            'responseRate': 0,
            'meetings': 0,
            'lastUpdated': s.get('updated_at', ''),
            'description': s.get('description', '')
        })
    return result


def get_feed(type_filter='', limit=50):
    where = "1=1"
    params = []
    if type_filter:
        where = "type = ?"
        params.append(type_filter)
    params.append(limit)

    rows = fetch_all(
        f"SELECT id, capital_group_id, type, action, detail, created_at "
        f"FROM prospecting_feed WHERE {where} ORDER BY created_at DESC LIMIT ?",
        params
    )
    result = []
    for r in rows:
        group_name = ''
        if r.get('capital_group_id'):
            g = fetch_one("SELECT name FROM capital_groups WHERE id = ?", [r['capital_group_id']])
            group_name = g['name'] if g else ''

        ts_label = ''
        if r.get('created_at'):
            try:
                created = datetime.fromisoformat(r['created_at'])
                delta = _now() - created
                if delta.total_seconds() < 3600:
                    ts_label = f'{int(delta.total_seconds() / 60)} min ago'
                elif delta.total_seconds() < 86400:
                    ts_label = f'{int(delta.total_seconds() / 3600)} hr ago'
                elif delta.days == 1:
                    ts_label = 'yesterday'
                else:
                    ts_label = f'{delta.days}d ago'
            except (ValueError, TypeError):
                ts_label = r['created_at']

        result.append({
            'id': r['id'],
            'type': r['type'],
            'action': r['action'],
            'group': group_name,
            'detail': r.get('detail', ''),
            'ts': ts_label
        })
    return result


def get_todays_focus(limit=10):
    now = _now()
    today_end = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).isoformat()

    rows = fetch_all(
        "SELECT t.id, t.type, t.title, t.description, t.priority, t.due_at, "
        "t.trigger_rule, t.capital_group_id, t.contact_id, t.signal_id, "
        "t.generated_reason, t.next_best_action_type, t.channel, "
        "g.name AS group_name, "
        "c.first_name AS contact_first, c.last_name AS contact_last, "
        "s.title AS signal_title, s.signal_type, s.summary AS signal_summary, "
        "s.source_url AS signal_source_url "
        "FROM prospecting_tasks t "
        "LEFT JOIN capital_groups g ON g.id = t.capital_group_id "
        "LEFT JOIN prospecting_contacts c ON c.id = t.contact_id "
        "LEFT JOIN prospecting_signals s ON s.id = t.signal_id "
        "WHERE t.status = 'pending' AND (t.due_at <= ? OR t.next_best_action_type IS NOT NULL) "
        "ORDER BY "
        "CASE t.next_best_action_type "
        "WHEN 'signal_company' THEN 1 "
        "WHEN 'signal_industry' THEN 2 "
        "WHEN 'overdue_followup' THEN 3 "
        "WHEN 'stale_checkin' THEN 4 "
        "WHEN 'initial_outreach' THEN 5 "
        "ELSE 6 END, "
        "t.priority DESC, t.due_at ASC "
        "LIMIT ?",
        [today_end, limit]
    )

    result = []
    seen_groups = set()
    for r in rows:
        contact_name = ' '.join(filter(None, [r.get('contact_first'), r.get('contact_last')])) or None
        if r.get('capital_group_id'):
            seen_groups.add(r['capital_group_id'])
        result.append({
            'id': r['id'],
            'type': r['type'],
            'title': r['title'],
            'description': r.get('description'),
            'priority': r.get('priority', 5),
            'due_at': r.get('due_at'),
            'channel': r.get('channel'),
            'group_name': r.get('group_name'),
            'contact_name': contact_name,
            'contact_id': r.get('contact_id'),
            'capital_group_id': r.get('capital_group_id'),
            'signal_id': r.get('signal_id'),
            'signal_title': r.get('signal_title'),
            'signal_type': r.get('signal_type'),
            'signal_summary': r.get('signal_summary'),
            'signal_source_url': r.get('signal_source_url'),
            'nba_type': r.get('next_best_action_type'),
            'reason': r.get('generated_reason'),
            'trigger_rule': r.get('trigger_rule'),
        })

    if len(result) < limit:
        for fq in get_followup_queue(limit=30):
            if len(result) >= limit:
                break
            if fq['capital_group_id'] in seen_groups:
                continue
            seen_groups.add(fq['capital_group_id'])
            days = fq['days_inactive']
            reason = f'No contact in {days} days' if days else 'No contact on record'
            result.append({
                'id': 'fq_' + fq['capital_group_id'],
                'type': 'follow_up',
                'title': fq['label'],
                'description': reason,
                'priority': 6,
                'due_at': None,
                'channel': None,
                'group_name': fq['group_name'],
                'contact_name': None,
                'contact_id': None,
                'capital_group_id': fq['capital_group_id'],
                'signal_id': None,
                'signal_title': None,
                'signal_type': None,
                'signal_summary': None,
                'signal_source_url': None,
                'nba_type': 'overdue_followup',
                'reason': reason,
                'trigger_rule': 'followup_queue',
            })

    return result


# ── Shared follow-up queue (single source of truth) ───────────────
_FOLLOWUP_VERBS = ['Follow up with', 'Check in with', 'Reconnect with',
                   'Touch base with', 'Reach out to']

def _followup_label(group_name, days_inactive):
    idx = hash(group_name) % len(_FOLLOWUP_VERBS)
    if days_inactive is None:
        return f'Follow up with {group_name}'
    if days_inactive >= 60:
        return f'Reconnect with {group_name}'
    if days_inactive >= 45:
        return f'Check in with {group_name}'
    return _FOLLOWUP_VERBS[idx] + f' {group_name}'


def get_followup_queue(limit=30):
    now = _now()
    threshold = (now - timedelta(days=30)).isoformat()

    rows = fetch_all(
        "SELECT id, name, type, warmth_score, last_contacted_at, relationship_status "
        "FROM capital_groups "
        "WHERE last_contacted_at IS NULL OR last_contacted_at < ? "
        "ORDER BY "
        "CASE WHEN last_contacted_at IS NOT NULL THEN 0 ELSE 1 END, "
        "last_contacted_at ASC, "
        "warmth_score DESC",
        [threshold]
    )

    result = []
    for r in rows[:limit]:
        last = r.get('last_contacted_at')
        if last:
            try:
                days = (now - datetime.fromisoformat(last)).days
            except (ValueError, TypeError):
                days = None
        else:
            days = None

        result.append({
            'capital_group_id': r['id'],
            'group_name': r['name'],
            'type': r.get('type', 'developer'),
            'warmth': r.get('warmth_score', 1),
            'status': r.get('relationship_status', 'prospect'),
            'days_inactive': days,
            'last_contacted_at': last,
            'label': _followup_label(r['name'], days),
            'nba_type': 'overdue_followup',
        })
    return result


def complete_task(task_id):
    execute(
        "UPDATE prospecting_tasks SET status = 'completed', completed_at = ? WHERE id = ?",
        [_iso(_now()), task_id]
    )
    task = fetch_one("SELECT * FROM prospecting_tasks WHERE id = ?", [task_id])
    if task and task.get('capital_group_id'):
        _log_feed(task['capital_group_id'], 'touchpoint',
                  f"Task completed: {task.get('title', '')}",
                  task.get('description', ''))
    if task and task.get('enrollment_id'):
        enrollment = fetch_one("SELECT * FROM prospecting_enrollments WHERE id = ?", [task['enrollment_id']])
        if enrollment:
            new_step = (enrollment.get('current_step') or 1) + 1
            seq = fetch_one("SELECT total_steps FROM prospecting_sequences WHERE id = ?", [enrollment['sequence_id']])
            if seq and new_step > seq.get('total_steps', 0):
                execute("UPDATE prospecting_enrollments SET status = 'completed', completed_at = ?, current_step = ? WHERE id = ?",
                        [_iso(_now()), new_step, enrollment['id']])
            else:
                execute("UPDATE prospecting_enrollments SET current_step = ?, last_step_at = ? WHERE id = ?",
                        [new_step, _iso(_now()), enrollment['id']])
    return task
