"""
API Routes: Performance Dashboard
Personal performance tracking — daily checklist, workouts, revenue, micro-logs.
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import json

from shared.database import fetch_all, fetch_one, execute, new_id

performance_bp = Blueprint('performance', __name__, url_prefix='/api/performance')


def _today_str():
    return datetime.utcnow().strftime('%Y-%m-%d')


def _ensure_day(date_str=None):
    ds = date_str or _today_str()
    row = fetch_one("SELECT * FROM performance_daily WHERE date_str = ?", [ds])
    if row:
        return row
    pid = new_id()
    execute(
        "INSERT INTO performance_daily (id, date_str) VALUES (?, ?)",
        [pid, ds]
    )
    return fetch_one("SELECT * FROM performance_daily WHERE id = ?", [pid])


@performance_bp.route('/today', methods=['GET'])
def get_today():
    now = datetime.utcnow()
    today = _today_str()
    day = _ensure_day(today)

    tp_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ?",
        [today]
    )
    today_tp = tp_row['cnt'] if tp_row else 0

    call_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ? AND type IN ('call', 'meeting')",
        [today]
    )
    today_calls = call_row['cnt'] if call_row else 0

    fu_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'completed' AND DATE(updated_at) = ?",
        [today]
    )
    today_followups = fu_row['cnt'] if fu_row else 0

    rel_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ? AND type IN ('meeting', 'referral', 'note')",
        [today]
    )
    today_relationship = rel_row['cnt'] if rel_row else 0

    workout = day.get('workout', 0) or 0
    squats = day.get('squats', 0) or 0
    revenue = day.get('revenue', 0) or 0
    revenue_target = day.get('revenue_target', 0) or 0
    daily_focus = day.get('daily_focus', '') or ''

    score = _compute_score(workout, squats, today_tp, today_followups, today_relationship)

    week_start = (now - timedelta(days=now.weekday())).strftime('%Y-%m-%d')
    week_end = (now - timedelta(days=now.weekday()) + timedelta(days=6)).strftime('%Y-%m-%d')
    week_days = fetch_all(
        "SELECT * FROM performance_daily WHERE date_str >= ? AND date_str <= ? ORDER BY date_str",
        [week_start, week_end]
    )

    week_tp_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) >= ? AND DATE(occurred_at) <= ?",
        [week_start, week_end]
    )
    week_tp = week_tp_row['cnt'] if week_tp_row else 0

    week_calls_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) >= ? AND DATE(occurred_at) <= ? AND type IN ('call', 'meeting')",
        [week_start, week_end]
    )
    week_calls = week_calls_row['cnt'] if week_calls_row else 0

    week_fu_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'completed' AND DATE(updated_at) >= ? AND DATE(updated_at) <= ?",
        [week_start, week_end]
    )
    week_followups = week_fu_row['cnt'] if week_fu_row else 0

    week_workouts = sum(1 for d in week_days if d.get('workout'))
    week_scores = []
    for wd in week_days:
        wd_date = wd['date_str']
        wd_tp = fetch_one(
            "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ?",
            [wd_date]
        )
        wd_fu = fetch_one(
            "SELECT COUNT(*) as cnt FROM prospecting_tasks WHERE status = 'completed' AND DATE(updated_at) = ?",
            [wd_date]
        )
        wd_rel = fetch_one(
            "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ? AND type IN ('meeting', 'referral', 'note')",
            [wd_date]
        )
        ws = _compute_score(
            wd.get('workout', 0) or 0,
            wd.get('squats', 0) or 0,
            wd_tp['cnt'] if wd_tp else 0,
            wd_fu['cnt'] if wd_fu else 0,
            wd_rel['cnt'] if wd_rel else 0
        )
        week_scores.append(ws)

    weekly_score = int(sum(week_scores) / len(week_scores)) if week_scores else 0

    streak = _compute_streak()

    momentum = _compute_momentum(week_tp, today_tp, len([d for d in week_days if d.get('workout')]), streak)

    behind_pace = score < 40

    monthly_revenue = _get_monthly_revenue()
    monthly_target = _get_monthly_target()

    logs = fetch_all(
        "SELECT * FROM performance_logs WHERE date_str = ? ORDER BY created_at DESC LIMIT 20",
        [today]
    )

    weekly_goal = 40
    day_of_week = now.weekday()
    if day_of_week >= 5:
        week_label = 'STRONG' if week_tp >= weekly_goal else ('ON TRACK' if week_tp >= weekly_goal * 0.7 else 'BEHIND')
    else:
        expected = int(weekly_goal * (day_of_week + 1) / 5.0)
        week_label = 'STRONG' if week_tp >= expected + 5 else ('ON TRACK' if week_tp >= expected - 3 else 'BEHIND')

    return jsonify({
        'date': today,
        'daily_score': score,
        'weekly_score': weekly_score,
        'streak': streak,
        'momentum': momentum,
        'workout': workout,
        'squats': squats,
        'touchpoints': today_tp,
        'calls_meetings': today_calls,
        'followups': today_followups,
        'relationship_actions': today_relationship,
        'revenue': revenue,
        'revenue_target': revenue_target,
        'monthly_revenue': monthly_revenue,
        'monthly_target': monthly_target,
        'daily_focus': daily_focus,
        'behind_pace': behind_pace,
        'logs': logs,
        'week': {
            'touchpoints': week_tp,
            'calls': week_calls,
            'followups': week_followups,
            'workouts': week_workouts,
            'goal': weekly_goal,
            'label': week_label,
            'scores': week_scores,
        }
    })


@performance_bp.route('/update', methods=['POST'])
def update_today():
    data = request.get_json(silent=True) or {}
    today = _today_str()
    _ensure_day(today)

    sets = []
    params = []
    for field in ('workout', 'squats', 'revenue', 'revenue_target', 'daily_focus'):
        if field in data:
            sets.append(field + ' = ?')
            params.append(data[field])

    if not sets:
        return jsonify({'error': 'nothing to update'}), 400

    sets.append('updated_at = ?')
    params.append(datetime.utcnow().isoformat())
    params.append(today)

    execute(
        "UPDATE performance_daily SET " + ', '.join(sets) + " WHERE date_str = ?",
        params
    )

    return jsonify({'ok': True})


@performance_bp.route('/log', methods=['POST'])
def micro_log():
    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'empty'}), 400

    today = _today_str()
    _ensure_day(today)
    lower = text.lower()
    result = {'action': 'logged', 'text': text}

    if 'squat' in lower:
        num = _extract_number(lower)
        if num > 0:
            day = fetch_one("SELECT squats FROM performance_daily WHERE date_str = ?", [today])
            current = (day.get('squats', 0) or 0) if day else 0
            execute("UPDATE performance_daily SET squats = ?, updated_at = ? WHERE date_str = ?",
                    [current + num, datetime.utcnow().isoformat(), today])
            result = {'action': 'squats', 'value': current + num, 'added': num}

    elif 'workout' in lower or 'gym' in lower or 'lifted' in lower or 'ran ' in lower or 'run ' in lower:
        execute("UPDATE performance_daily SET workout = 1, updated_at = ? WHERE date_str = ?",
                [datetime.utcnow().isoformat(), today])
        result = {'action': 'workout', 'value': 1}

    elif 'deal' in lower or '$' in lower or 'revenue' in lower or 'closed' in lower:
        num = _extract_number(lower.replace('$', '').replace(',', ''))
        if num > 0:
            day = fetch_one("SELECT revenue FROM performance_daily WHERE date_str = ?", [today])
            current = (day.get('revenue', 0) or 0) if day else 0
            execute("UPDATE performance_daily SET revenue = ?, updated_at = ? WHERE date_str = ?",
                    [current + num, datetime.utcnow().isoformat(), today])
            result = {'action': 'revenue', 'value': current + num, 'added': num}

    elif 'call' in lower or 'called' in lower or 'met ' in lower or 'meeting' in lower:
        result = {'action': 'touchpoint_hint', 'text': text}

    elif 'focus' in lower:
        focus_text = text
        for prefix in ['focus:', 'focus ', 'today focus:', 'today focus ']:
            if lower.startswith(prefix):
                focus_text = text[len(prefix):].strip()
                break
        execute("UPDATE performance_daily SET daily_focus = ?, updated_at = ? WHERE date_str = ?",
                [focus_text, datetime.utcnow().isoformat(), today])
        result = {'action': 'focus', 'value': focus_text}

    lid = new_id()
    execute(
        "INSERT INTO performance_logs (id, date_str, log_type, raw_text, parsed_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [lid, today, result.get('action', 'note'), text, json.dumps(result), datetime.utcnow().isoformat()]
    )

    return jsonify(result)


def _compute_score(workout, squats, touchpoints, followups, relationship):
    s = 0
    if workout:
        s += 10
    s += min(10, int(squats / 5)) if squats else 0
    s += min(30, touchpoints * 3)
    s += min(15, followups * 5)
    s += min(15, relationship * 5)
    base = min(80, s)
    consistency_bonus = min(20, (1 if workout else 0) * 5 + (1 if touchpoints >= 3 else 0) * 10 + (1 if followups >= 1 else 0) * 5)
    return min(100, base + consistency_bonus)


def _compute_streak():
    now = datetime.utcnow()
    streak = 0
    for days_ago in range(0, 180):
        d = now - timedelta(days=days_ago)
        if d.weekday() >= 5:
            continue
        ds = d.strftime('%Y-%m-%d')
        tp = fetch_one("SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE DATE(occurred_at) = ?", [ds])
        perf = fetch_one("SELECT workout FROM performance_daily WHERE date_str = ?", [ds])
        has_activity = (tp and tp['cnt'] > 0) or (perf and perf.get('workout'))
        if has_activity:
            streak += 1
        else:
            if days_ago == 0 and d.weekday() < 5:
                streak = 0
            break
    return streak


def _compute_momentum(week_tp, today_tp, week_workouts, streak):
    activity_score = min(10, week_tp) + min(5, week_workouts * 2) + min(5, streak)
    if activity_score >= 15:
        return 'HIGH'
    elif activity_score >= 8:
        return 'BUILDING'
    else:
        return 'SLIPPING'


def _get_monthly_revenue():
    now = datetime.utcnow()
    month_start = now.replace(day=1).strftime('%Y-%m-%d')
    rows = fetch_all(
        "SELECT COALESCE(SUM(revenue), 0) as total FROM performance_daily WHERE date_str >= ?",
        [month_start]
    )
    return rows[0]['total'] if rows else 0


def _get_monthly_target():
    now = datetime.utcnow()
    month_start = now.replace(day=1).strftime('%Y-%m-%d')
    row = fetch_one(
        "SELECT revenue_target FROM performance_daily WHERE date_str >= ? AND revenue_target > 0 ORDER BY date_str DESC LIMIT 1",
        [month_start]
    )
    return row['revenue_target'] if row else 0


def _extract_number(text):
    import re
    m = re.search(r'(\d+(?:\.\d+)?)', text)
    if m:
        val = float(m.group(1))
        if 'k' in text.lower():
            val *= 1000
        return val
    return 0
