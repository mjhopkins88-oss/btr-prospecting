"""
API Routes: Signal Intelligence
Flask Blueprint for Signal Quality Ranking Engine analytics.
Provides endpoints for signal source rankings, type accuracy,
source priority index, and overall signal intelligence stats.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

signal_quality_bp = Blueprint('signal_quality', __name__)


def _safe_ts(val):
    """Convert potential datetime to ISO string."""
    if val is None:
        return None
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return str(val)


@signal_quality_bp.route('/api/signal-intelligence', methods=['GET'])
def get_signal_intelligence():
    """
    GET /api/signal-intelligence
    Returns full signal intelligence dashboard data:
    - top sources by accuracy
    - signal type performance
    - source priority index
    - best performing cities
    """
    limit = min(int(request.args.get('limit', 20)), 100)

    # Top performing signal sources
    top_sources = fetch_all(
        "SELECT source_name, source_type, city, state, "
        "signals_generated, signals_confirmed, accuracy_score, created_at "
        "FROM signal_sources "
        "WHERE signals_generated > 0 "
        "ORDER BY accuracy_score DESC LIMIT ?",
        [limit]
    )
    for row in top_sources:
        row['created_at'] = _safe_ts(row.get('created_at'))
        row['accuracy_pct'] = round((row.get('accuracy_score') or 0) * 100, 1)

    # Signal type accuracy rankings
    type_rankings = fetch_all(
        "SELECT signal_type, signals_generated, signals_confirmed, accuracy_score "
        "FROM signal_type_performance "
        "WHERE signals_generated > 0 "
        "ORDER BY accuracy_score DESC"
    )
    for row in type_rankings:
        row['accuracy_pct'] = round((row.get('accuracy_score') or 0) * 100, 1)

    # Source priority index
    priority_index = fetch_all(
        "SELECT source_name, priority_score, signals_last_30_days, accuracy_score "
        "FROM source_priority_index "
        "ORDER BY priority_score DESC LIMIT ?",
        [limit]
    )
    for row in priority_index:
        row['accuracy_pct'] = round((row.get('accuracy_score') or 0) * 100, 1)
        score = row.get('priority_score') or 0
        if score > 0.7:
            row['schedule_interval'] = '2 hours'
        elif score >= 0.4:
            row['schedule_interval'] = '6 hours'
        else:
            row['schedule_interval'] = '24 hours'

    # Best performing cities
    city_rankings = fetch_all(
        "SELECT city, state, "
        "COUNT(*) as source_count, "
        "ROUND(AVG(accuracy_score), 4) as avg_accuracy, "
        "SUM(signals_generated) as total_signals, "
        "SUM(signals_confirmed) as total_confirmed "
        "FROM signal_sources "
        "WHERE city IS NOT NULL AND signals_generated > 0 "
        "GROUP BY city, state "
        "ORDER BY avg_accuracy DESC LIMIT ?",
        [limit]
    )
    for row in city_rankings:
        row['avg_accuracy_pct'] = round((row.get('avg_accuracy') or 0) * 100, 1)

    # Overall stats
    total_sources = fetch_one(
        "SELECT COUNT(*) as count FROM signal_sources WHERE signals_generated > 0"
    )
    avg_accuracy = fetch_one(
        "SELECT ROUND(AVG(accuracy_score), 4) as avg FROM signal_sources WHERE signals_generated > 0"
    )
    total_tracked = fetch_one(
        "SELECT COUNT(*) as count FROM signal_performance"
    )
    total_confirmed = fetch_one(
        "SELECT COUNT(*) as count FROM signal_performance WHERE confirmed_development = TRUE"
    )

    return jsonify({
        'success': True,
        'top_sources': top_sources,
        'type_rankings': type_rankings,
        'priority_index': priority_index,
        'city_rankings': city_rankings,
        'stats': {
            'total_sources': (total_sources or {}).get('count', 0),
            'avg_accuracy': (avg_accuracy or {}).get('avg', 0),
            'avg_accuracy_pct': round(((avg_accuracy or {}).get('avg') or 0) * 100, 1),
            'total_signals_tracked': (total_tracked or {}).get('count', 0),
            'total_confirmed': (total_confirmed or {}).get('count', 0),
        },
    })


@signal_quality_bp.route('/api/signal-intelligence/sources', methods=['GET'])
def get_signal_sources():
    """
    GET /api/signal-intelligence/sources
    Returns all tracked signal sources with filtering.
    """
    source_type = request.args.get('source_type')
    city = request.args.get('city')
    min_accuracy = request.args.get('min_accuracy', type=float)
    limit = min(int(request.args.get('limit', 50)), 200)

    sql = '''
        SELECT source_name, source_type, city, state,
               signals_generated, signals_confirmed, accuracy_score, created_at
        FROM signal_sources
        WHERE signals_generated > 0
    '''
    params = []

    if source_type:
        sql += ' AND source_type = ?'
        params.append(source_type)
    if city:
        sql += ' AND city = ?'
        params.append(city)
    if min_accuracy is not None:
        sql += ' AND accuracy_score >= ?'
        params.append(min_accuracy)

    sql += ' ORDER BY accuracy_score DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    for row in rows:
        row['created_at'] = _safe_ts(row.get('created_at'))
        row['accuracy_pct'] = round((row.get('accuracy_score') or 0) * 100, 1)

    return jsonify({'success': True, 'sources': rows, 'count': len(rows)})


@signal_quality_bp.route('/api/signal-intelligence/schedule', methods=['GET'])
def get_collector_schedule():
    """
    GET /api/signal-intelligence/schedule
    Returns recommended collector schedule based on priority scores.
    """
    rows = fetch_all(
        "SELECT source_name, priority_score, signals_last_30_days, accuracy_score "
        "FROM source_priority_index "
        "ORDER BY priority_score DESC"
    )

    schedule = []
    for row in rows:
        score = row.get('priority_score') or 0
        if score > 0.7:
            interval = 2
            tier = 'HIGH'
        elif score >= 0.4:
            interval = 6
            tier = 'MEDIUM'
        else:
            interval = 24
            tier = 'LOW'

        schedule.append({
            'source_name': row['source_name'],
            'priority_score': round(score, 4),
            'interval_hours': interval,
            'tier': tier,
            'signals_last_30_days': row.get('signals_last_30_days', 0),
            'accuracy_pct': round((row.get('accuracy_score') or 0) * 100, 1),
        })

    return jsonify({'success': True, 'schedule': schedule, 'count': len(schedule)})
