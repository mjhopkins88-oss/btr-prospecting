"""
API Routes: Predictions
Flask Blueprint for predicted development projects.
Queries predicted_project_index for fast, enriched results.
Falls back to predicted_projects if the index is empty.
"""
from flask import Blueprint, request, jsonify
import json

from shared.database import fetch_all, fetch_one

predictions_bp = Blueprint('predictions', __name__)


def _safe_ts(val):
    """Convert potential datetime to ISO string."""
    if val is None:
        return None
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return str(val)


def _index_has_data():
    """Check if predicted_project_index has rows."""
    try:
        row = fetch_one("SELECT COUNT(*) as count FROM predicted_project_index")
        return row and row.get('count', 0) > 0
    except Exception:
        return False


@predictions_bp.route('/api/predicted-projects', methods=['GET'])
def get_predicted_projects():
    """
    GET /api/predicted-projects
    Returns predicted development projects with enriched scoring.
    Queries predicted_project_index for speed; falls back to predicted_projects.
    Query params: city, state, confirmed, min_confidence, limit, offset
    """
    city = request.args.get('city')
    state = request.args.get('state')
    confirmed = request.args.get('confirmed')
    min_confidence = request.args.get('min_confidence', type=int)
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    use_index = _index_has_data()

    if use_index:
        sql = '''
            SELECT id, city, state, developer, prediction_date, confidence,
                   signal_count, cluster_detected, expected_construction_window,
                   pattern_detected, confirmed, freshness_boost,
                   contactability_score, developer_reputation_boost,
                   relationship_count, developer_linked, contractor_linked,
                   consultant_linked, relationship_boost, created_at
            FROM predicted_project_index
            WHERE 1=1
        '''
    else:
        sql = '''
            SELECT id, city, state, developer, prediction_date, confidence,
                   signal_count, cluster_detected, expected_construction_window,
                   pattern_detected, confirmed, created_at
            FROM predicted_projects
            WHERE 1=1
        '''
    params = []

    if city:
        sql += ' AND city = ?'
        params.append(city)
    if state:
        sql += ' AND state = ?'
        params.append(state)
    if confirmed is not None:
        sql += ' AND confirmed = ?'
        params.append(confirmed.lower() in ('true', '1', 'yes'))
    if min_confidence is not None:
        sql += ' AND confidence >= ?'
        params.append(min_confidence)

    sql += ' ORDER BY confidence DESC, relationship_count DESC, prediction_date DESC LIMIT ? OFFSET ?' if use_index else ' ORDER BY confidence DESC, prediction_date DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)

    for row in rows:
        row['prediction_date'] = _safe_ts(row.get('prediction_date'))
        row['created_at'] = _safe_ts(row.get('created_at'))
        row['confirmed'] = bool(row.get('confirmed'))
        row['cluster_detected'] = bool(row.get('cluster_detected'))
        row['signal_count'] = row.get('signal_count') or 0
        row['expected_construction_window'] = row.get('expected_construction_window') or None
        if use_index:
            row['freshness_boost'] = row.get('freshness_boost') or 0
            row['contactability_score'] = row.get('contactability_score') or 0
            row['developer_reputation_boost'] = row.get('developer_reputation_boost') or 0
            row['relationship_count'] = row.get('relationship_count') or 0
            row['developer_linked'] = bool(row.get('developer_linked'))
            row['contractor_linked'] = bool(row.get('contractor_linked'))
            row['consultant_linked'] = bool(row.get('consultant_linked'))
            row['relationship_boost'] = row.get('relationship_boost') or 0

    return jsonify({'predictions': rows, 'count': len(rows)})


@predictions_bp.route('/api/predicted-projects/<prediction_id>', methods=['GET'])
def get_predicted_project(prediction_id):
    """Get a single predicted project with its associated events."""
    # Try index first for enriched data
    prediction = fetch_one(
        "SELECT * FROM predicted_project_index WHERE id = ?",
        [prediction_id]
    )
    if not prediction:
        prediction = fetch_one(
            "SELECT * FROM predicted_projects WHERE id = ?",
            [prediction_id]
        )
    if not prediction:
        return jsonify({'error': 'Prediction not found'}), 404

    prediction['prediction_date'] = _safe_ts(prediction.get('prediction_date'))
    prediction['created_at'] = _safe_ts(prediction.get('created_at'))
    prediction['confirmed'] = bool(prediction.get('confirmed'))
    prediction['cluster_detected'] = bool(prediction.get('cluster_detected'))
    prediction['signal_count'] = prediction.get('signal_count') or 0

    # Get associated development events for this city/state
    events = fetch_all('''
        SELECT id, event_type, city, state, parcel_id, developer,
               event_date, source, created_at
        FROM development_events
        WHERE city = ? AND state = ?
        ORDER BY event_date ASC
    ''', [prediction.get('city'), prediction.get('state')])

    for e in events:
        e['event_date'] = _safe_ts(e.get('event_date'))
        e['created_at'] = _safe_ts(e.get('created_at'))

    prediction['events'] = events
    return jsonify(prediction)


@predictions_bp.route('/api/predicted-projects/stats', methods=['GET'])
def prediction_stats():
    """Get prediction pipeline statistics."""
    use_index = _index_has_data()
    table = 'predicted_project_index' if use_index else 'predicted_projects'

    stats = {
        'total': fetch_one(f"SELECT COUNT(*) as count FROM {table}"),
        'confirmed': fetch_one(f"SELECT COUNT(*) as count FROM {table} WHERE confirmed = 1"),
        'unconfirmed': fetch_one(f"SELECT COUNT(*) as count FROM {table} WHERE confirmed = 0"),
        'avg_confidence': fetch_one(f"SELECT ROUND(AVG(confidence), 1) as avg FROM {table}"),
        'by_state': fetch_all(
            f"SELECT state, COUNT(*) as count FROM {table} "
            "GROUP BY state ORDER BY count DESC"
        ),
        'events_total': fetch_one("SELECT COUNT(*) as count FROM development_events"),
        'events_by_type': fetch_all(
            "SELECT event_type, COUNT(*) as count FROM development_events "
            "GROUP BY event_type ORDER BY count DESC"
        ),
    }

    if use_index:
        stats['clusters_detected'] = fetch_one(
            f"SELECT COUNT(*) as count FROM {table} WHERE cluster_detected = 1"
        )
        stats['avg_signal_count'] = fetch_one(
            f"SELECT ROUND(AVG(signal_count), 1) as avg FROM {table}"
        )

    return jsonify(stats)


@predictions_bp.route('/api/development-events', methods=['GET'])
def get_development_events():
    """Get development events with optional filtering."""
    event_type = request.args.get('type')
    city = request.args.get('city')
    state = request.args.get('state')
    limit = min(int(request.args.get('limit', 50)), 200)

    sql = '''
        SELECT id, event_type, city, state, parcel_id, developer,
               event_date, source, created_at
        FROM development_events
        WHERE 1=1
    '''
    params = []

    if event_type:
        sql += ' AND event_type = ?'
        params.append(event_type)
    if city:
        sql += ' AND city = ?'
        params.append(city)
    if state:
        sql += ' AND state = ?'
        params.append(state)

    sql += ' ORDER BY event_date DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    for r in rows:
        r['event_date'] = _safe_ts(r.get('event_date'))
        r['created_at'] = _safe_ts(r.get('created_at'))

    return jsonify({'events': rows, 'count': len(rows)})
