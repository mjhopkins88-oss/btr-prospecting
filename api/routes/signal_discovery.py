"""
API Routes: Signal Discovery AI
Flask Blueprint for autonomous signal discovery data.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

signal_discovery_bp = Blueprint('signal_discovery', __name__)


@signal_discovery_bp.route('/api/signal-discovery/sources', methods=['GET'])
def get_discovered_sources():
    """
    GET /api/signal-discovery/sources
    Return discovered data sources.
    Query params: city, state, source_type, status, limit
    """
    city = request.args.get('city')
    state = request.args.get('state')
    source_type = request.args.get('source_type')
    status = request.args.get('status')
    limit = min(int(request.args.get('limit', 50)), 200)

    sql = '''
        SELECT id, source_type, city, state, title, url,
               description, priority, status, reliability_score,
               last_checked, discovered_at
        FROM data_sources
        WHERE 1=1
    '''
    params = []

    if city:
        sql += ' AND city = ?'
        params.append(city)
    if state:
        sql += ' AND state = ?'
        params.append(state)
    if source_type:
        sql += ' AND source_type = ?'
        params.append(source_type)
    if status:
        sql += ' AND status = ?'
        params.append(status)

    sql += ' ORDER BY priority DESC, reliability_score DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    return jsonify({'sources': rows, 'count': len(rows)})


@signal_discovery_bp.route('/api/signal-discovery/stats', methods=['GET'])
def get_discovery_stats():
    """
    GET /api/signal-discovery/stats
    Return signal discovery statistics.
    """
    total = fetch_one('SELECT COUNT(*) as count FROM data_sources')
    by_status = fetch_all('''
        SELECT status, COUNT(*) as count
        FROM data_sources
        GROUP BY status
    ''')
    by_type = fetch_all('''
        SELECT source_type, COUNT(*) as count,
               AVG(reliability_score) as avg_reliability
        FROM data_sources
        GROUP BY source_type
        ORDER BY count DESC
    ''')
    by_city = fetch_all('''
        SELECT city, state, COUNT(*) as count
        FROM data_sources
        GROUP BY city, state
        ORDER BY count DESC
        LIMIT 20
    ''')

    return jsonify({
        'total_sources': total['count'] if total else 0,
        'by_status': by_status or [],
        'by_type': by_type or [],
        'by_city': by_city or [],
    })
