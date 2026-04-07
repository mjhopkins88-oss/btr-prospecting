"""
API Routes: Signals
Flask Blueprint for signal querying and management.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

signals_bp = Blueprint('signals', __name__, url_prefix='/api/li')


@signals_bp.route('/signals', methods=['GET'])
def get_signals():
    """Get signals with optional filtering."""
    signal_type = request.args.get('type')
    city = request.args.get('city')
    state = request.args.get('state')
    source = request.args.get('source')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT s.id, s.source_type, s.headline, s.body, s.url,
               s.published_at, s.city, s.state, s.signal_type,
               s.strength, s.normalized, s.created_at,
               p.name as project_name,
               c.name as company_name
        FROM li_signals s
        LEFT JOIN li_projects p ON p.id = s.project_id
        LEFT JOIN li_companies c ON c.id = s.company_id
        WHERE 1=1
    '''
    params = []

    if signal_type:
        sql += ' AND s.signal_type = ?'
        params.append(signal_type)
    if city:
        sql += ' AND s.city = ?'
        params.append(city)
    if state:
        sql += ' AND s.state = ?'
        params.append(state)
    if source:
        sql += ' AND s.source_type = ?'
        params.append(source)

    sql += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    return jsonify({'signals': rows, 'count': len(rows)})


@signals_bp.route('/signals/stats', methods=['GET'])
def signal_stats():
    """Get signal pipeline statistics."""
    stats = {
        'by_type': fetch_all(
            "SELECT signal_type, COUNT(*) as count FROM li_signals "
            "GROUP BY signal_type ORDER BY count DESC"
        ),
        'by_source': fetch_all(
            "SELECT source_type, COUNT(*) as count FROM li_signals "
            "GROUP BY source_type ORDER BY count DESC"
        ),
        'by_city': fetch_all(
            "SELECT city, state, COUNT(*) as count FROM li_signals "
            "WHERE city IS NOT NULL GROUP BY city, state ORDER BY count DESC LIMIT 10"
        ),
        'total': fetch_one("SELECT COUNT(*) as count FROM li_signals"),
        'normalized': fetch_one("SELECT COUNT(*) as count FROM li_signals WHERE normalized = 1"),
    }
    return jsonify(stats)
