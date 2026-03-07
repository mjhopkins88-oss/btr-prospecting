"""
API Routes: Development Corridor Intelligence
Flask Blueprint for development corridor detection data.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

corridors_bp = Blueprint('corridors', __name__)


@corridors_bp.route('/api/corridors', methods=['GET'])
def get_corridors():
    """
    GET /api/corridors
    Return detected development corridors.
    Query params: state, min_density, limit
    """
    state = request.args.get('state')
    min_density = request.args.get('min_density', type=int, default=0)
    limit = min(int(request.args.get('limit', 50)), 200)

    sql = '''
        SELECT id, corridor_name, city, state, signal_density,
               growth_rate, dominant_development_type, metadata,
               created_at, updated_at
        FROM development_corridors
        WHERE signal_density >= ?
    '''
    params = [min_density]

    if state:
        sql += ' AND state = ?'
        params.append(state)

    sql += ' ORDER BY signal_density DESC, growth_rate DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    return jsonify({'corridors': rows, 'count': len(rows)})


@corridors_bp.route('/api/corridors/growing', methods=['GET'])
def get_growing_corridors():
    """
    GET /api/corridors/growing
    Return corridors with positive growth rates.
    """
    limit = min(int(request.args.get('limit', 20)), 100)

    sql = '''
        SELECT corridor_name, city, state, signal_density,
               growth_rate, dominant_development_type
        FROM development_corridors
        WHERE growth_rate > 0
        ORDER BY growth_rate DESC, signal_density DESC
        LIMIT ?
    '''
    rows = fetch_all(sql, [limit])
    return jsonify({'growing_corridors': rows})


@corridors_bp.route('/api/corridors/stats', methods=['GET'])
def get_corridor_stats():
    """
    GET /api/corridors/stats
    Return corridor detection statistics.
    """
    total = fetch_one('SELECT COUNT(*) as count FROM development_corridors')
    growing = fetch_one('''
        SELECT COUNT(*) as count FROM development_corridors WHERE growth_rate > 0
    ''')
    by_state = fetch_all('''
        SELECT state, COUNT(*) as count, SUM(signal_density) as total_signals
        FROM development_corridors
        GROUP BY state
        ORDER BY total_signals DESC
    ''')

    return jsonify({
        'total_corridors': total['count'] if total else 0,
        'growing_corridors': growing['count'] if growing else 0,
        'by_state': by_state or [],
    })
