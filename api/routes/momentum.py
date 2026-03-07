"""
API Routes: Opportunity Momentum Engine
Flask Blueprint for development momentum scores and signal sequences.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

momentum_bp = Blueprint('momentum', __name__)


@momentum_bp.route('/api/momentum', methods=['GET'])
def get_momentum_scores():
    """
    GET /api/momentum
    Return parcels with momentum scores.
    Query params: city, state, min_momentum, limit, offset
    """
    city = request.args.get('city')
    state = request.args.get('state')
    min_momentum = request.args.get('min_momentum', type=int, default=20)
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT p.parcel_id, p.address, p.city, p.state,
               p.development_probability, p.development_momentum_score,
               p.signal_sequence_length, p.signal_sequence_start,
               p.latitude, p.longitude
        FROM parcels p
        WHERE COALESCE(p.development_momentum_score, 0) >= ?
    '''
    params = [min_momentum]

    if city:
        sql += ' AND p.city = ?'
        params.append(city)
    if state:
        sql += ' AND p.state = ?'
        params.append(state)

    sql += ' ORDER BY p.development_momentum_score DESC, p.development_probability DESC'
    sql += ' LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    return jsonify({'parcels': rows, 'count': len(rows)})


@momentum_bp.route('/api/momentum/high', methods=['GET'])
def get_high_momentum():
    """
    GET /api/momentum/high
    Return parcels with high momentum (accelerating development signals).
    """
    limit = min(int(request.args.get('limit', 20)), 100)

    sql = '''
        SELECT p.parcel_id, p.address, p.city, p.state,
               p.development_probability, p.development_momentum_score,
               p.signal_sequence_length, p.signal_sequence_start
        FROM parcels p
        WHERE COALESCE(p.development_momentum_score, 0) >= 60
        ORDER BY p.development_momentum_score DESC
        LIMIT ?
    '''
    rows = fetch_all(sql, [limit])
    return jsonify({'high_momentum_parcels': rows})


@momentum_bp.route('/api/momentum/stats', methods=['GET'])
def get_momentum_stats():
    """
    GET /api/momentum/stats
    Return momentum distribution statistics.
    """
    total = fetch_one('''
        SELECT COUNT(*) as count FROM parcels
        WHERE COALESCE(development_momentum_score, 0) > 0
    ''')
    high = fetch_one('''
        SELECT COUNT(*) as count FROM parcels
        WHERE COALESCE(development_momentum_score, 0) >= 60
    ''')
    avg = fetch_one('''
        SELECT AVG(development_momentum_score) as avg_momentum
        FROM parcels
        WHERE COALESCE(development_momentum_score, 0) > 0
    ''')

    return jsonify({
        'parcels_with_momentum': total['count'] if total else 0,
        'high_momentum_count': high['count'] if high else 0,
        'avg_momentum_score': round(avg['avg_momentum'] or 0, 1) if avg else 0,
    })
