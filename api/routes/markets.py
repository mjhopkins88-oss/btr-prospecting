"""
API Routes: Markets
Flask Blueprint for autonomous market expansion data.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

markets_bp = Blueprint('markets', __name__)


def _safe_ts(val):
    """Convert potential datetime to ISO string."""
    if val is None:
        return None
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return str(val)


@markets_bp.route('/api/markets', methods=['GET'])
def get_markets():
    """
    GET /api/markets
    Returns markets with growth metrics and collector status.
    Query params: state, min_score, active_only, limit, offset
    """
    state = request.args.get('state')
    min_score = request.args.get('min_score', type=int)
    active_only = request.args.get('active_only')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT id, city, state, population, population_growth,
               permit_growth, rent_growth, market_score,
               collectors_active, created_at
        FROM markets
        WHERE 1=1
    '''
    params = []

    if state:
        sql += ' AND state = ?'
        params.append(state)
    if min_score is not None:
        sql += ' AND market_score >= ?'
        params.append(min_score)
    if active_only and active_only.lower() in ('true', '1', 'yes'):
        sql += ' AND collectors_active = 1'

    sql += ' ORDER BY market_score DESC, created_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)

    for row in rows:
        row['created_at'] = _safe_ts(row.get('created_at'))
        row['collectors_active'] = bool(row.get('collectors_active'))
        row['population'] = row.get('population') or 0
        row['population_growth'] = row.get('population_growth') or 0
        row['permit_growth'] = row.get('permit_growth') or 0
        row['rent_growth'] = row.get('rent_growth') or 0
        row['market_score'] = row.get('market_score') or 0

    return jsonify({'markets': rows, 'count': len(rows)})


@markets_bp.route('/api/markets/stats', methods=['GET'])
def market_stats():
    """Get market expansion statistics."""
    stats = {
        'total_markets': fetch_one("SELECT COUNT(*) as count FROM markets"),
        'active_markets': fetch_one(
            "SELECT COUNT(*) as count FROM markets WHERE collectors_active = 1"
        ),
        'pending_markets': fetch_one(
            "SELECT COUNT(*) as count FROM markets WHERE collectors_active = 0"
        ),
        'avg_score': fetch_one(
            "SELECT ROUND(AVG(market_score), 1) as avg FROM markets"
        ),
        'by_state': fetch_all(
            "SELECT state, COUNT(*) as count FROM markets "
            "GROUP BY state ORDER BY count DESC"
        ),
        'recent_log': fetch_all(
            "SELECT city, state, action, market_score, created_at "
            "FROM market_expansion_log ORDER BY created_at DESC LIMIT 10"
        ),
    }

    # Safe-format timestamps in log
    for entry in (stats.get('recent_log') or []):
        entry['created_at'] = _safe_ts(entry.get('created_at'))

    return jsonify(stats)


@markets_bp.route('/api/markets/<market_id>', methods=['GET'])
def get_market(market_id):
    """Get a single market with its expansion log."""
    market = fetch_one("SELECT * FROM markets WHERE id = ?", [market_id])
    if not market:
        return jsonify({'error': 'Market not found'}), 404

    market['created_at'] = _safe_ts(market.get('created_at'))
    market['collectors_active'] = bool(market.get('collectors_active'))

    # Get expansion log for this city
    log = fetch_all('''
        SELECT id, action, market_score, details, created_at
        FROM market_expansion_log
        WHERE city = ? AND state = ?
        ORDER BY created_at DESC
    ''', [market.get('city'), market.get('state')])

    for entry in log:
        entry['created_at'] = _safe_ts(entry.get('created_at'))

    market['expansion_log'] = log
    return jsonify(market)
