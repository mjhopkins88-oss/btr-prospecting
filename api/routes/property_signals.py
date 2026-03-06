"""
API Routes: Property Signals & Development Intelligence.
Provides endpoints for the free-data intelligence layer:
property signals, parcel probability, entity resolution,
market acceleration, and development opportunity ranking.
"""
import json
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

property_signals_bp = Blueprint('property_signals', __name__)


def _safe_ts(val):
    if val is None:
        return None
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return str(val)


# -----------------------------------------------------------------------
# Property Signals
# -----------------------------------------------------------------------

@property_signals_bp.route('/api/property-signals', methods=['GET'])
def get_property_signals():
    """
    GET /api/property-signals
    Query params: signal_type, city, state, entity_name, parcel_id, limit, offset
    """
    signal_type = request.args.get('signal_type')
    city = request.args.get('city')
    state = request.args.get('state')
    entity_name = request.args.get('entity_name')
    parcel_id = request.args.get('parcel_id')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT id, parcel_id, signal_type, source, entity_name,
               address, city, state, metadata, created_at
        FROM property_signals
        WHERE 1=1
    '''
    params = []

    if signal_type:
        sql += ' AND signal_type = ?'
        params.append(signal_type)
    if city:
        sql += ' AND city = ?'
        params.append(city)
    if state:
        sql += ' AND state = ?'
        params.append(state)
    if entity_name:
        sql += ' AND entity_name LIKE ?'
        params.append(f'%{entity_name}%')
    if parcel_id:
        sql += ' AND parcel_id = ?'
        params.append(parcel_id)

    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    for r in rows:
        r['created_at'] = _safe_ts(r.get('created_at'))
        if r.get('metadata'):
            try:
                r['metadata'] = json.loads(r['metadata']) if isinstance(r['metadata'], str) else r['metadata']
            except Exception:
                pass

    return jsonify({'signals': rows, 'count': len(rows)})


@property_signals_bp.route('/api/property-signals/stats', methods=['GET'])
def property_signal_stats():
    """Signal statistics across the property_signals table."""
    stats = {
        'total': fetch_one("SELECT COUNT(*) as count FROM property_signals"),
        'by_type': fetch_all(
            "SELECT signal_type, COUNT(*) as count FROM property_signals "
            "GROUP BY signal_type ORDER BY count DESC"
        ),
        'by_source': fetch_all(
            "SELECT source, COUNT(*) as count FROM property_signals "
            "GROUP BY source ORDER BY count DESC"
        ),
        'by_city': fetch_all(
            "SELECT city, state, COUNT(*) as count FROM property_signals "
            "WHERE city IS NOT NULL GROUP BY city, state ORDER BY count DESC LIMIT 20"
        ),
    }
    return jsonify(stats)


# -----------------------------------------------------------------------
# Development Opportunities (ranked by probability)
# -----------------------------------------------------------------------

@property_signals_bp.route('/api/opportunities', methods=['GET'])
def get_opportunities():
    """
    GET /api/opportunities
    Returns parcels ranked by development_probability.
    Integrates signal density and temporal pattern scores.
    Query params: city, state, min_probability, limit, offset
    """
    city = request.args.get('city')
    state = request.args.get('state')
    min_prob = request.args.get('min_probability', type=int, default=0)
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT p.parcel_id, p.address, p.city, p.state,
               p.latitude, p.longitude,
               COALESCE(p.development_probability, 0) as development_probability,
               pdp.likely_development_type,
               pdp.reasoning,
               (SELECT COUNT(*) FROM property_signals ps
                WHERE ps.parcel_id = p.parcel_id) as signal_density,
               (SELECT COUNT(*) FROM pattern_matches pm
                WHERE pm.parcel_id = p.parcel_id) as pattern_matches
        FROM parcels p
        LEFT JOIN parcel_development_probability pdp ON pdp.parcel_id = p.parcel_id
        WHERE COALESCE(p.development_probability, 0) >= ?
    '''
    params = [min_prob]

    if city:
        sql += ' AND p.city = ?'
        params.append(city)
    if state:
        sql += ' AND p.state = ?'
        params.append(state)

    sql += ' ORDER BY development_probability DESC, signal_density DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    return jsonify({'opportunities': rows, 'count': len(rows)})


# -----------------------------------------------------------------------
# Entity Resolution
# -----------------------------------------------------------------------

@property_signals_bp.route('/api/entities', methods=['GET'])
def get_entities():
    """
    GET /api/entities
    Returns resolved entities with parent relationships.
    Query params: entity_type, parent, limit
    """
    entity_type = request.args.get('entity_type')
    parent = request.args.get('parent')
    limit = min(int(request.args.get('limit', 100)), 500)

    sql = '''
        SELECT id, entity_name, normalized_name, entity_type,
               parent_entity, created_at
        FROM entities
        WHERE 1=1
    '''
    params = []

    if entity_type:
        sql += ' AND entity_type = ?'
        params.append(entity_type)
    if parent:
        sql += ' AND parent_entity = ?'
        params.append(parent)

    sql += ' ORDER BY entity_name ASC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    for r in rows:
        r['created_at'] = _safe_ts(r.get('created_at'))

    return jsonify({'entities': rows, 'count': len(rows)})


@property_signals_bp.route('/api/entities/<entity_name>/related', methods=['GET'])
def get_related_entities(entity_name):
    """Get all LLCs/entities related to a parent developer."""
    related = fetch_all('''
        SELECT entity_name, normalized_name, entity_type
        FROM entities
        WHERE parent_entity = ?
        ORDER BY entity_name
    ''', [entity_name])

    # Also get relationship graph connections
    relationships = fetch_all('''
        SELECT entity_a, entity_a_type, entity_b, entity_b_type,
               relationship_type, confidence
        FROM entity_relationships
        WHERE entity_a = ? OR entity_b = ?
        ORDER BY confidence DESC
    ''', [entity_name, entity_name])

    return jsonify({
        'parent': entity_name,
        'related_entities': related,
        'relationships': relationships,
    })


# -----------------------------------------------------------------------
# Market Acceleration
# -----------------------------------------------------------------------

@property_signals_bp.route('/api/market-acceleration', methods=['GET'])
def get_market_acceleration():
    """
    GET /api/market-acceleration
    Returns markets with acceleration metrics.
    Query params: emerging_only, limit
    """
    emerging_only = request.args.get('emerging_only')
    limit = min(int(request.args.get('limit', 50)), 200)

    sql = '''
        SELECT id, city, state, signals_90_days, signals_12_months,
               acceleration_ratio, is_emerging, last_calculated
        FROM market_acceleration
        WHERE 1=1
    '''
    params = []

    if emerging_only and emerging_only.lower() in ('true', '1', 'yes'):
        sql += ' AND is_emerging = 1'

    sql += ' ORDER BY acceleration_ratio DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    for r in rows:
        r['is_emerging'] = bool(r.get('is_emerging'))
        r['last_calculated'] = _safe_ts(r.get('last_calculated'))

    return jsonify({'markets': rows, 'count': len(rows)})
