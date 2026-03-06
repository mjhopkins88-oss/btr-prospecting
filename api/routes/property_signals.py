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
                WHERE pm.parcel_id = p.parcel_id) as pattern_matches,
               (SELECT COUNT(*) FROM entity_relationships er
                WHERE (er.entity_a = p.parcel_id OR er.entity_b = p.parcel_id)
                AND COALESCE(er.relationship_strength, 0) > 0) as graph_connections
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

    sql += ' ORDER BY development_probability DESC, signal_density DESC, graph_connections DESC LIMIT ? OFFSET ?'
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


# -----------------------------------------------------------------------
# Construction Supply Chain Signals
# -----------------------------------------------------------------------

SUPPLY_CHAIN_TYPES = [
    'CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY',
    'UTILITY_CONNECTION_REQUEST', 'EARTHWORK_CONTRACTOR',
    'CONCRETE_SUPPLY_SIGNAL', 'INFRASTRUCTURE_BID',
]


@property_signals_bp.route('/api/supply-chain-signals', methods=['GET'])
def get_supply_chain_signals():
    """
    GET /api/supply-chain-signals
    Returns construction supply chain signals for the radar map.
    Query params: city, state, limit, offset
    """
    city = request.args.get('city')
    state = request.args.get('state')
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))

    placeholders = ','.join(['?' for _ in SUPPLY_CHAIN_TYPES])
    sql = f'''
        SELECT ps.id, ps.parcel_id, ps.signal_type, ps.source,
               ps.entity_name, ps.address, ps.city, ps.state,
               ps.metadata, ps.created_at,
               p.latitude, p.longitude,
               COALESCE(p.development_probability, 0) as development_probability
        FROM property_signals ps
        LEFT JOIN parcels p ON p.parcel_id = ps.parcel_id
        WHERE ps.signal_type IN ({placeholders})
    '''
    params = list(SUPPLY_CHAIN_TYPES)

    if city:
        sql += ' AND ps.city = ?'
        params.append(city)
    if state:
        sql += ' AND ps.state = ?'
        params.append(state)

    sql += ' ORDER BY ps.created_at DESC LIMIT ? OFFSET ?'
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


# -----------------------------------------------------------------------
# Radar Map Data
# -----------------------------------------------------------------------

@property_signals_bp.route('/api/radar-map', methods=['GET'])
def get_radar_map_data():
    """
    GET /api/radar-map
    Returns geo-located signals for the development radar map.
    Includes standard development signals and construction supply chain signals.
    Query params: city, state, signal_category, min_probability, limit
    """
    city = request.args.get('city')
    state = request.args.get('state')
    signal_category = request.args.get('signal_category')
    min_prob = request.args.get('min_probability', type=int, default=0)
    limit = min(int(request.args.get('limit', 200)), 500)

    sql = '''
        SELECT ps.id, ps.parcel_id, ps.signal_type, ps.entity_name,
               ps.address, ps.city, ps.state, ps.created_at,
               p.latitude, p.longitude,
               COALESCE(p.development_probability, 0) as development_probability
        FROM property_signals ps
        LEFT JOIN parcels p ON p.parcel_id = ps.parcel_id
        WHERE 1=1
    '''
    params = []

    if city:
        sql += ' AND ps.city = ?'
        params.append(city)
    if state:
        sql += ' AND ps.state = ?'
        params.append(state)
    if min_prob > 0:
        sql += ' AND COALESCE(p.development_probability, 0) >= ?'
        params.append(min_prob)

    if signal_category == 'supply_chain':
        placeholders = ','.join(['?' for _ in SUPPLY_CHAIN_TYPES])
        sql += f' AND ps.signal_type IN ({placeholders})'
        params.extend(SUPPLY_CHAIN_TYPES)
    elif signal_category:
        sql += ' AND ps.signal_type = ?'
        params.append(signal_category)

    sql += ' ORDER BY development_probability DESC, ps.created_at DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)

    # Format as map markers
    markers = []
    for r in rows:
        marker_color = 'orange' if r.get('signal_type') in SUPPLY_CHAIN_TYPES else 'blue'
        markers.append({
            'id': r['id'],
            'parcel_id': r.get('parcel_id'),
            'signal_type': r['signal_type'],
            'entity_name': r.get('entity_name'),
            'address': r.get('address'),
            'city': r.get('city'),
            'state': r.get('state'),
            'latitude': r.get('latitude'),
            'longitude': r.get('longitude'),
            'development_probability': r.get('development_probability', 0),
            'marker_color': marker_color,
            'created_at': _safe_ts(r.get('created_at')),
        })

    return jsonify({'markers': markers, 'count': len(markers)})


# -----------------------------------------------------------------------
# Signal Graph Intelligence
# -----------------------------------------------------------------------

@property_signals_bp.route('/api/signal-graph', methods=['GET'])
def get_signal_graph():
    """
    GET /api/signal-graph
    Returns entity relationship graph data.
    Query params: entity, relationship_type, min_strength, limit
    """
    entity = request.args.get('entity')
    rel_type = request.args.get('relationship_type')
    min_strength = request.args.get('min_strength', type=int, default=0)
    limit = min(int(request.args.get('limit', 100)), 500)

    sql = '''
        SELECT id, entity_a, entity_a_type, entity_b, entity_b_type,
               relationship_type, confidence, relationship_strength,
               source, created_at
        FROM entity_relationships
        WHERE COALESCE(relationship_strength, 0) >= ?
    '''
    params = [min_strength]

    if entity:
        sql += ' AND (entity_a = ? OR entity_b = ?)'
        params.extend([entity, entity])
    if rel_type:
        sql += ' AND relationship_type = ?'
        params.append(rel_type)

    sql += ' ORDER BY relationship_strength DESC, confidence DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    for r in rows:
        r['created_at'] = _safe_ts(r.get('created_at'))

    return jsonify({'relationships': rows, 'count': len(rows)})
