"""
API Routes: Developer Network Intelligence
Flask Blueprint for developer network graph data.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

developer_network_bp = Blueprint('developer_network', __name__)


@developer_network_bp.route('/api/developer-network', methods=['GET'])
def get_network_edges():
    """
    GET /api/developer-network
    Return developer network edges (relationship graph).
    Query params: entity, relationship_type, min_strength, limit, offset
    """
    entity = request.args.get('entity')
    rel_type = request.args.get('relationship_type')
    min_strength = request.args.get('min_strength', type=int, default=0)
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT id, entity_a, entity_b, relationship_type,
               co_occurrence_count, last_seen, relationship_strength
        FROM developer_network_edges
        WHERE relationship_strength >= ?
    '''
    params = [min_strength]

    if entity:
        sql += ' AND (entity_a = ? OR entity_b = ?)'
        params.extend([entity, entity])
    if rel_type:
        sql += ' AND relationship_type = ?'
        params.append(rel_type)

    sql += ' ORDER BY relationship_strength DESC, co_occurrence_count DESC'
    sql += ' LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    return jsonify({'edges': rows, 'count': len(rows)})


@developer_network_bp.route('/api/developer-network/<entity_name>', methods=['GET'])
def get_entity_network(entity_name):
    """
    GET /api/developer-network/<entity_name>
    Return all network connections for a specific entity.
    """
    min_strength = request.args.get('min_strength', type=int, default=10)

    sql = '''
        SELECT id, entity_a, entity_b, relationship_type,
               co_occurrence_count, last_seen, relationship_strength
        FROM developer_network_edges
        WHERE (entity_a = ? OR entity_b = ?)
        AND relationship_strength >= ?
        ORDER BY relationship_strength DESC
    '''
    rows = fetch_all(sql, [entity_name, entity_name, min_strength])

    connections = []
    for row in rows:
        partner = row['entity_b'] if row['entity_a'] == entity_name else row['entity_a']
        connections.append({
            'partner': partner,
            'relationship_type': row['relationship_type'],
            'co_occurrence_count': row['co_occurrence_count'],
            'relationship_strength': row['relationship_strength'],
            'last_seen': row.get('last_seen'),
        })

    return jsonify({'entity': entity_name, 'connections': connections})


@developer_network_bp.route('/api/developer-network/clusters', methods=['GET'])
def get_network_clusters():
    """
    GET /api/developer-network/clusters
    Return top network clusters (strongest relationship groups).
    """
    limit = min(int(request.args.get('limit', 20)), 100)

    sql = '''
        SELECT entity_a, entity_b, relationship_type,
               co_occurrence_count, relationship_strength, last_seen
        FROM developer_network_edges
        ORDER BY relationship_strength DESC, co_occurrence_count DESC
        LIMIT ?
    '''
    rows = fetch_all(sql, [limit])
    return jsonify({'clusters': rows})


@developer_network_bp.route('/api/developer-network/stats', methods=['GET'])
def get_network_stats():
    """
    GET /api/developer-network/stats
    Return network graph statistics.
    """
    total = fetch_one('SELECT COUNT(*) as count FROM developer_network_edges')
    by_type = fetch_all('''
        SELECT relationship_type, COUNT(*) as count,
               AVG(relationship_strength) as avg_strength
        FROM developer_network_edges
        GROUP BY relationship_type
        ORDER BY count DESC
    ''')
    strong = fetch_one('''
        SELECT COUNT(*) as count FROM developer_network_edges
        WHERE relationship_strength >= 50
    ''')

    return jsonify({
        'total_edges': total['count'] if total else 0,
        'strong_edges': strong['count'] if strong else 0,
        'by_type': by_type or [],
    })
