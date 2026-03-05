"""
API Routes: Developer Intent
Flask Blueprint for developer intent detection predictions and signals.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

developer_intent_bp = Blueprint('developer_intent', __name__)


def _safe_ts(val):
    """Convert potential datetime to ISO string."""
    if val is None:
        return None
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return str(val)


@developer_intent_bp.route('/api/developer-intent', methods=['GET'])
def get_intent_predictions():
    """
    GET /api/developer-intent
    Return developer intent predictions.
    Query params: city, state, min_confidence, limit, offset
    """
    city = request.args.get('city')
    state = request.args.get('state')
    min_confidence = request.args.get('min_confidence', type=int)
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT dip.id, dip.developer_id, dip.predicted_city, dip.predicted_state,
               dip.signal_count, dip.confidence_score, dip.reasoning, dip.created_at,
               d.developer_name
        FROM developer_intent_predictions dip
        LEFT JOIN developers d ON dip.developer_id = d.id
        WHERE 1=1
    '''
    params = []

    if city:
        sql += ' AND dip.predicted_city = ?'
        params.append(city)
    if state:
        sql += ' AND dip.predicted_state = ?'
        params.append(state)
    if min_confidence is not None:
        sql += ' AND dip.confidence_score >= ?'
        params.append(min_confidence)

    sql += ' ORDER BY dip.confidence_score DESC, dip.created_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)

    predictions = []
    for row in rows:
        predictions.append({
            'id': row.get('id'),
            'developer_id': row.get('developer_id'),
            'developer': row.get('developer_name') or 'Unknown',
            'city': row.get('predicted_city'),
            'state': row.get('predicted_state'),
            'signal_count': row.get('signal_count') or 0,
            'confidence': row.get('confidence_score') or 0,
            'reasoning': row.get('reasoning'),
            'created_at': _safe_ts(row.get('created_at')),
        })

    return jsonify({'predictions': predictions, 'count': len(predictions)})


@developer_intent_bp.route('/api/developer-intent/<prediction_id>', methods=['GET'])
def get_intent_prediction(prediction_id):
    """Get a single intent prediction with its associated signals."""
    prediction = fetch_one(
        '''SELECT dip.id, dip.developer_id, dip.predicted_city, dip.predicted_state,
                  dip.signal_count, dip.confidence_score, dip.reasoning, dip.created_at,
                  d.developer_name
           FROM developer_intent_predictions dip
           LEFT JOIN developers d ON dip.developer_id = d.id
           WHERE dip.id = ?''',
        [prediction_id]
    )
    if not prediction:
        return jsonify({'error': 'Prediction not found'}), 404

    result = {
        'id': prediction.get('id'),
        'developer_id': prediction.get('developer_id'),
        'developer': prediction.get('developer_name') or 'Unknown',
        'city': prediction.get('predicted_city'),
        'state': prediction.get('predicted_state'),
        'signal_count': prediction.get('signal_count') or 0,
        'confidence': prediction.get('confidence_score') or 0,
        'reasoning': prediction.get('reasoning'),
        'created_at': _safe_ts(prediction.get('created_at')),
    }

    # Fetch associated signals
    signals = fetch_all(
        '''SELECT id, signal_type, city, state, related_entity,
                  signal_strength, created_at
           FROM developer_intent_signals
           WHERE developer_id = ? AND city = ? AND state = ?
           ORDER BY created_at DESC''',
        [prediction.get('developer_id'), prediction.get('predicted_city'),
         prediction.get('predicted_state')]
    )
    result['signals'] = [
        {
            'id': s.get('id'),
            'signal_type': s.get('signal_type'),
            'city': s.get('city'),
            'state': s.get('state'),
            'related_entity': s.get('related_entity'),
            'signal_strength': s.get('signal_strength') or 0,
            'created_at': _safe_ts(s.get('created_at')),
        }
        for s in signals
    ]

    return jsonify(result)


@developer_intent_bp.route('/api/developer-intent/stats', methods=['GET'])
def intent_stats():
    """Get developer intent detection statistics."""
    stats = {
        'total_predictions': fetch_one(
            'SELECT COUNT(*) as count FROM developer_intent_predictions'
        ),
        'total_signals': fetch_one(
            'SELECT COUNT(*) as count FROM developer_intent_signals'
        ),
        'avg_confidence': fetch_one(
            'SELECT ROUND(AVG(confidence_score), 1) as avg FROM developer_intent_predictions'
        ),
        'by_state': fetch_all(
            'SELECT predicted_state as state, COUNT(*) as count '
            'FROM developer_intent_predictions '
            'GROUP BY predicted_state ORDER BY count DESC'
        ),
        'by_signal_type': fetch_all(
            'SELECT signal_type, COUNT(*) as count '
            'FROM developer_intent_signals '
            'GROUP BY signal_type ORDER BY count DESC'
        ),
    }
    return jsonify(stats)
