"""
API Routes: Capital Flow
Flask Blueprint for capital flow detection predictions and events.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

capital_flow_bp = Blueprint('capital_flow', __name__)


def _safe_ts(val):
    """Convert potential datetime to ISO string."""
    if val is None:
        return None
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return str(val)


@capital_flow_bp.route('/api/capital-flow', methods=['GET'])
def get_capital_predictions():
    """
    GET /api/capital-flow
    Return capital flow predictions.
    Query params: city, state, min_confidence, limit, offset
    """
    city = request.args.get('city')
    state = request.args.get('state')
    min_confidence = request.args.get('min_confidence', type=int)
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT cp.id, cp.developer_id, cp.predicted_city, cp.predicted_state,
               cp.capital_event_type, cp.estimated_capital_amount,
               cp.confidence_score, cp.reasoning, cp.created_at,
               d.developer_name
        FROM capital_predictions cp
        LEFT JOIN developers d ON cp.developer_id = d.id
        WHERE 1=1
    '''
    params = []

    if city:
        sql += ' AND cp.predicted_city = ?'
        params.append(city)
    if state:
        sql += ' AND cp.predicted_state = ?'
        params.append(state)
    if min_confidence is not None:
        sql += ' AND cp.confidence_score >= ?'
        params.append(min_confidence)

    sql += ' ORDER BY cp.confidence_score DESC, cp.created_at DESC LIMIT ? OFFSET ?'
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
            'capital_event': row.get('capital_event_type'),
            'estimated_amount': row.get('estimated_capital_amount'),
            'confidence': row.get('confidence_score') or 0,
            'reasoning': row.get('reasoning'),
            'created_at': _safe_ts(row.get('created_at')),
        })

    return jsonify({'predictions': predictions, 'count': len(predictions)})


@capital_flow_bp.route('/api/capital-flow/<prediction_id>', methods=['GET'])
def get_capital_prediction(prediction_id):
    """Get a single capital prediction with its associated events."""
    prediction = fetch_one(
        '''SELECT cp.id, cp.developer_id, cp.predicted_city, cp.predicted_state,
                  cp.capital_event_type, cp.estimated_capital_amount,
                  cp.confidence_score, cp.reasoning, cp.created_at,
                  d.developer_name
           FROM capital_predictions cp
           LEFT JOIN developers d ON cp.developer_id = d.id
           WHERE cp.id = ?''',
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
        'capital_event': prediction.get('capital_event_type'),
        'estimated_amount': prediction.get('estimated_capital_amount'),
        'confidence': prediction.get('confidence_score') or 0,
        'reasoning': prediction.get('reasoning'),
        'created_at': _safe_ts(prediction.get('created_at')),
    }

    # Fetch associated capital events
    events = fetch_all(
        '''SELECT id, event_type, company_name, loan_amount, lender_name,
                  related_project, source, created_at
           FROM capital_events
           WHERE developer_id = ? AND city = ? AND state = ?
           ORDER BY created_at DESC''',
        [prediction.get('developer_id'), prediction.get('predicted_city'),
         prediction.get('predicted_state')]
    )
    result['events'] = [
        {
            'id': e.get('id'),
            'event_type': e.get('event_type'),
            'company_name': e.get('company_name'),
            'loan_amount': e.get('loan_amount'),
            'lender_name': e.get('lender_name'),
            'related_project': e.get('related_project'),
            'source': e.get('source'),
            'created_at': _safe_ts(e.get('created_at')),
        }
        for e in events
    ]

    # Fetch associated capital signals
    signals = fetch_all(
        '''SELECT id, signal_type, signal_strength, created_at
           FROM capital_signals
           WHERE developer_id = ? AND city = ? AND state = ?
           ORDER BY created_at DESC''',
        [prediction.get('developer_id'), prediction.get('predicted_city'),
         prediction.get('predicted_state')]
    )
    result['signals'] = [
        {
            'id': s.get('id'),
            'signal_type': s.get('signal_type'),
            'signal_strength': s.get('signal_strength') or 0,
            'created_at': _safe_ts(s.get('created_at')),
        }
        for s in signals
    ]

    return jsonify(result)


@capital_flow_bp.route('/api/capital-flow/stats', methods=['GET'])
def capital_flow_stats():
    """Get capital flow detection statistics."""
    stats = {
        'total_predictions': fetch_one(
            'SELECT COUNT(*) as count FROM capital_predictions'
        ),
        'total_events': fetch_one(
            'SELECT COUNT(*) as count FROM capital_events'
        ),
        'total_signals': fetch_one(
            'SELECT COUNT(*) as count FROM capital_signals'
        ),
        'avg_confidence': fetch_one(
            'SELECT ROUND(AVG(confidence_score), 1) as avg FROM capital_predictions'
        ),
        'by_state': fetch_all(
            'SELECT predicted_state as state, COUNT(*) as count '
            'FROM capital_predictions '
            'GROUP BY predicted_state ORDER BY count DESC'
        ),
        'by_event_type': fetch_all(
            'SELECT capital_event_type as event_type, COUNT(*) as count '
            'FROM capital_predictions '
            'GROUP BY capital_event_type ORDER BY count DESC'
        ),
    }
    return jsonify(stats)
