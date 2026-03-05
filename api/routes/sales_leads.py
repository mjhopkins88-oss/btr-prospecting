"""
API Routes: Sales Leads
Flask Blueprint for the inside sales leads endpoint.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one

sales_leads_bp = Blueprint('sales_leads', __name__, url_prefix='/api')


@sales_leads_bp.route('/sales-leads', methods=['GET'])
def get_sales_leads():
    """Return latest inside sales leads."""
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    min_score = request.args.get('min_score')

    sql = "SELECT id, developer, city, state, lead_score, confidence, source_signal, created_at FROM sales_leads WHERE 1=1"
    params = []

    if min_score:
        sql += " AND lead_score >= ?"
        params.append(int(min_score))

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    leads = fetch_all(sql, params)

    return jsonify({
        "leads": [
            {
                "id": l.get("id"),
                "developer": l.get("developer"),
                "city": l.get("city"),
                "state": l.get("state"),
                "score": l.get("lead_score"),
                "confidence": l.get("confidence"),
                "source_signal": l.get("source_signal"),
                "created_at": l.get("created_at"),
            }
            for l in leads
        ],
        "count": len(leads)
    })


@sales_leads_bp.route('/sales-leads/<lead_id>', methods=['GET'])
def get_sales_lead(lead_id):
    """Return a single sales lead with full details including summary."""
    lead = fetch_one(
        "SELECT * FROM sales_leads WHERE id = ?",
        [lead_id]
    )
    if not lead:
        return jsonify({"error": "Lead not found"}), 404
    return jsonify(lead)


@sales_leads_bp.route('/sales-leads/stats', methods=['GET'])
def sales_lead_stats():
    """Return summary statistics for inside sales leads."""
    total = fetch_one("SELECT COUNT(*) as count FROM sales_leads")
    avg_score = fetch_one("SELECT ROUND(AVG(lead_score), 1) as avg_score FROM sales_leads")
    by_state = fetch_all(
        "SELECT state, COUNT(*) as count FROM sales_leads GROUP BY state ORDER BY count DESC LIMIT 10"
    )
    return jsonify({
        "total": total,
        "avg_score": avg_score,
        "by_state": by_state,
    })
