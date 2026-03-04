"""
API Routes: Leads
Flask Blueprint for lead intelligence CRUD and querying.
"""
from flask import Blueprint, request, jsonify
import json

from shared.database import fetch_all, fetch_one, execute, new_id

leads_bp = Blueprint('leads', __name__, url_prefix='/api/li')


@leads_bp.route('/leads', methods=['GET'])
def get_leads():
    """Get leads with optional filtering."""
    grade = request.args.get('grade')
    status = request.args.get('status')
    region = request.args.get('region')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT l.id, l.score, l.grade, l.status, l.assigned_to, l.region,
               l.next_action, l.score_components, l.created_at, l.updated_at,
               p.name as project_name, p.city, p.state, p.project_type,
               p.unit_count, p.status as project_status,
               c.name as company_name, c.company_type
        FROM li_leads l
        LEFT JOIN li_projects p ON p.id = l.project_id
        LEFT JOIN li_companies c ON c.id = l.company_id
        WHERE 1=1
    '''
    params = []

    if grade:
        sql += ' AND l.grade = ?'
        params.append(grade)
    if status:
        sql += ' AND l.status = ?'
        params.append(status)
    if region:
        sql += ' AND l.region = ?'
        params.append(region)

    sql += ' ORDER BY l.score DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)

    # Parse score_components JSON
    for r in rows:
        try:
            r['score_components'] = json.loads(r.get('score_components') or '{}')
        except Exception:
            r['score_components'] = {}

    return jsonify({'leads': rows, 'count': len(rows)})


@leads_bp.route('/leads/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    """Get a single lead with full details."""
    lead = fetch_one('''
        SELECT l.*, p.name as project_name, p.city, p.state, p.project_type,
               p.unit_count, p.estimated_value, p.status as project_status,
               c.name as company_name, c.company_type, c.domain
        FROM li_leads l
        LEFT JOIN li_projects p ON p.id = l.project_id
        LEFT JOIN li_companies c ON c.id = l.company_id
        WHERE l.id = ?
    ''', [lead_id])

    if not lead:
        return jsonify({'error': 'Lead not found'}), 404

    # Get signals for this lead's project
    signals = fetch_all(
        "SELECT id, headline, signal_type, strength, url, created_at "
        "FROM li_signals WHERE project_id = ? ORDER BY strength DESC LIMIT 20",
        [lead.get('project_id')]
    ) if lead.get('project_id') else []

    # Get contacts for this lead's company
    contacts = fetch_all(
        "SELECT id, full_name, title, email, phone, linkedin_url "
        "FROM li_contacts WHERE company_id = ? ORDER BY full_name",
        [lead.get('company_id')]
    ) if lead.get('company_id') else []

    try:
        lead['score_components'] = json.loads(lead.get('score_components') or '{}')
    except Exception:
        lead['score_components'] = {}

    lead['signals'] = signals
    lead['contacts'] = contacts

    return jsonify(lead)


@leads_bp.route('/leads/<lead_id>/status', methods=['PATCH'])
def update_lead_status(lead_id):
    """Update a lead's status."""
    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    if new_status not in ('new', 'routed', 'contacted', 'qualified', 'proposal', 'won', 'lost', 'archived'):
        return jsonify({'error': 'Invalid status'}), 400

    rc = execute(
        "UPDATE li_leads SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [new_status, lead_id]
    )
    if rc == 0:
        return jsonify({'error': 'Lead not found'}), 404
    return jsonify({'ok': True, 'status': new_status})


@leads_bp.route('/leads/<lead_id>/outcome', methods=['POST'])
def record_outcome(lead_id):
    """Record an outcome (won/lost/stale) for a lead."""
    data = request.get_json(silent=True) or {}
    outcome_type = data.get('outcome_type')
    if outcome_type not in ('won', 'lost', 'stale', 'deferred'):
        return jsonify({'error': 'Invalid outcome_type'}), 400

    oid = new_id()
    execute('''
        INSERT INTO li_outcomes (id, lead_id, outcome_type, notes, revenue, created_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', [oid, lead_id, outcome_type, data.get('notes'), data.get('revenue')])

    # Update lead status
    execute(
        "UPDATE li_leads SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [outcome_type, lead_id]
    )

    return jsonify({'ok': True, 'outcome_id': oid})


@leads_bp.route('/leads/stats', methods=['GET'])
def lead_stats():
    """Get lead pipeline statistics."""
    stats = {
        'by_grade': fetch_all(
            "SELECT grade, COUNT(*) as count FROM li_leads GROUP BY grade ORDER BY grade"
        ),
        'by_status': fetch_all(
            "SELECT status, COUNT(*) as count FROM li_leads GROUP BY status ORDER BY count DESC"
        ),
        'by_region': fetch_all(
            "SELECT region, COUNT(*) as count FROM li_leads "
            "WHERE region IS NOT NULL GROUP BY region ORDER BY count DESC"
        ),
        'total': fetch_one("SELECT COUNT(*) as count FROM li_leads"),
        'avg_score': fetch_one("SELECT ROUND(AVG(score), 1) as avg_score FROM li_leads"),
    }
    return jsonify(stats)
