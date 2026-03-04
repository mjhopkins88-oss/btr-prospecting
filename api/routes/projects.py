"""
API Routes: Projects
Flask Blueprint for project entity CRUD.
"""
from flask import Blueprint, request, jsonify
import json

from shared.database import fetch_all, fetch_one

projects_bp = Blueprint('projects', __name__, url_prefix='/api/li')


@projects_bp.route('/projects', methods=['GET'])
def get_projects():
    """Get projects with optional filtering."""
    city = request.args.get('city')
    state = request.args.get('state')
    status = request.args.get('status')
    limit = min(int(request.args.get('limit', 50)), 200)

    sql = '''
        SELECT p.id, p.name, p.city, p.state, p.project_type, p.status,
               p.unit_count, p.estimated_value, p.created_at, p.updated_at,
               COUNT(DISTINCT s.id) as signal_count,
               COUNT(DISTINCT l.id) as lead_count
        FROM li_projects p
        LEFT JOIN li_signals s ON s.project_id = p.id
        LEFT JOIN li_leads l ON l.project_id = p.id
        WHERE 1=1
    '''
    params = []

    if city:
        sql += ' AND p.city = ?'
        params.append(city)
    if state:
        sql += ' AND p.state = ?'
        params.append(state)
    if status:
        sql += ' AND p.status = ?'
        params.append(status)

    sql += ' GROUP BY p.id, p.name, p.city, p.state, p.project_type, p.status, p.unit_count, p.estimated_value, p.created_at, p.updated_at'
    sql += ' ORDER BY p.updated_at DESC LIMIT ?'
    params.append(limit)

    rows = fetch_all(sql, params)
    return jsonify({'projects': rows, 'count': len(rows)})


@projects_bp.route('/projects/<project_id>', methods=['GET'])
def get_project(project_id):
    """Get a single project with signals and leads."""
    project = fetch_one("SELECT * FROM li_projects WHERE id = ?", [project_id])
    if not project:
        return jsonify({'error': 'Project not found'}), 404

    signals = fetch_all(
        "SELECT id, headline, signal_type, strength, url, source_type, created_at "
        "FROM li_signals WHERE project_id = ? ORDER BY created_at DESC LIMIT 30",
        [project_id]
    )

    leads = fetch_all(
        "SELECT l.id, l.score, l.grade, l.status, c.name as company_name "
        "FROM li_leads l LEFT JOIN li_companies c ON c.id = l.company_id "
        "WHERE l.project_id = ? ORDER BY l.score DESC",
        [project_id]
    )

    try:
        project['raw_json'] = json.loads(project.get('raw_json') or '{}')
    except Exception:
        project['raw_json'] = {}

    project['signals'] = signals
    project['leads'] = leads

    return jsonify(project)
