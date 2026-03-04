"""
Lead Routing Engine.
Assigns leads to sales reps based on region, grade, and capacity.
"""
import json
from shared.config import DEFAULT_ROUTE_REGION_MAP
from shared.database import get_db, fetch_all, fetch_one


# Default sales team routing rules
# In production, this would come from a database table
DEFAULT_ROUTES = {
    'west': {
        'rep': 'West Team',
        'email': None,
        'max_leads_per_day': 20,
    },
    'south': {
        'rep': 'South Team',
        'email': None,
        'max_leads_per_day': 20,
    },
    'east': {
        'rep': 'East Team',
        'email': None,
        'max_leads_per_day': 20,
    },
    'default': {
        'rep': 'General Team',
        'email': None,
        'max_leads_per_day': 30,
    },
}


def _get_region(state):
    """Map state to region."""
    if not state:
        return 'default'
    return DEFAULT_ROUTE_REGION_MAP.get(state.upper(), 'default')


def _suggest_next_action(grade, project_status):
    """Suggest the next sales action based on lead grade and project status."""
    if grade in ('A+', 'A'):
        if project_status in ('permitted', 'under_construction'):
            return 'Schedule call — active project, high fit'
        return 'Priority outreach — high-value lead'
    elif grade in ('B+', 'B'):
        return 'Research and queue for outreach'
    elif grade in ('C+', 'C'):
        return 'Monitor — add to nurture sequence'
    else:
        return 'Low priority — review monthly'


def route_leads(min_grade='C', limit=50):
    """
    Route unassigned leads to appropriate teams.
    Only routes leads with grade >= min_grade.
    """
    # Get unassigned leads
    leads = fetch_all(
        "SELECT l.id, l.project_id, l.company_id, l.score, l.grade, l.region, "
        "p.name as project_name, p.status as project_status, p.city, p.state, "
        "c.name as company_name "
        "FROM li_leads l "
        "LEFT JOIN li_projects p ON p.id = l.project_id "
        "LEFT JOIN li_companies c ON c.id = l.company_id "
        "WHERE l.assigned_to IS NULL AND l.status = 'new' "
        "ORDER BY l.score DESC LIMIT ?",
        [limit]
    )

    if not leads:
        print("[Router] No unassigned leads to route.")
        return 0

    conn = get_db()
    cur = conn.cursor()
    routed = 0

    for lead in leads:
        grade = lead.get('grade', 'F')
        if grade > min_grade:  # alphabetical comparison works for grades
            continue

        state = lead.get('state') or lead.get('region') or ''
        region = _get_region(state)
        route = DEFAULT_ROUTES.get(region, DEFAULT_ROUTES['default'])
        next_action = _suggest_next_action(grade, lead.get('project_status'))

        try:
            cur.execute('''
                UPDATE li_leads
                SET assigned_to = ?, region = ?, next_action = ?,
                    status = 'routed', updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (route['rep'], region, next_action, lead['id']))
            routed += 1
        except Exception as e:
            print(f"[Router] Error routing lead {lead['id']}: {e}")

    conn.commit()
    conn.close()
    print(f"[Router] Routed {routed}/{len(leads)} leads.")
    return routed
