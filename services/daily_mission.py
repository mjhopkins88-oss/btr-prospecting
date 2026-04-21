"""
Daily Mission module — 3 follow-ups + 1 outreach + 1 high priority.
"""
from datetime import datetime, timedelta
from shared.database import fetch_all


def get_daily_mission():
    """Return a structured daily mission list."""
    now = datetime.utcnow()
    mission = []

    # Top 3 overdue follow-ups
    overdue = fetch_all(
        """SELECT id, name, last_contacted_at, relationship_status, warmth_score
           FROM capital_groups
           WHERE last_contacted_at IS NOT NULL
             AND last_contacted_at < ?
             AND relationship_status NOT IN ('dormant', 'cold')
           ORDER BY last_contacted_at ASC
           LIMIT 3""",
        [(now - timedelta(days=14)).isoformat()]
    )
    for r in overdue:
        days = (now - datetime.fromisoformat(str(r['last_contacted_at']).replace('Z', ''))).days
        mission.append({
            'id': r['id'],
            'name': r['name'],
            'slot': 'follow_up',
            'why': f"{days}d since last touch",
            'priority': 'medium'
        })

    # 1 outreach: prospect with no prior contact
    outreach_rows = fetch_all(
        """SELECT id, name, relationship_status, warmth_score
           FROM capital_groups
           WHERE (last_contacted_at IS NULL OR relationship_status = 'prospect')
           ORDER BY warmth_score DESC NULLS LAST
           LIMIT 1""", []
    )
    for r in outreach_rows:
        mission.append({
            'id': r['id'],
            'name': r['name'],
            'slot': 'outreach',
            'why': 'Untapped prospect',
            'priority': 'medium'
        })

    # 1 high priority: active opportunity that's stalled
    high_rows = fetch_all(
        """SELECT id, name, opportunity_stage, last_contacted_at
           FROM capital_groups
           WHERE opportunity_stage IS NOT NULL
             AND opportunity_stage NOT IN ('won', 'lost')
             AND (last_contacted_at IS NULL OR last_contacted_at < ?)
           ORDER BY last_contacted_at ASC NULLS FIRST
           LIMIT 1""",
        [(now - timedelta(days=7)).isoformat()]
    )
    for r in high_rows:
        mission.append({
            'id': r['id'],
            'name': r['name'],
            'slot': 'high_priority',
            'why': f"Stalled opportunity ({r['opportunity_stage']})",
            'priority': 'high'
        })

    return mission
