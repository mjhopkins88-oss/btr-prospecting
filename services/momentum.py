"""
Momentum module — simple activity-based momentum signal.
"""
from datetime import datetime, timedelta
from shared.database import fetch_one


def get_momentum_state():
    """Return a dict with level ('low'|'building'|'high') and supporting counts."""
    now = datetime.utcnow()
    week_ago = (now - timedelta(days=7)).isoformat()

    tp_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM capital_group_touchpoints WHERE occurred_at > ?",
        [week_ago]
    )
    touchpoints = tp_row['cnt'] if tp_row else 0

    fu_row = fetch_one(
        """SELECT COUNT(*) as cnt FROM prospecting_tasks
           WHERE type = 'follow_up' AND status = 'completed'
             AND created_at > ?""",
        [week_ago]
    )
    follow_ups = fu_row['cnt'] if fu_row else 0

    score = touchpoints + follow_ups
    if score >= 15:
        level = 'high'
    elif score >= 5:
        level = 'building'
    else:
        level = 'low'

    return {
        'level': level,
        'week_touchpoints': touchpoints,
        'week_followups_completed': follow_ups,
        'score': score
    }
