"""
Quick Wins module — low-effort, high-return next actions.
"""
from datetime import datetime, timedelta
from shared.database import fetch_all


def get_quick_wins(limit=5):
    """Return small list of easy wins: warm recent contacts + low-effort follow-ups."""
    now = datetime.utcnow()
    wins = []

    # Recent warm contacts (touched in last 14d, warm/hot status)
    warm_rows = fetch_all(
        """SELECT id, name, relationship_status, last_contacted_at, warmth_score
           FROM capital_groups
           WHERE relationship_status IN ('warm', 'engaged', 'partner')
             AND last_contacted_at IS NOT NULL
             AND last_contacted_at > ?
           ORDER BY warmth_score DESC NULLS LAST, last_contacted_at DESC
           LIMIT ?""",
        [(now - timedelta(days=14)).isoformat(), limit]
    )
    for r in warm_rows:
        wins.append({
            'id': r['id'],
            'name': r['name'],
            'type': 'warm_contact',
            'why': f"Recently warm ({r['relationship_status']})",
            'effort': 'low'
        })

    # Low-effort follow-ups: groups with recent light touch, easy to continue
    easy_rows = fetch_all(
        """SELECT id, name, relationship_status, last_contacted_at
           FROM capital_groups
           WHERE last_contacted_at IS NOT NULL
             AND last_contacted_at > ?
             AND last_contacted_at < ?
             AND relationship_status NOT IN ('dormant', 'cold')
           ORDER BY last_contacted_at DESC
           LIMIT ?""",
        [
            (now - timedelta(days=10)).isoformat(),
            (now - timedelta(days=3)).isoformat(),
            limit
        ]
    )
    for r in easy_rows:
        if any(w['id'] == r['id'] for w in wins):
            continue
        days = (now - datetime.fromisoformat(str(r['last_contacted_at']).replace('Z', ''))).days
        wins.append({
            'id': r['id'],
            'name': r['name'],
            'type': 'easy_followup',
            'why': f"Quick follow-up ({days}d since last touch)",
            'effort': 'low'
        })

    return wins[:limit]
