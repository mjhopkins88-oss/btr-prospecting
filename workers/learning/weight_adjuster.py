"""
Feedback Learning Loop.
Adjusts signal type weights based on outcome data from li_outcomes.
Signals that lead to positive outcomes get higher weights over time.
"""
import json
from shared.database import get_db, fetch_all, fetch_one, new_id


def _get_outcome_stats():
    """
    Compute win/loss rates per signal type.
    Joins outcomes → leads → signals to find which signal types
    correlate with positive outcomes.
    """
    stats = fetch_all('''
        SELECT s.signal_type,
               COUNT(DISTINCT o.id) as outcome_count,
               SUM(CASE WHEN o.outcome_type = 'won' THEN 1 ELSE 0 END) as wins,
               SUM(CASE WHEN o.outcome_type = 'lost' THEN 1 ELSE 0 END) as losses,
               SUM(CASE WHEN o.outcome_type = 'won' THEN COALESCE(o.revenue, 0) ELSE 0 END) as total_revenue
        FROM li_signals s
        INNER JOIN li_leads l ON l.project_id = s.project_id
        INNER JOIN li_outcomes o ON o.lead_id = l.id
        GROUP BY s.signal_type
        HAVING COUNT(DISTINCT o.id) >= 3
    ''')
    return stats


def _compute_adjusted_weights(stats, learning_rate=0.1):
    """
    Compute adjusted weights based on win rates.
    Uses exponential moving average to avoid wild swings.
    """
    # Default weights
    base_weights = {
        'land_acquisition': 1.0,
        'permit_filed': 1.0,
        'construction_start': 1.0,
        'project_announced': 1.0,
        'funding': 1.0,
        'zoning_change': 1.0,
        'news': 1.0,
        'other': 1.0,
    }

    # Load current weights from DB
    current = fetch_all("SELECT signal_type, weight FROM li_score_weights")
    current_map = {r['signal_type']: r['weight'] for r in current}

    adjustments = {}
    for row in stats:
        sig_type = row['signal_type']
        wins = row['wins'] or 0
        losses = row['losses'] or 0
        total = wins + losses
        if total == 0:
            continue

        win_rate = wins / total
        # Scale: win_rate 0.5 → weight 1.0, win_rate 1.0 → weight 1.5, win_rate 0.0 → weight 0.5
        target_weight = 0.5 + win_rate

        current_weight = current_map.get(sig_type, base_weights.get(sig_type, 1.0))
        # Exponential moving average
        new_weight = current_weight + learning_rate * (target_weight - current_weight)
        # Clamp to reasonable range
        new_weight = max(0.2, min(2.0, new_weight))
        adjustments[sig_type] = round(new_weight, 3)

    return adjustments


def adjust_weights():
    """
    Main entry point: analyze outcomes and adjust signal type weights.
    """
    stats = _get_outcome_stats()
    if not stats:
        print("[WeightAdjuster] Not enough outcome data to adjust weights (need >= 3 outcomes per signal type).")
        return {}

    adjustments = _compute_adjusted_weights(stats)
    if not adjustments:
        print("[WeightAdjuster] No adjustments needed.")
        return {}

    conn = get_db()
    cur = conn.cursor()

    for sig_type, weight in adjustments.items():
        try:
            cur.execute(
                "INSERT OR REPLACE INTO li_score_weights (id, signal_type, weight, updated_at) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (new_id(), sig_type, weight)
            )
        except Exception as e:
            print(f"[WeightAdjuster] Error saving weight for {sig_type}: {e}")

    conn.commit()
    conn.close()

    print(f"[WeightAdjuster] Adjusted weights: {json.dumps(adjustments)}")
    return adjustments
