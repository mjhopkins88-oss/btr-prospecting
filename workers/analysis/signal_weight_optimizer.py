"""
Self-Optimizing Signal Weight Engine.
Replaces static signal scores with adaptive scoring based on
historical accuracy of each signal type leading to confirmed developments.

Tracks how often signals lead to confirmed developments and adjusts
signal weights automatically.
"""
import json
from datetime import datetime, timedelta

from db import get_db


# Default weights (fallback)
DEFAULT_WEIGHTS = {
    'LAND_PURCHASE': 30,
    'ZONING_APPLICATION': 25,
    'BUILDING_PERMIT': 25,
    'ENGINEERING_ENGAGEMENT': 20,
    'NEWS_SIGNAL': 10,
    'CONTRACTOR_ACTIVITY': 15,
    'MULTIFAMILY_PERMIT': 40,
    'CONSTRUCTION_FINANCING': 45,
    'SUBDIVISION_PLAT': 30,
    'REZONING_REQUEST': 30,
}


def _calculate_signal_accuracy():
    """
    Calculate accuracy for each signal type by comparing signals
    against confirmed developments.
    """
    conn = get_db()
    cur = conn.cursor()
    accuracies = {}

    try:
        # Get all signal types and their counts
        cur.execute('''
            SELECT signal_type, COUNT(*) as total
            FROM property_signals
            WHERE signal_type IS NOT NULL
            GROUP BY signal_type
        ''')
        signal_counts = {r[0]: r[1] for r in cur.fetchall()}

        # Get signal types that led to confirmed developments
        # (parcels with development_probability >= 70)
        cur.execute('''
            SELECT ps.signal_type, COUNT(DISTINCT ps.parcel_id) as confirmed
            FROM property_signals ps
            JOIN parcels p ON p.parcel_id = ps.parcel_id
            WHERE p.development_probability >= 70
            AND ps.signal_type IS NOT NULL
            GROUP BY ps.signal_type
        ''')
        confirmed_counts = {r[0]: r[1] for r in cur.fetchall()}

        for sig_type, total in signal_counts.items():
            confirmed = confirmed_counts.get(sig_type, 0)
            accuracy = (confirmed / max(total, 1)) * 100
            accuracies[sig_type] = {
                'total_signals': total,
                'confirmed': confirmed,
                'accuracy': round(accuracy, 1),
            }
    except Exception as e:
        print(f"[WeightOptimizer] Accuracy calculation error: {e}")

    conn.close()
    return accuracies


def _compute_optimized_weights(accuracies):
    """Compute optimized weights based on accuracy data."""
    optimized = {}

    for sig_type, data in accuracies.items():
        accuracy = data['accuracy']
        total = data['total_signals']
        default = DEFAULT_WEIGHTS.get(sig_type, 15)

        # Need minimum sample size for adjustment
        if total < 5:
            optimized[sig_type] = default
            continue

        # Adjust weight: scale default by accuracy ratio
        if accuracy >= 80:
            adjusted = min(int(default * 1.3), 50)
        elif accuracy >= 60:
            adjusted = min(int(default * 1.1), 45)
        elif accuracy >= 40:
            adjusted = default
        elif accuracy >= 20:
            adjusted = max(int(default * 0.8), 5)
        else:
            adjusted = max(int(default * 0.6), 5)

        optimized[sig_type] = adjusted

    return optimized


def run_weight_optimization():
    """Full weight optimization cycle."""
    print(f"[WeightOptimizer] START — {datetime.utcnow().isoformat()}")

    accuracies = _calculate_signal_accuracy()
    optimized = _compute_optimized_weights(accuracies)

    # Log results
    print(f"[WeightOptimizer] Signal accuracy analysis:")
    for sig_type, data in sorted(accuracies.items(), key=lambda x: x[1]['accuracy'], reverse=True):
        weight = optimized.get(sig_type, '?')
        print(f"  {sig_type}: accuracy={data['accuracy']}% "
              f"(confirmed={data['confirmed']}/{data['total_signals']}) "
              f"weight={weight}")

    # Store optimized weights
    conn = get_db()
    cur = conn.cursor()
    try:
        for sig_type, data in accuracies.items():
            cur.execute('''
                INSERT OR REPLACE INTO signal_type_performance
                (signal_type, total_signals, confirmed_predictions,
                 accuracy_score, optimized_weight)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                sig_type, data['total_signals'], data['confirmed'],
                data['accuracy'], optimized.get(sig_type, 15),
            ))
    except Exception as e:
        print(f"[WeightOptimizer] Storage error: {e}")
    conn.commit()
    conn.close()

    print(f"[WeightOptimizer] COMPLETE — {len(optimized)} weights updated")
    return {'weights_updated': len(optimized), 'accuracies': accuracies}
