"""
Parcel Probability Worker.
Pipeline orchestrator that runs the full Parcel Development Probability Engine:
1. Scan parcels and build context
2. Run probability scoring engine
3. Apply parcel probability boost to predicted developments
"""
import json
import traceback
from datetime import datetime

from db import get_db


def _apply_parcel_scoring():
    """
    Apply parcel probability as an additional scoring layer
    to predicted_projects and predicted_project_index.

    Scoring rules (additive, does NOT modify existing scores):
    - parcel_probability >= 85: +25
    - parcel_probability >= 70: +15
    - parcel_probability >= 50: +5
    """
    print("[Parcel Worker] Applying parcel probability scoring boost...")

    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT id, city, state FROM predicted_projects
    ''')
    predictions = cur.fetchall()

    boosted = 0

    for pred_id, city, state in predictions:
        if not city or not state:
            continue

        # Find highest parcel probability in this city/state
        cur.execute('''
            SELECT MAX(pdp.probability_score), pdp.likely_development_type
            FROM parcel_development_probability pdp
            JOIN parcels p ON p.parcel_id = pdp.parcel_id
            WHERE p.city = ? AND p.state = ?
            GROUP BY pdp.likely_development_type
            ORDER BY MAX(pdp.probability_score) DESC
            LIMIT 1
        ''', (city, state))
        row = cur.fetchone()

        if not row:
            continue

        max_prob = row[0] or 0
        dev_type = row[1]

        if max_prob < 50:
            continue

        # Calculate boost
        if max_prob >= 85:
            boost = 25
        elif max_prob >= 70:
            boost = 15
        else:
            boost = 5

        from workers.analysis.parcel_probability_engine import score_likelihood_label
        likelihood = score_likelihood_label(max_prob)

        # Apply to predicted_projects
        cur.execute('''
            UPDATE predicted_projects
            SET confidence = MIN(confidence + ?, 100),
                parcel_probability_score = ?,
                parcel_development_likelihood = ?
            WHERE id = ?
        ''', (boost, max_prob, likelihood, pred_id))

        # Apply to predicted_project_index
        try:
            cur.execute('''
                UPDATE predicted_project_index
                SET confidence = MIN(confidence + ?, 100),
                    parcel_probability_score = ?,
                    parcel_development_likelihood = ?
                WHERE id = ?
            ''', (boost, max_prob, likelihood, pred_id))
        except Exception:
            pass

        boosted += 1

    conn.commit()
    conn.close()

    print(f"[Parcel Worker] Scoring boost applied to {boosted} predictions")
    return boosted


def run_parcel_probability_pipeline():
    """
    Full Parcel Probability pipeline:
    1. Score all parcels
    2. Apply scoring boost to predicted developments
    """
    print(f"\n{'='*60}")
    print(f"[Parcel Worker] PIPELINE START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Run probability engine
    try:
        from workers.analysis.parcel_probability_engine import run_probability_engine
        results['engine'] = run_probability_engine()
    except Exception as e:
        print(f"[Parcel Worker] Engine error: {e}")
        traceback.print_exc()
        results['engine'] = {'error': str(e)}

    # Step 2: Apply scoring boost
    try:
        boosted = _apply_parcel_scoring()
        results['scoring'] = {'boosted': boosted}
    except Exception as e:
        print(f"[Parcel Worker] Scoring error: {e}")
        traceback.print_exc()
        results['scoring'] = {'error': str(e)}

    print(f"\n{'='*60}")
    print(f"[Parcel Worker] PIPELINE COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[Parcel Worker] Results: {results}")
    print(f"{'='*60}\n")

    return results
