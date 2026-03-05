"""
Contractor Intelligence Worker.
Pipeline orchestrator that runs the full Contractor Intelligence Mapping Engine:
1. Scan contractor_activity and detect parcel activity clusters
2. Map contractor-developer relationships
3. Infer likely developers from contractor signals
4. Boost prediction scores based on contractor intelligence
"""
import json
import traceback
from datetime import datetime

from db import get_db


def _apply_contractor_scoring():
    """
    Apply contractor intelligence as an additional scoring layer
    to predicted_projects and predicted_project_index.

    Scoring rules (additive, does NOT modify existing scores):
    - Contractor activity detected on parcel: +10
    - Engineering firm involved: +10
    - Contractor historically linked to developer: +15
    - Contractor activity cluster detected (2+ types): +20
    """
    print("[Contractor Worker] Applying contractor scoring boost...")

    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT id, city, state, developer FROM predicted_projects
    ''')
    predictions = cur.fetchall()

    boosted = 0

    for pred_id, city, state, developer in predictions:
        if not city or not state:
            continue

        total_boost = 0
        contractor_detected = False
        contractor_firms = []
        inferred_developer = None
        contractor_confidence = 0

        # Get parcels for this city/state
        cur.execute('''
            SELECT DISTINCT parcel_id FROM development_events
            WHERE city = ? AND state = ? AND parcel_id IS NOT NULL
        ''', (city, state))
        parcel_ids = [r[0] for r in cur.fetchall()]

        if not parcel_ids:
            continue

        for parcel_id in parcel_ids:
            # Check 1: Any contractor activity on this parcel (+10)
            cur.execute('''
                SELECT COUNT(*) FROM contractor_activity
                WHERE parcel_id = ?
            ''', (parcel_id,))
            activity_count = cur.fetchone()[0]
            if activity_count > 0:
                contractor_detected = True
                total_boost = max(total_boost, 10)

            # Check 2: Engineering firm involved (+10)
            cur.execute('''
                SELECT cf.firm_name FROM contractor_activity ca
                JOIN contractor_firms cf ON cf.id = ca.firm_id
                WHERE ca.parcel_id = ?
                AND cf.firm_type IN ('CIVIL_ENGINEERING', 'ARCHITECTURE')
            ''', (parcel_id,))
            eng_firms = cur.fetchall()
            if eng_firms:
                total_boost = max(total_boost, 20)  # 10 for activity + 10 for engineering
                for f in eng_firms:
                    if f[0] not in contractor_firms:
                        contractor_firms.append(f[0])

            # Get all contractor firms for this parcel
            cur.execute('''
                SELECT DISTINCT cf.firm_name FROM contractor_activity ca
                JOIN contractor_firms cf ON cf.id = ca.firm_id
                WHERE ca.parcel_id = ?
            ''', (parcel_id,))
            for f in cur.fetchall():
                if f[0] not in contractor_firms:
                    contractor_firms.append(f[0])

            # Check 3: Contractor historically linked to developer (+15)
            if contractor_detected:
                cur.execute('''
                    SELECT cdr.relationship_strength, d.developer_name
                    FROM contractor_activity ca
                    JOIN contractor_developer_relationships cdr ON cdr.contractor_id = ca.firm_id
                    JOIN developers d ON d.id = cdr.developer_id
                    WHERE ca.parcel_id = ?
                    ORDER BY cdr.relationship_strength DESC
                    LIMIT 1
                ''', (parcel_id,))
                rel_row = cur.fetchone()
                if rel_row:
                    total_boost += 15
                    inferred_developer = rel_row[1]
                    contractor_confidence = min(100, rel_row[0] + 10)

            # Check 4: Activity cluster (2+ distinct types on parcel) (+20)
            cur.execute('''
                SELECT COUNT(DISTINCT activity_type) FROM contractor_activity
                WHERE parcel_id = ?
            ''', (parcel_id,))
            type_count = cur.fetchone()[0]
            if type_count >= 2:
                total_boost += 20
                contractor_confidence = max(contractor_confidence, 50 + type_count * 10)

        if total_boost == 0:
            continue

        contractor_confidence = min(100, contractor_confidence)
        firms_json = json.dumps(contractor_firms) if contractor_firms else None

        # Apply boost to predicted_projects (additive)
        cur.execute('''
            UPDATE predicted_projects
            SET confidence = MIN(confidence + ?, 100),
                contractor_activity_detected = ?,
                contractor_firms_list = ?,
                contractor_developer_inference = ?,
                contractor_confidence = ?
            WHERE id = ?
        ''', (total_boost, contractor_detected, firms_json,
              inferred_developer, contractor_confidence, pred_id))

        # Apply to predicted_project_index too
        try:
            cur.execute('''
                UPDATE predicted_project_index
                SET confidence = MIN(confidence + ?, 100),
                    contractor_activity_detected = ?,
                    contractor_firms_list = ?,
                    contractor_developer_inference = ?,
                    contractor_confidence = ?
                WHERE id = ?
            ''', (total_boost, contractor_detected, firms_json,
                  inferred_developer, contractor_confidence, pred_id))
        except Exception:
            pass

        boosted += 1

    conn.commit()
    conn.close()

    print(f"[Contractor Worker] Scoring boost applied to {boosted} predictions")
    return boosted


def run_contractor_intelligence_pipeline():
    """
    Full Contractor Intelligence pipeline:
    1. Analyze contractor activity and detect clusters
    2. Map contractor-developer relationships
    3. Infer developers from contractor signals
    4. Apply scoring boost
    """
    print(f"\n{'='*60}")
    print(f"[Contractor Worker] PIPELINE START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Analyze contractor activity
    try:
        from workers.analysis.contractor_intelligence_analyzer import run_contractor_analysis
        results['analysis'] = run_contractor_analysis()
    except Exception as e:
        print(f"[Contractor Worker] Analysis error: {e}")
        traceback.print_exc()
        results['analysis'] = {'error': str(e)}

    # Step 2: Map contractor-developer relationships
    try:
        from workers.analysis.contractor_relationship_mapper import build_contractor_relationships
        results['relationships'] = build_contractor_relationships()
    except Exception as e:
        print(f"[Contractor Worker] Relationship mapping error: {e}")
        traceback.print_exc()
        results['relationships'] = {'error': str(e)}

    # Step 3: Infer developers (informational, stored via scoring step)
    try:
        from workers.prediction.contractor_developer_inference import infer_developers_for_all_parcels
        inferences = infer_developers_for_all_parcels()
        results['inferences'] = {'count': len(inferences)}
    except Exception as e:
        print(f"[Contractor Worker] Inference error: {e}")
        traceback.print_exc()
        results['inferences'] = {'error': str(e)}

    # Step 4: Apply scoring boost
    try:
        boosted = _apply_contractor_scoring()
        results['scoring'] = {'boosted': boosted}
    except Exception as e:
        print(f"[Contractor Worker] Scoring boost error: {e}")
        traceback.print_exc()
        results['scoring'] = {'error': str(e)}

    print(f"\n{'='*60}")
    print(f"[Contractor Worker] PIPELINE COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[Contractor Worker] Results: {results}")
    print(f"{'='*60}\n")

    return results
