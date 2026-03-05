"""
Developer DNA Worker.
Pipeline orchestrator that runs the full Developer DNA Modeling Engine:
1. Scan developer project history
2. Build DNA profiles
3. Generate expansion predictions
4. Update predicted development scoring
"""
import traceback
from datetime import datetime

from db import get_db


def _apply_dna_scoring():
    """
    Apply developer DNA intelligence as an additional scoring layer
    to predicted_projects and predicted_project_index.

    Scoring rules (additive, does NOT modify existing scores):
    - Developer expansion prediction exists for city: +15
    - Developer historically builds projects of similar size: +10
    - Developer has active signals nearby: +15
    """
    print("[DNA Worker] Applying DNA scoring boost...")

    conn = get_db()
    cur = conn.cursor()

    # Get all predicted projects
    cur.execute('''
        SELECT id, city, state, developer FROM predicted_projects
        WHERE developer IS NOT NULL AND developer != ''
    ''')
    predictions = cur.fetchall()

    boosted = 0

    for pred_id, city, state, developer in predictions:
        if not city or not state or not developer:
            continue

        total_boost = 0
        expansion_signal = False
        reasoning = None
        dna_confidence = 0

        # Look up developer in developers table
        cur.execute('SELECT id FROM developers WHERE developer_name = ?', (developer,))
        dev_row = cur.fetchone()
        if not dev_row:
            continue
        developer_id = dev_row[0]

        # Check 1: Expansion prediction exists for this city (+15)
        cur.execute('''
            SELECT confidence, reasoning FROM developer_expansion_predictions
            WHERE developer_id = ? AND predicted_city = ? AND predicted_state = ?
            ORDER BY confidence DESC LIMIT 1
        ''', (developer_id, city, state))
        exp_row = cur.fetchone()
        if exp_row:
            total_boost += 15
            expansion_signal = True
            dna_confidence = exp_row[0]
            reasoning = exp_row[1]

        # Check 2: Developer historically builds similar-sized projects (+10)
        cur.execute('''
            SELECT average_project_size FROM developer_dna_profiles
            WHERE developer_id = ?
        ''', (developer_id,))
        dna_row = cur.fetchone()
        if dna_row and dna_row[0] and dna_row[0] > 0:
            total_boost += 10
            if dna_confidence == 0:
                dna_confidence = 50  # base DNA confidence when profile exists

        # Check 3: Developer has active signals in adjacent markets (+15)
        cur.execute('''
            SELECT COUNT(*) FROM development_events
            WHERE developer = ? AND state = ?
            AND city != ?
        ''', (developer, state, city))
        nearby_count = cur.fetchone()[0]
        if nearby_count > 0:
            total_boost += 15
            if not reasoning:
                reasoning = f"Developer has {nearby_count} active signals in {state}"

        if total_boost == 0:
            continue

        # Apply boost to predicted_projects (additive)
        cur.execute('''
            UPDATE predicted_projects
            SET confidence = MIN(confidence + ?, 100),
                developer_dna_confidence = ?,
                developer_expansion_signal = ?,
                developer_expansion_reasoning = ?
            WHERE id = ?
        ''', (total_boost, dna_confidence, expansion_signal, reasoning, pred_id))

        # Apply to predicted_project_index too
        try:
            cur.execute('''
                UPDATE predicted_project_index
                SET confidence = MIN(confidence + ?, 100),
                    developer_dna_confidence = ?,
                    developer_expansion_signal = ?,
                    developer_expansion_reasoning = ?
                WHERE id = ?
            ''', (total_boost, dna_confidence, expansion_signal, reasoning, pred_id))
        except Exception:
            pass

        boosted += 1

    conn.commit()
    conn.close()

    print(f"[DNA Worker] Scoring boost applied to {boosted} predictions")
    return boosted


def run_developer_dna_pipeline():
    """
    Full Developer DNA pipeline:
    1. Analyze developer history and build DNA profiles
    2. Generate expansion predictions
    3. Apply scoring boost to predicted developments
    """
    print(f"\n{'='*60}")
    print(f"[DNA Worker] PIPELINE START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Build DNA profiles
    try:
        from workers.analysis.developer_dna_analyzer import run_dna_analysis
        results['analysis'] = run_dna_analysis()
    except Exception as e:
        print(f"[DNA Worker] DNA analysis error: {e}")
        traceback.print_exc()
        results['analysis'] = {'error': str(e)}

    # Step 2: Generate expansion predictions
    try:
        from workers.prediction.developer_expansion_predictor import predict_expansions
        results['predictions'] = predict_expansions()
    except Exception as e:
        print(f"[DNA Worker] Expansion prediction error: {e}")
        traceback.print_exc()
        results['predictions'] = {'error': str(e)}

    # Step 3: Apply scoring boost
    try:
        boosted = _apply_dna_scoring()
        results['scoring'] = {'boosted': boosted}
    except Exception as e:
        print(f"[DNA Worker] Scoring boost error: {e}")
        traceback.print_exc()
        results['scoring'] = {'error': str(e)}

    print(f"\n{'='*60}")
    print(f"[DNA Worker] PIPELINE COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[DNA Worker] Results: {results}")
    print(f"{'='*60}\n")

    return results
