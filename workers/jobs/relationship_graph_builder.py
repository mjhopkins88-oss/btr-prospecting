"""
Relationship Graph Builder Job.
Scheduled worker task that runs every 12 hours.
Orchestrates the full relationship graph pipeline.
"""
import traceback
from datetime import datetime


def run_relationship_graph_builder():
    """
    Full relationship graph pipeline:
    1. Scan signals → extract entity relationships
    2. Resolve developer LLC ownership
    3. Map parcel relationships
    4. Update prediction scores with relationship data
    """
    print(f"\n{'='*60}")
    print(f"[RelGraph] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Build entity relationships from events
    try:
        from workers.analysis.entity_relationship_builder import build_relationships_from_events
        rel_count = build_relationships_from_events()
        results['relationships_built'] = rel_count
    except Exception as e:
        print(f"[RelGraph] Entity relationship building error: {e}")
        traceback.print_exc()
        results['relationships_built'] = 0

    # Step 2: Resolve developer LLC ownership
    try:
        from workers.analysis.developer_entity_resolver import resolve_developer_ownership
        ownership_count = resolve_developer_ownership()
        results['ownership_resolved'] = ownership_count
    except Exception as e:
        print(f"[RelGraph] Developer resolution error: {e}")
        traceback.print_exc()
        results['ownership_resolved'] = 0

    # Step 3: Map parcel relationships
    try:
        from workers.analysis.parcel_relationship_mapper import map_parcel_relationships
        parcel_count = map_parcel_relationships()
        results['parcel_relationships'] = parcel_count
    except Exception as e:
        print(f"[RelGraph] Parcel mapping error: {e}")
        traceback.print_exc()
        results['parcel_relationships'] = 0

    # Step 4: Update prediction scores with relationship data
    try:
        updated = _update_prediction_relationships()
        results['predictions_updated'] = updated
    except Exception as e:
        print(f"[RelGraph] Prediction update error: {e}")
        traceback.print_exc()
        results['predictions_updated'] = 0

    print(f"\n{'='*60}")
    print(f"[RelGraph] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[RelGraph] Results: {results}")
    print(f"{'='*60}\n")

    return results


def _update_prediction_relationships():
    """
    Update predicted_projects with relationship data from the graph.
    This writes relationship_count, developer_linked, contractor_linked,
    consultant_linked back to predicted_projects.
    """
    from db import get_db
    from workers.search.relationship_graph_query import compute_relationship_data_for_prediction

    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT id, city, state, developer
        FROM predicted_projects
    ''')
    predictions = cur.fetchall()
    col_names = [d[0] for d in cur.description]

    if not predictions:
        conn.close()
        return 0

    updated = 0
    for row in predictions:
        pred = dict(zip(col_names, row))
        city = pred.get('city')
        state = pred.get('state')
        developer = pred.get('developer')

        if not city or not state:
            continue

        try:
            rel_data = compute_relationship_data_for_prediction(city, state, developer)

            cur.execute('''
                UPDATE predicted_projects
                SET relationship_count = ?,
                    developer_linked = ?,
                    contractor_linked = ?,
                    consultant_linked = ?
                WHERE id = ?
            ''', (
                rel_data['relationship_count'],
                bool(rel_data['developer_linked']),
                bool(rel_data['contractor_linked']),
                bool(rel_data['consultant_linked']),
                pred['id'],
            ))
            updated += 1
        except Exception as e:
            print(f"[RelGraph] Error updating prediction {pred['id']}: {e}")

    conn.commit()
    conn.close()
    print(f"[RelGraph] Updated {updated}/{len(predictions)} predictions with relationship data.")
    return updated
