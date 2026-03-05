"""
Developer Intent Worker.
Scheduled pipeline that runs every 4 hours to:
1. Scan for contractor preconstruction signals
2. Scan for engineering engagement signals
3. Scan for entity formation signals
4. Scan for expansion/hiring signals
5. Analyze grouped signals and generate intent predictions

Railway cron: 0 */4 * * *
"""
import traceback
from datetime import datetime


def run_developer_intent_pipeline():
    """
    Full developer intent detection pipeline.
    """
    print(f"\n{'='*60}")
    print(f"[DeveloperIntentWorker] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Scan contractor preconstruction signals
    try:
        from workers.analysis.developer_intent_engine import scan_contractor_precon_signals
        count = scan_contractor_precon_signals()
        results['contractor_precon_signals'] = count
        print(f"[DeveloperIntentWorker] Contractor precon signals ingested: {count}")
    except Exception as e:
        print(f"[DeveloperIntentWorker] Contractor precon scan error: {e}")
        traceback.print_exc()
        results['contractor_precon_signals'] = {'error': str(e)}

    # Step 2: Scan engineering engagement signals
    try:
        from workers.analysis.developer_intent_engine import scan_engineering_signals
        count = scan_engineering_signals()
        results['engineering_signals'] = count
        print(f"[DeveloperIntentWorker] Engineering signals ingested: {count}")
    except Exception as e:
        print(f"[DeveloperIntentWorker] Engineering scan error: {e}")
        traceback.print_exc()
        results['engineering_signals'] = {'error': str(e)}

    # Step 3: Scan entity formation signals
    try:
        from workers.analysis.developer_intent_engine import scan_entity_formation_signals
        count = scan_entity_formation_signals()
        results['entity_formation_signals'] = count
        print(f"[DeveloperIntentWorker] Entity formation signals ingested: {count}")
    except Exception as e:
        print(f"[DeveloperIntentWorker] Entity formation scan error: {e}")
        traceback.print_exc()
        results['entity_formation_signals'] = {'error': str(e)}

    # Step 4: Scan expansion/hiring signals
    try:
        from workers.analysis.developer_intent_engine import scan_expansion_signals
        count = scan_expansion_signals()
        results['expansion_signals'] = count
        print(f"[DeveloperIntentWorker] Expansion signals ingested: {count}")
    except Exception as e:
        print(f"[DeveloperIntentWorker] Expansion scan error: {e}")
        traceback.print_exc()
        results['expansion_signals'] = {'error': str(e)}

    # Step 5: Analyze signals and generate intent predictions
    try:
        from workers.analysis.developer_intent_engine import analyze_intent_signals
        predictions = analyze_intent_signals()
        results['predictions_generated'] = len(predictions)
        results['predictions'] = predictions
        print(f"[DeveloperIntentWorker] Predictions generated: {len(predictions)}")
        for p in predictions:
            print(f"  - {p['developer_name']} → {p['city']}, {p['state']} "
                  f"(confidence: {p['confidence']}%, signals: {p['signal_count']})")
    except Exception as e:
        print(f"[DeveloperIntentWorker] Analysis error: {e}")
        traceback.print_exc()
        results['predictions_generated'] = {'error': str(e)}

    print(f"\n{'='*60}")
    print(f"[DeveloperIntentWorker] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[DeveloperIntentWorker] Results: {results}")
    print(f"{'='*60}\n")

    return results
