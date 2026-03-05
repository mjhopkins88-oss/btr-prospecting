"""
Pattern Scan Worker.
Scheduled pipeline that runs every 12 hours to:
1. Ingest signals into pattern_signal_history
2. Run pattern detection against development_patterns
3. Store pattern_matches
4. Boost predicted development scores
"""
import traceback
from datetime import datetime


def run_pattern_scan_pipeline():
    """
    Full predictive pattern engine pipeline.
    """
    print(f"\n{'='*60}")
    print(f"[PatternScanWorker] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Run existing event generation + BTR pattern detection
    try:
        from workers.jobs.pattern_scan_job import run_pattern_scan
        scan_results = run_pattern_scan()
        results['pattern_scan'] = scan_results
    except Exception as e:
        print(f"[PatternScanWorker] Pattern scan error: {e}")
        traceback.print_exc()
        results['pattern_scan'] = {'error': str(e)}

    # Step 2: Ingest signals into pattern_signal_history
    try:
        from workers.analysis.pattern_detection_engine import ingest_signals_to_history
        ingested = ingest_signals_to_history()
        results['signals_ingested'] = ingested
    except Exception as e:
        print(f"[PatternScanWorker] Signal ingestion error: {e}")
        traceback.print_exc()
        results['signals_ingested'] = 0

    # Step 3: Detect pattern matches
    try:
        from workers.analysis.pattern_detection_engine import detect_pattern_matches
        matches = detect_pattern_matches()
        results['pattern_matches'] = matches
    except Exception as e:
        print(f"[PatternScanWorker] Pattern detection error: {e}")
        traceback.print_exc()
        results['pattern_matches'] = {'error': str(e)}

    # Step 4: Boost predictions from pattern matches
    try:
        from workers.analysis.pattern_detection_engine import boost_predictions_from_patterns
        boosted = boost_predictions_from_patterns()
        results['predictions_boosted'] = boosted
    except Exception as e:
        print(f"[PatternScanWorker] Score boost error: {e}")
        traceback.print_exc()
        results['predictions_boosted'] = 0

    print(f"\n{'='*60}")
    print(f"[PatternScanWorker] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[PatternScanWorker] Results: {results}")
    print(f"{'='*60}\n")

    return results
