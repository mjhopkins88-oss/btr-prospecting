"""
Pattern Scan Job.
Scheduled worker task that runs every 12 hours.
Generates development events from signals, then runs the BTR pattern detector.
"""
import traceback
from datetime import datetime


def run_pattern_scan():
    """
    Full pattern scan pipeline:
    1. Generate events from raw signals
    2. Detect BTR development patterns
    3. Store predicted projects
    4. Confirm existing predictions
    """
    print(f"\n{'='*60}")
    print(f"[PatternScan] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Generate development events from signals
    try:
        from workers.processing.event_generator import generate_all_events
        events_created = generate_all_events()
        results['events_created'] = events_created
    except Exception as e:
        print(f"[PatternScan] Event generation error: {e}")
        traceback.print_exc()
        results['events_created'] = 0

    # Step 2-4: Detect patterns, store predictions, confirm
    try:
        from workers.patterns.btr_pattern_detector import run_detection
        detection_results = run_detection()
        results.update(detection_results)
    except Exception as e:
        print(f"[PatternScan] Pattern detection error: {e}")
        traceback.print_exc()
        results['patterns_detected'] = 0
        results['predictions_stored'] = 0
        results['predictions_confirmed'] = 0

    print(f"\n{'='*60}")
    print(f"[PatternScan] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[PatternScan] Results: {results}")
    print(f"{'='*60}\n")

    return results
