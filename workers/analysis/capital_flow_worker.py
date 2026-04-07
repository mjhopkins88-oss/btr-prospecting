"""
Capital Flow Worker.
Scheduled pipeline that runs every 6 hours to:
1. Scan for loan signals from capital events
2. Scan for equity/JV signals from capital events
3. Cross-reference contractor activity with capital events
4. Analyze grouped signals and generate capital predictions

Railway cron: 0 */6 * * *
"""
import traceback
from datetime import datetime


def run_capital_flow_pipeline():
    """
    Full capital flow detection pipeline.
    """
    print(f"\n{'='*60}")
    print(f"[CapitalFlowWorker] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Scan loan signals
    try:
        from workers.analysis.capital_flow_engine import scan_loan_signals
        count = scan_loan_signals()
        results['loan_signals'] = count
        print(f"[CapitalFlowWorker] Loan signals ingested: {count}")
    except Exception as e:
        print(f"[CapitalFlowWorker] Loan signal scan error: {e}")
        traceback.print_exc()
        results['loan_signals'] = {'error': str(e)}

    # Step 2: Scan equity/JV signals
    try:
        from workers.analysis.capital_flow_engine import scan_equity_signals
        count = scan_equity_signals()
        results['equity_signals'] = count
        print(f"[CapitalFlowWorker] Equity signals ingested: {count}")
    except Exception as e:
        print(f"[CapitalFlowWorker] Equity signal scan error: {e}")
        traceback.print_exc()
        results['equity_signals'] = {'error': str(e)}

    # Step 3: Cross-reference contractor capital signals
    try:
        from workers.analysis.capital_flow_engine import scan_contractor_capital_signals
        count = scan_contractor_capital_signals()
        results['contractor_capital_signals'] = count
        print(f"[CapitalFlowWorker] Contractor capital signals ingested: {count}")
    except Exception as e:
        print(f"[CapitalFlowWorker] Contractor capital scan error: {e}")
        traceback.print_exc()
        results['contractor_capital_signals'] = {'error': str(e)}

    # Step 4: Analyze signals and generate capital predictions
    try:
        from workers.analysis.capital_flow_engine import analyze_capital_signals
        predictions = analyze_capital_signals()
        results['predictions_generated'] = len(predictions)
        results['predictions'] = predictions
        print(f"[CapitalFlowWorker] Predictions generated: {len(predictions)}")
        for p in predictions:
            amt = f" — ${p['estimated_amount']/1_000_000:.0f}M" if p.get('estimated_amount') else ''
            print(f"  - {p['developer_name']} → {p['city']}, {p['state']} "
                  f"({p['capital_event']}{amt}, confidence: {p['confidence']}%)")
    except Exception as e:
        print(f"[CapitalFlowWorker] Analysis error: {e}")
        traceback.print_exc()
        results['predictions_generated'] = {'error': str(e)}

    print(f"\n{'='*60}")
    print(f"[CapitalFlowWorker] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[CapitalFlowWorker] Results: {results}")
    print(f"{'='*60}\n")

    return results
