"""
Market Expansion Job.
Weekly scheduled job that runs the full market expansion pipeline:
1. Discover new high-potential markets
2. Deploy collectors to activated markets
"""
import traceback
from datetime import datetime


def run_market_expansion():
    """
    Full market expansion pipeline:
    1. Run market discovery (score cities, identify new markets)
    2. Deploy collectors to new markets
    """
    print(f"\n{'='*60}")
    print(f"[MarketExpansion] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}

    # Step 1: Discover new markets
    try:
        from workers.market_analysis.market_discovery_worker import run_market_discovery
        discovery = run_market_discovery()
        results['discovery'] = discovery
    except Exception as e:
        print(f"[MarketExpansion] Discovery error: {e}")
        traceback.print_exc()
        results['discovery'] = {'error': str(e)}

    # Step 2: Deploy collectors
    try:
        from workers.collectors.collector_deployment_manager import deploy_collectors_for_new_markets
        activated = deploy_collectors_for_new_markets()
        results['collectors_deployed'] = activated
    except Exception as e:
        print(f"[MarketExpansion] Collector deployment error: {e}")
        traceback.print_exc()
        results['collectors_deployed'] = 0

    print(f"\n{'='*60}")
    print(f"[MarketExpansion] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[MarketExpansion] Results: {results}")
    print(f"{'='*60}\n")

    return results
