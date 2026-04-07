"""
Distributed Scraping Engine / Collector Manager.
Manages multiple data collection workers with rate limiting,
retry logic, and health monitoring.

Provides:
  - Centralized collector registration and execution
  - Per-collector rate limiting and backoff
  - Health monitoring and failure tracking
  - Collector scheduling coordination
"""
import time
import traceback
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# Collector health tracking
_collector_stats = defaultdict(lambda: {
    'runs': 0,
    'successes': 0,
    'failures': 0,
    'last_run': None,
    'last_error': None,
    'total_signals': 0,
    'avg_duration': 0,
})

# Rate limit config (seconds between runs per collector)
DEFAULT_RATE_LIMIT = 300  # 5 minutes
RATE_LIMITS = {
    'news_collector': 600,
    'permits_collector': 300,
    'planning_agenda_collector': 600,
    'building_permit_collector': 600,
    'land_transaction_collector': 600,
    'plat_filing_collector': 600,
    'construction_financing_collector': 600,
    'entity_watcher': 300,
    'engineering_activity': 300,
    'site_prep_collector': 300,
    'utility_connection_collector': 300,
    'contractor_bid_collector': 300,
    'utility_connection_intel_collector': 600,
    'civil_engineering_collector': 600,
    'infrastructure_collector': 600,
    'entity_formation_collector': 600,
    'land_listing_collector': 600,
    'construction_hiring_collector': 600,
}

# Max retries per collector per cycle
MAX_RETRIES = 2
RETRY_BACKOFF_BASE = 5  # seconds


def register_collector(name, fn, rate_limit=None):
    """Register a collector with optional custom rate limit."""
    if rate_limit:
        RATE_LIMITS[name] = rate_limit
    return name


def _should_run(name):
    """Check if enough time has passed since last run."""
    stats = _collector_stats[name]
    if stats['last_run'] is None:
        return True
    limit = RATE_LIMITS.get(name, DEFAULT_RATE_LIMIT)
    elapsed = (datetime.utcnow() - stats['last_run']).total_seconds()
    return elapsed >= limit


def run_collector(name, fn, *args, **kwargs):
    """
    Run a single collector with retry logic and health tracking.
    Returns the number of signals collected (or 0 on failure).
    """
    if not _should_run(name):
        return 0

    stats = _collector_stats[name]
    stats['runs'] += 1
    stats['last_run'] = datetime.utcnow()

    start = time.time()
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = fn(*args, **kwargs)
            duration = time.time() - start
            count = result if isinstance(result, int) else 0

            stats['successes'] += 1
            stats['total_signals'] += count
            # Running average
            prev_avg = stats['avg_duration']
            stats['avg_duration'] = (prev_avg * (stats['successes'] - 1) + duration) / stats['successes']

            return count
        except Exception as e:
            last_error = str(e)
            if attempt < MAX_RETRIES:
                backoff = RETRY_BACKOFF_BASE * attempt
                print(f"[CollectorManager] {name} attempt {attempt} failed: {e}. "
                      f"Retrying in {backoff}s...")
                time.sleep(backoff)

    # All retries exhausted
    stats['failures'] += 1
    stats['last_error'] = last_error
    print(f"[CollectorManager] {name} FAILED after {MAX_RETRIES} attempts: {last_error}")
    return 0


def run_all_collectors(collectors):
    """
    Run a list of (name, fn) collector tuples with managed execution.
    Returns dict of {name: signal_count}.
    """
    print(f"[CollectorManager] Running {len(collectors)} collectors — "
          f"{datetime.utcnow().isoformat()}")

    results = {}
    for name, fn in collectors:
        count = run_collector(name, fn)
        results[name] = count

    total = sum(results.values())
    succeeded = sum(1 for c in results.values() if c >= 0)
    print(f"[CollectorManager] Complete: {total} signals from "
          f"{succeeded}/{len(collectors)} collectors")

    return results


def get_collector_health():
    """Return health status for all registered collectors."""
    health = {}
    for name, stats in _collector_stats.items():
        success_rate = (
            (stats['successes'] / max(stats['runs'], 1)) * 100
        )
        health[name] = {
            'runs': stats['runs'],
            'successes': stats['successes'],
            'failures': stats['failures'],
            'success_rate': round(success_rate, 1),
            'total_signals': stats['total_signals'],
            'avg_duration_s': round(stats['avg_duration'], 2),
            'last_run': stats['last_run'].isoformat() if stats['last_run'] else None,
            'last_error': stats['last_error'],
            'status': 'healthy' if success_rate >= 80 else 'degraded' if success_rate >= 50 else 'unhealthy',
        }
    return health


def log_collector_health():
    """Print collector health summary."""
    health = get_collector_health()
    if not health:
        print("[CollectorManager] No collector stats available yet")
        return

    print(f"\n[CollectorManager] COLLECTOR HEALTH REPORT")
    for name, info in sorted(health.items()):
        status = info['status'].upper()
        print(f"  {name}: {status} — "
              f"{info['success_rate']}% success, "
              f"{info['total_signals']} signals, "
              f"avg {info['avg_duration_s']}s")
        if info['last_error']:
            print(f"    Last error: {info['last_error'][:100]}")
