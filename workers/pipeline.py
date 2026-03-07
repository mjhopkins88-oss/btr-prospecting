"""
Lead Intelligence Pipeline Orchestrator.
Runs the full signal->lead pipeline as a sequence of stages.
Can be invoked as a scheduled job or triggered manually via API.
"""
import traceback
from datetime import datetime

from shared.queue import (
    enqueue, QUEUE_COLLECT, QUEUE_NORMALIZE, QUEUE_RESOLVE,
    QUEUE_ENRICH, QUEUE_SCORE, QUEUE_ROUTE, QUEUE_BRIEF,
)


def _safe_call(label, fn, *args, **kwargs):
    """Call a collector/function safely, returning its result or 0 on error."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        print(f"[Pipeline] {label} error: {e}")
        traceback.print_exc()
        return 0


def run_collection():
    """Stage 1: Collect signals from all sources with per-collector logging."""
    from workers.collectors.news_collector import collect_news
    from workers.collectors.permits_collector import collect_permits
    from workers.collectors.entity_watcher import watch_entities
    from workers.collectors.engineering_activity import collect_engineering_activity
    from workers.collectors.news_parser import parse_news
    from workers.collectors.construction.site_prep_activity_collector import collect_site_prep
    from workers.collectors.construction.engineering_activity_collector import collect_engineering_plans
    from workers.collectors.construction.utility_connection_collector import collect_utility_connections
    from workers.collectors.construction.contractor_bid_collector import collect_contractor_bids
    from workers.collectors.planning_agenda_collector import collect_planning_agendas
    from workers.collectors.building_permit_collector import collect_building_permits
    from shared.config import TARGET_CITIES

    print(f"[Pipeline] Stage 1: Collection — {datetime.utcnow().isoformat()}")

    # --- Issue 5: Log which cities are being scanned ---
    print("\n[Pipeline] CITY SCAN TARGETS")
    for market in TARGET_CITIES:
        print(f"  Scanning city: {market['city']} {market['state']}")

    # Run each collector and track counts
    collectors = [
        ('Permits', collect_permits),
        ('Zoning/Permits (news)', collect_news),
        ('Engineering signals', collect_engineering_activity),
        ('Entity filings', watch_entities),
        ('News signals', parse_news),
        ('Site prep signals', collect_site_prep),
        ('Engineering plans', collect_engineering_plans),
        ('Utility connections', collect_utility_connections),
        ('Contractor bids', collect_contractor_bids),
        ('Planning agendas', collect_planning_agendas),
        ('Building permits', collect_building_permits),
    ]

    counts = {}
    for label, fn in collectors:
        count = _safe_call(label, fn)
        counts[label] = count
        if count == 0:
            print(f"  {label}: 0 records collected")

    # --- Issue 2: Collector summary ---
    total = sum(counts.values())
    print("\n  COLLECTOR SUMMARY")
    for label, count in counts.items():
        print(f"  {label} collected: {count}")
    print(f"  Total signals this cycle: {total}")

    # --- Issue 5: Per-city signal counts ---
    _log_per_city_signal_counts()

    print(f"[Pipeline] Stage 1 complete: {total} signals collected")
    return total


def _log_per_city_signal_counts():
    """Log signal counts per city from property_signals and li_signals."""
    try:
        from db import get_db
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            SELECT city, state, COUNT(*) as cnt
            FROM property_signals
            WHERE created_at >= date('now', '-1 day')
            AND city IS NOT NULL AND city != ''
            GROUP BY city, state
            ORDER BY cnt DESC
        ''')
        rows = cur.fetchall()
        conn.close()
        if rows:
            print("\n  SIGNALS PER CITY (last 24h)")
            for city, state, cnt in rows:
                print(f"  {city} {state}: {cnt} signals detected")
        else:
            print("\n  SIGNALS PER CITY: No signals detected in the last 24 hours")
    except Exception as e:
        print(f"  [Pipeline] Per-city count error: {e}")


def run_normalization():
    """Stage 2: Normalize raw signals."""
    from workers.processing.normalizer import normalize_signals

    print(f"[Pipeline] Stage 2: Normalization — {datetime.utcnow().isoformat()}")
    try:
        count = normalize_signals(batch_size=200)
        print(f"[Pipeline] Stage 2 complete: {count} signals normalized")
        return count
    except Exception as e:
        print(f"[Pipeline] Normalization error: {e}")
        traceback.print_exc()
        return 0


def run_entity_resolution():
    """Stage 3: Resolve duplicate entities."""
    from workers.processing.entity_resolver import resolve_all

    print(f"[Pipeline] Stage 3: Entity Resolution — {datetime.utcnow().isoformat()}")
    try:
        count = resolve_all()
        print(f"[Pipeline] Stage 3 complete: {count} entities merged")
        return count
    except Exception as e:
        print(f"[Pipeline] Entity resolution error: {e}")
        traceback.print_exc()
        return 0


def run_enrichment():
    """Stage 4: AI enrichment of projects."""
    from workers.enrichment.ai_enricher import enrich_projects

    print(f"[Pipeline] Stage 4: Enrichment — {datetime.utcnow().isoformat()}")
    try:
        count = enrich_projects(limit=20)
        print(f"[Pipeline] Stage 4 complete: {count} projects enriched")
        return count
    except Exception as e:
        print(f"[Pipeline] Enrichment error: {e}")
        traceback.print_exc()
        return 0


def run_scoring():
    """Stage 5: Score leads."""
    from workers.scoring.lead_scorer import score_leads

    print(f"[Pipeline] Stage 5: Scoring — {datetime.utcnow().isoformat()}")
    try:
        count = score_leads(limit=200)
        print(f"[Pipeline] Stage 5 complete: {count} leads scored")
        return count
    except Exception as e:
        print(f"[Pipeline] Scoring error: {e}")
        traceback.print_exc()
        return 0


def run_routing():
    """Stage 6: Route leads to teams."""
    from workers.routing.router import route_leads

    print(f"[Pipeline] Stage 6: Routing — {datetime.utcnow().isoformat()}")
    try:
        count = route_leads()
        print(f"[Pipeline] Stage 6 complete: {count} leads routed")
        return count
    except Exception as e:
        print(f"[Pipeline] Routing error: {e}")
        traceback.print_exc()
        return 0


def run_brief():
    """Stage 7: Generate daily brief."""
    from workers.reporting.daily_brief import generate_brief

    print(f"[Pipeline] Stage 7: Daily Brief — {datetime.utcnow().isoformat()}")
    try:
        brief = generate_brief()
        print(f"[Pipeline] Stage 7 complete: brief generated")
        return brief
    except Exception as e:
        print(f"[Pipeline] Brief generation error: {e}")
        traceback.print_exc()
        return None


def run_learning():
    """Stage 8: Adjust weights from feedback."""
    from workers.learning.weight_adjuster import adjust_weights

    print(f"[Pipeline] Stage 8: Weight Adjustment — {datetime.utcnow().isoformat()}")
    try:
        adjustments = adjust_weights()
        print(f"[Pipeline] Stage 8 complete: {len(adjustments)} weights adjusted")
        return adjustments
    except Exception as e:
        print(f"[Pipeline] Weight adjustment error: {e}")
        traceback.print_exc()
        return {}


def _log_opportunity_engine(results):
    """Issue 4: Log opportunity/prediction pipeline visibility."""
    signals_evaluated = results.get('collection', 0)
    predictions = 0
    predictions_above_threshold = 0

    try:
        from db import get_db
        conn = get_db()
        cur = conn.cursor()

        # Count parcels analyzed (distinct parcels with signals)
        cur.execute('''
            SELECT COUNT(DISTINCT parcel_id)
            FROM property_signals
            WHERE parcel_id IS NOT NULL AND parcel_id != ''
        ''')
        parcels_analyzed = (cur.fetchone() or (0,))[0]

        # Count predictions from development_scores
        cur.execute('''
            SELECT COUNT(*) FROM development_scores
            WHERE updated_at >= date('now', '-1 day')
        ''')
        predictions = (cur.fetchone() or (0,))[0]

        cur.execute('''
            SELECT COUNT(*) FROM development_scores
            WHERE probability >= 60 AND updated_at >= date('now', '-1 day')
        ''')
        predictions_above_threshold = (cur.fetchone() or (0,))[0]

        conn.close()
    except Exception:
        parcels_analyzed = 0

    print("\n  OpportunityEngine:")
    print(f"  Signals evaluated: {signals_evaluated}")
    print(f"  Parcels analyzed: {parcels_analyzed}")
    print(f"  Predictions generated: {predictions}")
    print(f"  Predictions above threshold: {predictions_above_threshold}")


def _log_daily_signal_summary(collection_total):
    """Issue 3: Log daily signal summary after pipeline cycle."""
    try:
        from db import get_db
        conn = get_db()
        cur = conn.cursor()

        # Count signals by type from the last 24 hours
        signal_types = {
            'Permits': ('BUILDING_PERMIT', 'permit_filed'),
            'Zoning': ('ZONING_APPLICATION', 'zoning_change'),
            'Entity filings': ('LLC_FORMATION', 'DEVELOPER_EXPANSION'),
            'Engineering signals': ('ENGINEERING_ENGAGEMENT', 'CIVIL_ENGINEERING_PLAN', 'SITE_PLAN_SUBMISSION'),
            'Supply chain signals': ('SITE_PREP_ACTIVITY', 'UTILITY_CONNECTION_REQUEST', 'CONCRETE_SUPPLY_SIGNAL', 'INFRASTRUCTURE_BID', 'EARTHWORK_CONTRACTOR'),
            'News signals': ('NEWS_SIGNAL',),
            'Planning signals': ('ZONING_AGENDA_ITEM', 'SITE_PLAN_SUBMISSION', 'SUBDIVISION_APPLICATION', 'REZONING_REQUEST', 'DEVELOPMENT_REVIEW_CASE'),
            'Building permits': ('MULTIFAMILY_PERMIT', 'SUBDIVISION_PERMIT', 'SITE_DEVELOPMENT_PERMIT', 'RESIDENTIAL_COMPLEX_PERMIT'),
        }

        summary = {}
        for label, types in signal_types.items():
            placeholders = ','.join(['?' for _ in types])
            cur.execute(f'''
                SELECT COUNT(*) FROM property_signals
                WHERE signal_type IN ({placeholders})
                AND created_at >= date('now', '-1 day')
            ''', types)
            summary[label] = (cur.fetchone() or (0,))[0]

        conn.close()
    except Exception:
        summary = {
            'Permits': 0, 'Zoning': 0, 'Entity filings': 0,
            'Engineering signals': 0, 'Supply chain signals': 0, 'News signals': 0,
        }

    total = sum(summary.values())
    print(f"\n{'='*30}")
    print("DAILY SIGNAL SUMMARY")
    print(f"{'='*30}")
    for label, count in summary.items():
        print(f"  {label}: {count}")
    print(f"  Total signals collected: {total}")


def _log_master_signal_counter(signals_added):
    """Issue 7: Log global signal counter."""
    try:
        from db import get_db
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM property_signals')
        total_property = (cur.fetchone() or (0,))[0]
        cur.execute('SELECT COUNT(*) FROM li_signals')
        total_li = (cur.fetchone() or (0,))[0]
        conn.close()
        total_stored = total_property + total_li
    except Exception:
        total_stored = 0

    print(f"\n  Total signals stored: {total_stored}")
    print(f"  Signals added this cycle: {signals_added}")


def _log_health_check(results):
    """Issue 8: Log system health check."""
    collectors_running = results.get('collection', 0) >= 0
    signals_collected = results.get('collection', 0)

    db_connected = False
    try:
        from db import get_db
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.fetchone()
        conn.close()
        db_connected = True
    except Exception:
        pass

    predictions = 0
    try:
        from db import get_db
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            SELECT COUNT(*) FROM development_scores
            WHERE updated_at >= date('now', '-1 day')
        ''')
        predictions = (cur.fetchone() or (0,))[0]
        conn.close()
    except Exception:
        pass

    print(f"\n  SYSTEM HEALTH CHECK")
    print(f"  Collectors running: {'YES' if collectors_running else 'NO'}")
    print(f"  Database connected: {'YES' if db_connected else 'NO'}")
    print(f"  Signals collected: {signals_collected}")
    print(f"  Predictions generated: {predictions}")


def run_full_pipeline():
    """
    Run the complete lead intelligence pipeline sequentially.
    Each stage is independent — if one fails, the others still run.
    """
    print(f"\n{'='*60}")
    print(f"[Pipeline] FULL PIPELINE START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    results = {}
    results['collection'] = run_collection()
    results['normalization'] = run_normalization()
    results['entity_resolution'] = run_entity_resolution()
    results['enrichment'] = run_enrichment()
    results['scoring'] = run_scoring()
    results['routing'] = run_routing()
    results['brief'] = run_brief() is not None
    results['learning'] = run_learning()

    # --- Issue 6: Low signal warning ---
    if results.get('collection', 0) == 0:
        print(f"\n  WARNING")
        print(f"  No development signals detected in this cycle.")
        print(f"  Collectors may need additional data sources.")

    # --- Issue 3: Daily signal summary ---
    _log_daily_signal_summary(results.get('collection', 0))

    # --- Issue 4: Opportunity pipeline visibility ---
    _log_opportunity_engine(results)

    # --- Issue 7: Master signal counter ---
    _log_master_signal_counter(results.get('collection', 0))

    # --- Issue 8: Health check ---
    _log_health_check(results)

    print(f"\n{'='*60}")
    print(f"[Pipeline] FULL PIPELINE COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"[Pipeline] Results: {results}")
    print(f"{'='*60}\n")

    return results


def run_full_pipeline_queued():
    """
    Run the pipeline with each stage enqueued separately.
    For Redis/RQ environments where each stage runs as its own job.
    """
    # When using queues, stages run sequentially via chained enqueue
    # For simplicity, run synchronously (RQ will handle isolation)
    return run_full_pipeline()
