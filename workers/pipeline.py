"""
Lead Intelligence Pipeline Orchestrator.
Runs the full signal→lead pipeline as a sequence of stages.
Can be invoked as a scheduled job or triggered manually via API.
"""
import traceback
from datetime import datetime

from shared.queue import (
    enqueue, QUEUE_COLLECT, QUEUE_NORMALIZE, QUEUE_RESOLVE,
    QUEUE_ENRICH, QUEUE_SCORE, QUEUE_ROUTE, QUEUE_BRIEF,
)


def run_collection():
    """Stage 1: Collect signals from all sources."""
    from workers.collectors.news_collector import collect_news
    from workers.collectors.permits_collector import collect_permits

    print(f"[Pipeline] Stage 1: Collection — {datetime.utcnow().isoformat()}")
    total = 0
    try:
        total += collect_news()
    except Exception as e:
        print(f"[Pipeline] News collection error: {e}")
        traceback.print_exc()
    try:
        total += collect_permits()
    except Exception as e:
        print(f"[Pipeline] Permits collection error: {e}")
        traceback.print_exc()
    print(f"[Pipeline] Stage 1 complete: {total} signals collected")
    return total


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
