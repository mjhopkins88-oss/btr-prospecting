"""
Sales Intelligence Service — thin named entry point re-exporting the
engine orchestrator. Exists so callers (API routes, Mission, follow-up
integration) can depend on a stable "service" name without duplicating
engine.py's orchestration logic.
"""
from multifamily.sales_intelligence.engine import build_sales_intelligence
from multifamily.sales_intelligence.nepq_types import SalesIntelligenceOutput


def generate_sales_intelligence_for_lead(lead) -> SalesIntelligenceOutput:
    """Single-argument service entry point: full SalesIntelligenceOutput
    for one lead, including that lead's own real activity/outcome history
    when it has any (demo leads have none — they're regenerated on every
    pipeline run, so there's nothing persisted to look up)."""
    if lead.is_demo:
        activities, outcomes = [], []
    else:
        from multifamily import repository
        activities = repository.get_activities_for_lead(lead.id)
        outcomes = repository.get_outcomes_for_lead(lead.id)
    return build_sales_intelligence(lead, activities=activities, outcomes=outcomes)


__all__ = ['build_sales_intelligence', 'generate_sales_intelligence_for_lead']
