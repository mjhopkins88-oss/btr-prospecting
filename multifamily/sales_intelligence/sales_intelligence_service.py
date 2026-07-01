"""
Sales Intelligence Service — thin named entry point re-exporting the
engine orchestrator. Exists so callers (API routes, Mission, follow-up
integration) can depend on a stable "service" name without duplicating
engine.py's orchestration logic.
"""
from multifamily.sales_intelligence.engine import build_sales_intelligence

__all__ = ['build_sales_intelligence']
