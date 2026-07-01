"""
Compact follow-up-suggestion formatting for the activity dashboard and
log-activity response. Deliberately Flask-independent (pure DB +
sales-intelligence engine) so it's testable without importing api/routes.
"""
from typing import Any, Dict, List, Optional

from multifamily import repository
from multifamily.sales_intelligence.engine import build_sales_intelligence


def build_follow_up_suggestion(lead) -> Optional[Dict[str, Any]]:
    """Which next touch to make on this lead, when, and why — reuses the
    same engine as the Mission/Workbench/drawer, but only surfaces the
    follow_up_strategy slice (not the full package)."""
    if not lead:
        return None
    try:
        activities = repository.get_activities_for_lead(lead.id)
        outcomes = repository.get_outcomes_for_lead(lead.id)
        pkg = build_sales_intelligence(lead, activities=activities, outcomes=outcomes)
    except Exception:
        return None
    fu = pkg.follow_up_strategy
    return {
        'follow_up_type': fu.follow_up_type,
        'message_field': fu.message_field,
        'recommended_wait_days': fu.recommended_wait_days,
        'reasoning': fu.reasoning,
        'is_final_attempt': fu.is_final_attempt,
        'suggested_message': (getattr(pkg.messages, fu.message_field) if fu.message_field else None),
    }


def attach_follow_up_suggestions(items: List[Dict[str, Any]], lead_id_key: str = 'lead_id') -> List[Dict[str, Any]]:
    """Additive `suggested_follow_up` on each dict in an activity-dashboard
    list, looked up by the lead_id already present on that row."""
    for item in items:
        item['suggested_follow_up'] = build_follow_up_suggestion(repository.get_lead_by_id(item.get(lead_id_key)))
    return items
