"""
Assign an outreach window (and urgency label) from a lead's process
stage plus timing context. The detector gathers the context (renewal
days, whether a permit was issued, completion recency, etc.); this engine
is the single source of truth for stage + context -> window.
"""
from typing import Any, Dict, Tuple

from multifamily.timing.process_stage_types import URGENCY_LABELS

# Renewal-day thresholds (Part 4 rules 2 & 3).
_RENEWAL_THIS_WEEK_MAX = 45        # <=45 days out -> this_week
_RENEWAL_NEXT_30_MAX = 120         # 46-120 days   -> next_30_days
_RENEWAL_NEXT_60_MAX = 150         # 121-150 days  -> next_60_days
_RENEWAL_NEXT_90_MAX = 180         # 151-180 days  -> next_90_days
                                    # >180 days     -> nurture

_COMPLETION_THIS_WEEK_MAX = 30     # completed/CO within 30 days -> this_week
_COMPLETION_NEXT_30_MAX = 120      # within 120 days -> next_30_days; older -> too_late


def assign_outreach_window(process_stage: str, context: Dict[str, Any]) -> str:
    if process_stage == 'inbound_request':
        return 'immediate'

    if process_stage == 'renewal_window':
        days = context.get('days_until_renewal')
        if days is None:
            return 'next_30_days'  # known renewal, unknown precise date
        if days <= _RENEWAL_THIS_WEEK_MAX:
            return 'this_week'
        if days <= _RENEWAL_NEXT_30_MAX:
            return 'next_30_days'
        if days <= _RENEWAL_NEXT_60_MAX:
            return 'next_60_days'
        if days <= _RENEWAL_NEXT_90_MAX:
            return 'next_90_days'
        return 'nurture'

    if process_stage in ('acquisition_due_diligence', 'refinance_or_financing', 'construction_loan_closing'):
        return 'this_week'

    if process_stage == 'construction_start':
        # Groundbreaking already announced — builder's risk may already be
        # bound, so it's worth a fast touch but flagged as possibly late.
        return 'this_week'

    if process_stage == 'entitlement_or_permit':
        # Rule 7: permit issued, no construction start -> next_30_days.
        # Rule 8: entitlement only -> nurture unless other (financing/
        # construction) timing exists.
        if context.get('permit_issued') or context.get('has_other_timing'):
            return 'next_30_days'
        return 'nurture'

    if process_stage == 'completion_or_lease_up':
        days = context.get('completion_days')
        if days is None:
            return 'next_30_days'
        if days <= _COMPLETION_THIS_WEEK_MAX:
            return 'this_week'
        if days <= _COMPLETION_NEXT_30_MAX:
            return 'next_30_days'
        return 'too_late'

    if process_stage == 'post_renewal':
        return 'nurture'

    # general_watchlist
    if context.get('warm_website_intent'):
        return 'next_30_days'
    return 'nurture'


def window_with_urgency(process_stage: str, context: Dict[str, Any]) -> Tuple[str, str]:
    window = assign_outreach_window(process_stage, context)
    return window, URGENCY_LABELS.get(window, window)
