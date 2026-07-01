"""
Assign an outreach window (and urgency label) from a lead's process
stage plus timing context. The detector gathers the context (renewal
days, whether a permit was issued, completion recency, etc.); this engine
is the single source of truth for stage + context -> window.
"""
from typing import Any, Dict, Optional, Tuple

from multifamily.timing.process_stage_types import URGENCY_LABELS

# Renewal engagement bands (Strategy Research §3/§8) — continuous, no
# gaps: rescue <=45 days, decision 46-90 days (BOR changes happen here),
# open >90 days. Used for MESSAGE POSTURE (renewal_band(), below);
# outreach_window scheduling (this_week/next_30_days/etc.) is a related
# but separate axis derived from the same day count.
_RESCUE_MAX_DAYS = 45
_DECISION_MAX_DAYS = 90
_RENEWAL_NURTURE_MIN_DAYS = 180     # >180 days out -> nurture (too far to act on yet)

_COMPLETION_THIS_WEEK_MAX = 30     # completed/CO within 30 days -> this_week
_COMPLETION_NEXT_30_MAX = 120      # within 120 days -> next_30_days; older -> too_late

# Post-renewal is an ACTIVE outreach window for the first 6 weeks (no
# deadline pressure, but maximum emotional salience) — beyond that it's
# stale and process_stage_detector falls back to plain 'post_renewal'.
POST_RENEWAL_ACTIVE_MAX_DAYS = 42


def renewal_band(days_until_renewal: Optional[int]) -> Optional[str]:
    """Continuous, gapless classification for message posture — 'rescue'
    (speed/market-access framing) vs. 'decision'/'open' (analysis/
    benchmarking framing). None when no renewal date is known."""
    if days_until_renewal is None:
        return None
    if days_until_renewal <= _RESCUE_MAX_DAYS:
        return 'rescue'
    if days_until_renewal <= _DECISION_MAX_DAYS:
        return 'decision'
    return 'open'


def assign_outreach_window(process_stage: str, context: Dict[str, Any]) -> str:
    if process_stage == 'inbound_request':
        return 'immediate'

    if process_stage == 'renewal_window':
        days = context.get('days_until_renewal')
        if days is None:
            return 'next_30_days'  # known renewal, unknown precise date
        band = renewal_band(days)
        if band == 'rescue':
            return 'this_week'
        if band == 'decision':
            return 'next_30_days'
        # open (>90 days) — still worth scheduling, just not urgent yet.
        if days <= _RENEWAL_NURTURE_MIN_DAYS:
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

    if process_stage == 'post_renewal_active':
        # Active relationship-building window (Strategy Research §3) —
        # no deadline, but a real window, not a cooldown.
        return 'next_30_days'

    if process_stage == 'post_renewal':
        return 'nurture'

    # general_watchlist
    if context.get('warm_website_intent'):
        return 'next_30_days'
    return 'nurture'


def window_with_urgency(process_stage: str, context: Dict[str, Any]) -> Tuple[str, str]:
    window = assign_outreach_window(process_stage, context)
    return window, URGENCY_LABELS.get(window, window)
