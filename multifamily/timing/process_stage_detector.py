"""
Detect a lead's process stage across the insurance opportunity lifecycle
and assemble the full timing result (stage, outreach window, urgency,
reason, recommended contact roles, and message angle).

Implements Part 4 rules 1-12. Pure analytics — never touches scoring.
Reuses multifamily/stage_timing.compute_stage_timing() to refine the
construction sub-stages and detect "possibly late" groundbreaking.
"""
from typing import Any, Dict, Optional

from multifamily.types import MultifamilyLead
from multifamily.stage_timing import compute_stage_timing
from multifamily.timing.process_stage_types import (
    ProcessStageResult, PROCESS_STAGE_LABELS,
)
from multifamily.timing.outreach_window_engine import (
    window_with_urgency, renewal_band as _renewal_band, POST_RENEWAL_ACTIVE_MAX_DAYS,
)
from multifamily.timing.timing_reason_builder import build_timing_reason
from multifamily.timing.contact_role_recommender import recommend_contact_roles
from multifamily.timing.message_angle_recommender import recommend_message_angle

# Rule 1: direct inbound actions (a prospect raising their hand).
INBOUND_REQUEST_SIGNALS = {
    'benchmark_form_submit', 'quote_request', 'meeting_request',
    'calculator_submit', 'guide_download', 'linkedin_lead_form_submit',
}
# Passive on-site/search interest — not a form submission.
WEBSITE_INTENT_SIGNALS = {
    'website_visit', 'repeat_website_visit', 'keyword_intent', 'paid_search_click',
}
WARM_WEBSITE_INTENT_SIGNALS = {'repeat_website_visit', 'paid_search_click'}

_CONSTRUCTION_SIGNALS = {'permit_filed', 'planning_approval', 'groundbreaking', 'vertical_construction', 'completion'}
_CONSTRUCTION_TIMING_SIGNALS = {'groundbreaking', 'vertical_construction', 'completion'}


def _signal_types(lead: MultifamilyLead) -> set:
    return {s.signal_type for s in lead.signals}


def _renewal_days(lead: MultifamilyLead) -> Optional[int]:
    for s in lead.signals:
        if s.signal_type == 'renewal_date_known':
            days = (s.detail or {}).get('days_until_renewal')
            if isinstance(days, (int, float)):
                return int(days)
    return None


def _has_builders_risk_context(lead: MultifamilyLead) -> bool:
    return 'builders_risk_need' in (lead.pain_flags or []) or 'lender_requirement' in (lead.pain_flags or [])


def _confidence(lead: MultifamilyLead, driving_signal_types: set) -> str:
    """Rough timing confidence: self-reported/direct inbound = high,
    third-party feeds (permit/news) = medium, thin/no timing = low."""
    relevant = [s for s in lead.signals if s.signal_type in driving_signal_types]
    self_reported = any((s.detail or {}).get('self_reported') for s in relevant)
    if self_reported or (lead.primary_source in ('form', 'benchmark_form', 'manual', 'crm')):
        return 'high'
    if relevant and max((s.confidence or 0) for s in relevant) >= 0.6:
        return 'medium'
    if not relevant:
        return 'low'
    return 'medium'


def _result(lead, stage, context, driving_signals) -> ProcessStageResult:
    window, urgency = window_with_urgency(stage, context)
    band = _renewal_band(context.get('days_until_renewal')) if stage == 'renewal_window' else None
    return ProcessStageResult(
        process_stage=stage,
        stage_label=PROCESS_STAGE_LABELS.get(stage, stage),
        outreach_window=window,
        urgency_label=urgency,
        timing_reason=build_timing_reason(stage, window, context),
        recommended_contact_roles=recommend_contact_roles(stage),
        recommended_message_angle=recommend_message_angle(stage, lead, renewal_band=band),
        timing_confidence=_confidence(lead, driving_signals),
        renewal_band=band,
    )


def detect_process_stage(lead: MultifamilyLead) -> ProcessStageResult:
    types = _signal_types(lead)
    renewal_days = _renewal_days(lead)

    # Rule 1 — direct inbound request wins over everything (they asked).
    if types & INBOUND_REQUEST_SIGNALS:
        ctx: Dict[str, Any] = {'days_until_renewal': renewal_days}
        return _result(lead, 'inbound_request', ctx, INBOUND_REQUEST_SIGNALS)

    # Rule 4 — acquisition / due diligence.
    if 'acquisition' in types:
        return _result(lead, 'acquisition_due_diligence', {}, {'acquisition'})

    # Rule 5/6 — refinance / financing (with builder's-risk context -> loan closing).
    if types & {'refinance', 'financing'}:
        if _has_builders_risk_context(lead) and (types & _CONSTRUCTION_SIGNALS):
            return _result(lead, 'construction_loan_closing', {}, {'refinance', 'financing'})
        return _result(lead, 'refinance_or_financing', {}, {'refinance', 'financing'})

    # Construction loan / builder's risk without an explicit financing signal,
    # but with a construction signal + builder's-risk requirement (Rule 6).
    if _has_builders_risk_context(lead) and (types & {'permit_filed', 'planning_approval'}):
        return _result(lead, 'construction_loan_closing', {}, {'permit_filed', 'planning_approval'})

    # Rule 2/3 & 11 — renewal timing.
    if 'renewal_date_known' in types:
        if renewal_days is not None and renewal_days < 0:
            days_since_renewal = -renewal_days
            if days_since_renewal <= POST_RENEWAL_ACTIVE_MAX_DAYS:
                # Active relationship-building window (Rule 11 refined) —
                # no deadline pressure, but a real window, not a cooldown.
                return _result(
                    lead, 'post_renewal_active', {'days_since_renewal': days_since_renewal}, {'renewal_date_known'},
                )
            return _result(lead, 'post_renewal', {}, {'renewal_date_known'})  # Rule 11 (stale)
        return _result(lead, 'renewal_window', {'days_until_renewal': renewal_days}, {'renewal_date_known'})

    # Rules 7-10 — construction lifecycle (refined via compute_stage_timing).
    if types & _CONSTRUCTION_SIGNALS:
        timing = compute_stage_timing(lead) or {}
        current = timing.get('current_stage')

        if current == 'completion' or 'completion' in types:  # Rule 10
            completion_days = timing.get('days_in_stage')
            return _result(lead, 'completion_or_lease_up', {'completion_days': completion_days}, {'completion'})

        if current in ('groundbreaking', 'vertical_construction') or (types & {'groundbreaking', 'vertical_construction'}):  # Rule 9
            return _result(lead, 'construction_start', {'possibly_late': True}, _CONSTRUCTION_TIMING_SIGNALS)

        if 'permit_filed' in types:  # Rule 7
            return _result(lead, 'entitlement_or_permit', {'permit_issued': True}, {'permit_filed'})

        # Rule 8 — entitlement only (planning approval, no permit/construction/financing).
        return _result(lead, 'entitlement_or_permit', {'permit_issued': False, 'has_other_timing': False}, {'planning_approval'})

    # Website-intent-only leads — interest, but no concrete insurance event.
    if types & WEBSITE_INTENT_SIGNALS:
        warm = bool(types & WARM_WEBSITE_INTENT_SIGNALS)
        return _result(lead, 'general_watchlist', {'warm_website_intent': warm}, WEBSITE_INTENT_SIGNALS)

    # Rule 12 — news-only / portfolio growth / no timing.
    return _result(lead, 'general_watchlist', {}, types)
