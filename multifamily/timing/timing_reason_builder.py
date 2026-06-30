"""
Build the human-readable `timing_reason` string shown on lead cards and
the lead-detail drawer — a one-line "why now" that explains the process
stage and outreach window in plain language.
"""
from typing import Any, Dict

from multifamily.timing.process_stage_types import PROCESS_STAGE_LABELS, URGENCY_LABELS


def build_timing_reason(process_stage: str, outreach_window: str, context: Dict[str, Any]) -> str:
    urgency = URGENCY_LABELS.get(outreach_window, outreach_window)

    if process_stage == 'inbound_request':
        return f"Direct inbound request — they raised their hand. {urgency}."

    if process_stage == 'renewal_window':
        days = context.get('days_until_renewal')
        if days is None:
            return f"Known renewal on the calendar but no precise date. {urgency}."
        return f"Renewal in ~{int(days)} days — ahead of the typical broker process. {urgency}."

    if process_stage == 'acquisition_due_diligence':
        return f"Acquisition / due diligence underway — coverage should be pressure-tested before close. {urgency}."

    if process_stage == 'refinance_or_financing':
        return f"Refinance / financing event — lender insurance requirements are likely in play. {urgency}."

    if process_stage == 'construction_loan_closing':
        return f"Construction loan / builder's risk requirement in motion. {urgency}."

    if process_stage == 'entitlement_or_permit':
        if context.get('permit_issued'):
            return f"Permit issued but construction hasn't started — coverage need is ahead. {urgency}."
        return f"Entitlement stage — early, but worth tracking for when financing/construction firms up. {urgency}."

    if process_stage == 'construction_start':
        if context.get('possibly_late'):
            return f"Construction already underway — builder's risk may already be bound, but worth a fast check. {urgency}."
        return f"Construction starting — builder's risk is a live decision. {urgency}."

    if process_stage == 'completion_or_lease_up':
        return f"Project completing / leasing up — transition from builder's risk to operating + GL. {urgency}."

    if process_stage == 'post_renewal':
        return f"Just past renewal — not the moment to disrupt, but a good time to plant for next cycle. {urgency}."

    # general_watchlist
    if context.get('warm_website_intent'):
        return f"Repeat interest with no concrete insurance event yet — worth a light touch. {urgency}."
    label = PROCESS_STAGE_LABELS.get(process_stage, process_stage)
    return f"{label}: no concrete insurance timing yet. {urgency}."
