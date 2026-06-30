"""
Process-stage timing intelligence — shared constants and result type.

This is the broad *insurance opportunity lifecycle* classifier, distinct
from (and complementary to) multifamily/stage_timing.py, which only
covers the construction sub-stages and answers "is this construction
lead stalled?". The process-stage system answers, for ANY lead: where is
this in the insurance buying timeline, how soon should we reach out, why,
who should we talk to, and what angle should we open with.

Pure analytics — never feeds into multifamily/scoring/. Computed live at
serialize time (api/routes/multifamily.py), never persisted, because
windows/urgency are time-dependent (a "renewal in 90 days" becomes "in
30 days" without the lead ever being re-submitted).
"""
from dataclasses import dataclass, field
from typing import List

# ---- Process stages (the insurance opportunity lifecycle) ----
PROCESS_STAGES = [
    'inbound_request',
    'renewal_window',
    'acquisition_due_diligence',
    'refinance_or_financing',
    'entitlement_or_permit',
    'construction_loan_closing',
    'construction_start',
    'completion_or_lease_up',
    'post_renewal',
    'general_watchlist',
]

PROCESS_STAGE_LABELS = {
    'inbound_request': 'Inbound Request',
    'renewal_window': 'Renewal Window',
    'acquisition_due_diligence': 'Acquisition / Due Diligence',
    'refinance_or_financing': 'Refinance / Financing',
    'entitlement_or_permit': 'Entitlement / Permit',
    'construction_loan_closing': 'Construction Loan / Builder\'s Risk',
    'construction_start': 'Construction Start',
    'completion_or_lease_up': 'Completion / Lease-Up',
    'post_renewal': 'Post-Renewal',
    'general_watchlist': 'General Watchlist',
}

# ---- Outreach windows (how soon to reach out) ----
OUTREACH_WINDOWS = [
    'immediate', 'this_week', 'next_30_days', 'next_60_days',
    'next_90_days', 'nurture', 'too_early', 'too_late',
]

URGENCY_LABELS = {
    'immediate': 'Call today',
    'this_week': 'This week',
    'next_30_days': 'Next 30 days',
    'next_60_days': 'Next 60 days',
    'next_90_days': 'Next 90 days',
    'nurture': 'Nurture',
    'too_early': 'Too early',
    'too_late': 'Likely too late',
}

# Sort weight so the UI/API can rank by urgency (higher = sooner).
OUTREACH_WINDOW_RANK = {
    'immediate': 7,
    'this_week': 6,
    'next_30_days': 5,
    'next_60_days': 4,
    'next_90_days': 3,
    'too_late': 2,
    'nurture': 1,
    'too_early': 0,
}

TIMING_CONFIDENCE_LEVELS = ['high', 'medium', 'low']

# ---- Recommended contact roles by stage ----
CONTACT_ROLES = {
    'inbound_request': ['Insurance / Risk decision-maker', 'Owner / Principal'],
    'renewal_window': ['Risk Manager', 'VP of Risk / Insurance', 'Controller / CFO'],
    'acquisition_due_diligence': ['Acquisitions', 'Asset Management', 'CFO / Finance'],
    'refinance_or_financing': ['CFO / Finance', 'Capital Markets', 'Controller'],
    'entitlement_or_permit': ['Development', 'Project Manager'],
    'construction_loan_closing': ['Construction / Development', 'CFO / Finance', 'Project Executive'],
    'construction_start': ['Construction / Development', 'Project Executive', 'Risk Manager'],
    'completion_or_lease_up': ['Asset Management', 'Operations', 'Risk Manager'],
    'post_renewal': ['Risk Manager', 'Owner / Principal'],
    'general_watchlist': ['Owner / Principal', 'Risk Manager'],
}

# ---- Recommended message angles by stage (exact copy, neutral/benchmark tone) ----
# These are the operator's opening question — calm, curious, not pushy, no
# savings claims, no fake familiarity.
MESSAGE_ANGLES = {
    'renewal_window': (
        "Are you far enough ahead of renewal to pressure test the property and liability "
        "structure, or has the current broker already started running the process?"
    ),
    'acquisition_due_diligence': (
        "When you're underwriting a new acquisition, do you usually rely on the seller's "
        "current insurance numbers, or do you independently pressure test property, GL, "
        "excess, and deductibles before close?"
    ),
    'refinance_or_financing': (
        "Are the lender insurance requirements already cleared, or are there still open items "
        "around property, GL, excess, deductibles, exclusions, or escrow?"
    ),
    'construction_loan_closing': (
        "Has builder's risk already been locked in, or is that still a moving piece as you get "
        "closer to construction?"
    ),
    'construction_start': (
        "Has builder's risk already been locked in, or is that still a moving piece as you get "
        "closer to construction?"
    ),
    'entitlement_or_permit': (
        "Has builder's risk already been locked in, or is that still a moving piece as you get "
        "closer to construction?"
    ),
    'completion_or_lease_up': (
        "Have you already mapped the transition from builder's risk to operating property and "
        "GL as buildings come online?"
    ),
    'post_renewal': (
        "Not looking to disrupt anything right after renewal, but did the insurance outcome land "
        "cleanly enough that you'd repeat the same process next year?"
    ),
}

# Neutral benchmark angle for inbound requests and watchlist leads with no
# specific lifecycle context.
DEFAULT_MESSAGE_ANGLE = (
    "Would it be useful to pressure test your current property and liability structure against "
    "where multifamily insurance pricing has moved this year, or is the current program already "
    "where you want it?"
)


@dataclass
class ProcessStageResult:
    process_stage: str
    stage_label: str
    outreach_window: str
    urgency_label: str
    timing_reason: str
    recommended_contact_roles: List[str] = field(default_factory=list)
    recommended_message_angle: str = DEFAULT_MESSAGE_ANGLE
    timing_confidence: str = 'medium'
