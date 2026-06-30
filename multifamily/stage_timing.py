"""
Phase 5: process-stage timing intelligence for construction-trigger leads.

Pure analytics layer — does NOT feed into multifamily/scoring/ at all.
Surfaces whether a lead's construction process (permit filed -> planning
approval -> groundbreaking -> vertical construction -> completion)
appears to be on track, due soon, or stalled, relative to rough
planning-stage benchmarks. These benchmarks are a reasonable v1 starting
point, not calibrated against real historical outcomes yet — treat them
as a planning heuristic, not a guarantee.

Always computed live at read/serialize time (see api/routes/multifamily.py),
never persisted: "days in stage" grows every day regardless of whether
the lead is re-submitted, so freezing a snapshot at insert time would go
stale almost immediately. This mirrors why_warm/likely_pain in spirit
but is intentionally NOT stored on the lead the way those are.
"""
from datetime import datetime
from typing import Any, Dict, Optional

from multifamily.types import MultifamilyLead

# Ordered earliest -> latest. A lead may carry more than one of these
# signals as a project progresses; the most advanced one wins.
CONSTRUCTION_STAGE_ORDER = [
    'permit_filed', 'planning_approval', 'groundbreaking', 'vertical_construction', 'completion',
]

STAGE_LABELS = {
    'permit_filed': 'Permit Filed',
    'planning_approval': 'Planning Approval',
    'groundbreaking': 'Groundbreaking',
    'vertical_construction': 'Vertical Construction',
    'completion': 'Completion',
}

# Rough planning-stage benchmarks (days) for how long a project typically
# stays at a given stage before moving to the next one. No expected
# duration for 'completion' — there's no "next" stage.
EXPECTED_DAYS_TO_NEXT_STAGE = {
    'permit_filed': 60,
    'planning_approval': 45,
    'groundbreaking': 30,
    'vertical_construction': 270,
}

# Once a lead has used up this fraction of its expected window without
# advancing, flag it as "due_soon" (an early warning before "overdue").
DUE_SOON_THRESHOLD = 0.8

TIMING_STATUSES = ['on_track', 'due_soon', 'overdue', 'completed', 'unknown']


def _days_since(occurred_at: Optional[str]) -> Optional[int]:
    if not occurred_at:
        return None
    try:
        ts = datetime.fromisoformat(str(occurred_at))
    except ValueError:
        return None
    return max(0, (datetime.utcnow() - ts).days)


def _explain(stage_label: str, days_in_stage: Optional[int], expected_days: Optional[int], timing_status: str) -> str:
    if timing_status == 'completed':
        return 'Construction completed.'
    if days_in_stage is None:
        return f'At {stage_label}, but the signal has no usable timestamp to measure timing against.'
    if expected_days is None:
        return f'At {stage_label} for {days_in_stage} day(s) — no benchmark duration available for this stage.'
    if timing_status == 'overdue':
        return (f'At {stage_label} for {days_in_stage} days — typically progresses to the next stage '
                f'within {expected_days} days. This lead may be stalled.')
    if timing_status == 'due_soon':
        return (f'At {stage_label} for {days_in_stage} days, approaching the typical {expected_days}-day '
                f'window to the next stage. Worth checking in.')
    return f'At {stage_label} for {days_in_stage} days — on track within the typical {expected_days}-day window.'


def compute_stage_timing(lead: MultifamilyLead) -> Optional[Dict[str, Any]]:
    """Return a stage-timing insight for the lead's most advanced
    construction-stage signal, or None if it has no construction signal
    at all (most leads — this is purely additive for construction
    triggers)."""
    stage_signals = [s for s in lead.signals if s.signal_type in CONSTRUCTION_STAGE_ORDER]
    if not stage_signals:
        return None

    current_signal = max(stage_signals, key=lambda s: CONSTRUCTION_STAGE_ORDER.index(s.signal_type))
    current_stage = current_signal.signal_type
    days_in_stage = _days_since(current_signal.occurred_at)
    expected_days = EXPECTED_DAYS_TO_NEXT_STAGE.get(current_stage)

    if current_stage == 'completion':
        timing_status = 'completed'
    elif days_in_stage is None or expected_days is None:
        timing_status = 'unknown'
    elif days_in_stage > expected_days:
        timing_status = 'overdue'
    elif days_in_stage > expected_days * DUE_SOON_THRESHOLD:
        timing_status = 'due_soon'
    else:
        timing_status = 'on_track'

    stage_label = STAGE_LABELS.get(current_stage, current_stage)

    return {
        'current_stage': current_stage,
        'stage_label': stage_label,
        'days_in_stage': days_in_stage,
        'expected_days_to_next_stage': expected_days,
        'timing_status': timing_status,
        'explanation': _explain(stage_label, days_in_stage, expected_days, timing_status),
    }
