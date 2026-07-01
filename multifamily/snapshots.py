"""
Score / timing snapshot capture (outcome/snapshot/notification phase).

`snapshot_lead(lead, reason)` takes a point-in-time projection of a lead's
ALREADY-COMPUTED score + process-stage timing + attribution summary and
persists it as one row in multifamily_lead_snapshots. Pure recording — it
never recomputes scoring math and never mutates the lead; it just reads
`lead.score` (set by score_lead elsewhere) and re-derives the
(read-only, already-existing) process-stage/attribution views so the
history shows what the lead looked like at this moment.

Real leads only: demo lead ids regenerate every pipeline run, so a
snapshot on one would be orphaned before anyone could read it back.
"""
from typing import Any, Dict, Optional

from multifamily import repository
from multifamily.timing import detect_process_stage

# Every point in the lead lifecycle that triggers a snapshot:
#   created         - a brand-new real lead was persisted
#   signal_added    - an automated collector (multifamily/ingest.py) folded
#                     a new signal onto an already-known lead
#   merged          - a human-facing dedupe merge occurred (intake auto-merge
#                     or an admin-confirmed match-candidate merge)
#   outcome_changed - a business-outcome event was recorded
#   manual_rerun    - an operator explicitly asked for a fresh checkpoint
SNAPSHOT_REASONS = ['created', 'signal_added', 'merged', 'outcome_changed', 'manual_rerun']


def snapshot_lead(lead, reason: str) -> Optional[Dict[str, Any]]:
    """Persist a snapshot of `lead`'s current score/timing/attribution
    state. Returns the inserted row, or None for a demo lead (no-op) or an
    unrecognized reason (defensive — callers should only pass
    SNAPSHOT_REASONS values)."""
    if lead is None or getattr(lead, 'is_demo', False):
        return None
    if reason not in SNAPSHOT_REASONS:
        return None

    score = lead.score
    stage = detect_process_stage(lead)
    attribution = repository.get_attribution_summary(lead.id)

    return repository.insert_snapshot(
        lead.id, reason,
        score_total=(score.total if score else None),
        score_category=(score.category if score else None),
        reason_codes=(list(score.reason_codes) if score else []),
        disqualifier_codes=(list(score.disqualifier_codes) if score else []),
        process_stage=stage.process_stage,
        outreach_window=stage.outreach_window,
        timing_reason=stage.timing_reason,
        timing_confidence=stage.timing_confidence,
        urgency_label=stage.urgency_label,
        signal_count=len(lead.signals or []),
        attribution_summary=attribution,
    )
