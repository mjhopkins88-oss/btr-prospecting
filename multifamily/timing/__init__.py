"""
Process-stage timing intelligence for Multifamily Command.

Public API:
    detect_process_stage(lead) -> ProcessStageResult
    estimate_first_renewal(lead) -> Optional[Dict]
"""
from multifamily.timing.process_stage_types import (
    ProcessStageResult, PROCESS_STAGES, OUTREACH_WINDOWS, URGENCY_LABELS,
    PROCESS_STAGE_LABELS, OUTREACH_WINDOW_RANK, RENEWAL_BANDS,
)
from multifamily.timing.process_stage_detector import detect_process_stage
from multifamily.timing.first_renewal_estimator import estimate_first_renewal

__all__ = [
    'detect_process_stage', 'estimate_first_renewal', 'ProcessStageResult', 'PROCESS_STAGES',
    'OUTREACH_WINDOWS', 'URGENCY_LABELS', 'PROCESS_STAGE_LABELS', 'OUTREACH_WINDOW_RANK', 'RENEWAL_BANDS',
]
