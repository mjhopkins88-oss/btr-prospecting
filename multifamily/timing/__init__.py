"""
Process-stage timing intelligence for Multifamily Command.

Public API:
    detect_process_stage(lead) -> ProcessStageResult
"""
from multifamily.timing.process_stage_types import (
    ProcessStageResult, PROCESS_STAGES, OUTREACH_WINDOWS, URGENCY_LABELS,
    PROCESS_STAGE_LABELS, OUTREACH_WINDOW_RANK,
)
from multifamily.timing.process_stage_detector import detect_process_stage

__all__ = [
    'detect_process_stage', 'ProcessStageResult', 'PROCESS_STAGES',
    'OUTREACH_WINDOWS', 'URGENCY_LABELS', 'PROCESS_STAGE_LABELS', 'OUTREACH_WINDOW_RANK',
]
