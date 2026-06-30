"""
Recommend the opening message angle for a lead, based on its process
stage. Uses the exact stage-specific copy in process_stage_types.

Special case: an inbound_request (someone literally raised their hand)
has no stage-specific angle of its own, so we look for the strongest
underlying lifecycle context among the lead's signals (renewal,
acquisition, refinance, construction, completion) and use that angle if
present. Otherwise we fall back to a neutral benchmark angle.
"""
from typing import Optional

from multifamily.types import MultifamilyLead
from multifamily.timing.process_stage_types import MESSAGE_ANGLES, DEFAULT_MESSAGE_ANGLE

# Signal type -> the lifecycle stage whose angle best fits it. Used only
# to refine inbound_request leads that ALSO carry a lifecycle trigger.
_SIGNAL_TO_ANGLE_STAGE = {
    'renewal_date_known': 'renewal_window',
    'acquisition': 'acquisition_due_diligence',
    'refinance': 'refinance_or_financing',
    'financing': 'refinance_or_financing',
    'permit_filed': 'entitlement_or_permit',
    'planning_approval': 'entitlement_or_permit',
    'groundbreaking': 'construction_start',
    'vertical_construction': 'construction_start',
    'completion': 'completion_or_lease_up',
}

# Order of preference when an inbound lead carries several lifecycle triggers.
_INBOUND_CONTEXT_PRIORITY = [
    'renewal_date_known', 'acquisition', 'refinance', 'financing',
    'completion', 'vertical_construction', 'groundbreaking',
    'permit_filed', 'planning_approval',
]


def _inbound_context_angle(lead: MultifamilyLead) -> Optional[str]:
    present = {s.signal_type for s in lead.signals}
    for signal_type in _INBOUND_CONTEXT_PRIORITY:
        if signal_type in present:
            stage = _SIGNAL_TO_ANGLE_STAGE.get(signal_type)
            if stage and stage in MESSAGE_ANGLES:
                return MESSAGE_ANGLES[stage]
    return None


def recommend_message_angle(process_stage: str, lead: MultifamilyLead) -> str:
    if process_stage in MESSAGE_ANGLES:
        return MESSAGE_ANGLES[process_stage]
    if process_stage == 'inbound_request':
        context_angle = _inbound_context_angle(lead)
        if context_angle:
            return context_angle
    return DEFAULT_MESSAGE_ANGLE
