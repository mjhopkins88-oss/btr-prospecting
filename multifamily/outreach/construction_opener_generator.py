"""
Opener generator for construction-stage triggers (permits, groundbreaking,
vertical construction, completion).
"""
from multifamily.types import MultifamilyLead
from multifamily.outreach.nepq_multifamily_angle_builder import build_angle

_STAGE_LABELS = {
    'permit_filed': 'the permit filing',
    'planning_approval': 'the planning approval',
    'groundbreaking': 'breaking ground',
    'vertical_construction': 'construction being underway',
    'completion': 'construction wrapping up',
}


def generate(lead: MultifamilyLead) -> str:
    angle = build_angle(lead)
    stage_signal = next(
        (s for s in lead.signals if s.signal_type in _STAGE_LABELS), None
    )
    stage_label = _STAGE_LABELS.get(
        stage_signal.signal_type if stage_signal else None, 'the current construction stage'
    )

    builders_risk_note = (
        " Worth a quick conversation about builder's risk coverage while the project's active."
        if 'builders_risk_need' in lead.pain_flags
        else ''
    )

    return (
        f"Saw {stage_label} at {lead.property.name}. {angle}{builders_risk_note} "
        f"Happy to do a quick benchmark whenever it's convenient."
    )
