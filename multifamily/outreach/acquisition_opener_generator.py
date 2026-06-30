"""
Opener generator for acquisition/refinance/financing triggers.
"""
from multifamily.types import MultifamilyLead
from multifamily.outreach.nepq_multifamily_angle_builder import build_angle

_EVENT_LABELS = {
    'acquisition': 'the recent acquisition',
    'refinance': 'the recent refinance',
    'financing': 'the recent financing',
}


def generate(lead: MultifamilyLead) -> str:
    angle = build_angle(lead)
    event_signal = next(
        (s for s in lead.signals if s.signal_type in _EVENT_LABELS), None
    )
    event_label = _EVENT_LABELS.get(
        event_signal.signal_type if event_signal else None, 'the recent transaction'
    )

    return (
        f"Congrats on {event_label} involving {lead.property.name}. {angle} "
        f"Lenders often want a fresh look at coverage post-close — happy to "
        f"compare notes if it's a useful checkpoint right now."
    )
