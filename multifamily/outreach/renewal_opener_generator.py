"""
Opener generator for renewal-timing triggers (renewal_date_known).
"""
from multifamily.types import MultifamilyLead
from multifamily.outreach.nepq_multifamily_angle_builder import build_angle


def generate(lead: MultifamilyLead) -> str:
    angle = build_angle(lead)
    renewal_signal = next(
        (s for s in lead.signals if s.signal_type == 'renewal_date_known'), None
    )
    days = (renewal_signal.detail or {}).get('days_until_renewal') if renewal_signal else None

    timing_clause = (
        f"with a renewal coming up in the next {int(days)} days"
        if isinstance(days, (int, float))
        else "with a renewal on the horizon"
    )

    return (
        f"Hi — saw {lead.company.name} is {timing_clause}. {angle} "
        f"No pressure either way — happy to share what we're seeing in "
        f"{lead.state or 'the market'} if it's useful before you're deep into renewal."
    )
