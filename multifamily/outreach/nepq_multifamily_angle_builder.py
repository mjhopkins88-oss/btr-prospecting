"""
NEPQ-style (neutral, curious, question-led) angle builder for multifamily
insurance outreach.

Tone rules: neutral, calm, curious, not pushy, benchmark-oriented, no hard
selling, no exaggerated claims. This module produces the underlying
"angle" (the situational hook + curiosity question); the per-trigger
opener generators wrap it into a full opener.
"""
from multifamily.types import MultifamilyLead

_ASSET_TYPE_LABELS = {
    'garden': 'garden-style community',
    'mid_rise': 'mid-rise community',
    'high_rise': 'high-rise community',
    'mixed_use': 'mixed-use property',
}


def _asset_descriptor(lead: MultifamilyLead) -> str:
    label = _ASSET_TYPE_LABELS.get(lead.property.asset_type, 'multifamily property')
    if lead.property.unit_count:
        return f'{lead.property.unit_count}-unit {label}'
    return label


def build_angle(lead: MultifamilyLead) -> str:
    """Return a short, neutral curiosity hook for this lead's situation."""
    asset = _asset_descriptor(lead)
    company = lead.company.name

    return (
        f"Curious how {company}'s current program on the {asset} is "
        f"benchmarking against where multifamily insurance pricing has "
        f"moved this year."
    )
