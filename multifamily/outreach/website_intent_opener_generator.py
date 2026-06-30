"""
Opener generator for website/search/ads intent (visits, repeat visits,
keyword intent, paid clicks, calculator/guide downloads).
"""
from multifamily.types import MultifamilyLead
from multifamily.outreach.nepq_multifamily_angle_builder import build_angle

_INTENT_LABELS = {
    'website_visit': 'checking out our multifamily insurance page',
    'repeat_website_visit': 'coming back to our multifamily insurance page a few times',
    'keyword_intent': 'searching around multifamily insurance options',
    'paid_search_click': 'clicking through on multifamily insurance',
    'calculator_submit': 'running numbers through our coverage calculator',
    'guide_download': 'grabbing our renewal readiness guide',
}


def generate(lead: MultifamilyLead) -> str:
    angle = build_angle(lead)
    intent_signal = next(
        (s for s in lead.signals if s.signal_type in _INTENT_LABELS), None
    )
    intent_label = _INTENT_LABELS.get(
        intent_signal.signal_type if intent_signal else None, 'looking into multifamily insurance'
    )

    return (
        f"Noticed {lead.company.name} {intent_label}. {angle} "
        f"No obligation — just happy to share a quick benchmark if it's helpful."
    )
