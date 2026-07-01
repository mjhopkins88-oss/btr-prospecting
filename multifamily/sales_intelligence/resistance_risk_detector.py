"""
Resistance Risk Detector — estimates how much pushback/skepticism to
expect from a lead, so message tone/length can be softened accordingly.
"""
from multifamily.types import MultifamilyLead

_TRIGGER_ONLY_SOURCES = {'permit', 'news', 'serp'}


def detect_resistance_risk(lead: MultifamilyLead) -> str:
    category = lead.score.category if lead.score else None
    if lead.primary_source in _TRIGGER_ONLY_SOURCES:
        return 'high'
    if category in ('nurture', 'watchlist'):
        return 'high'
    if lead.score and lead.score.disqualifier_codes:
        return 'medium'
    if getattr(lead, 'spam_status', 'clean') == 'suspicious':
        return 'medium'
    if category == 'warm':
        return 'medium'
    return 'low'
