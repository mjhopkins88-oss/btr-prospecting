"""
Buyer Awareness Classifier — infers how far along a lead is in recognizing
they have a problem/need, from signal types and pain flags alone (no
scoring-math involvement).
"""
from multifamily.types import MultifamilyLead

_DIRECT_ASK_SIGNALS = {'quote_request', 'meeting_request'}
_RESEARCH_SIGNALS = {'benchmark_form_submit', 'linkedin_lead_form_submit', 'calculator_submit'}
_LOW_INTENT_WEB_SIGNALS = {'website_visit', 'repeat_website_visit', 'keyword_intent', 'paid_search_click', 'guide_download'}
_ACQUISITION_SIGNALS = {'acquisition', 'refinance', 'financing'}
_CONSTRUCTION_SIGNALS = {'permit_filed', 'planning_approval', 'groundbreaking', 'vertical_construction'}
_TRIGGER_ONLY_SOURCES = {'permit', 'news'}


def classify_buyer_awareness(lead: MultifamilyLead) -> str:
    signal_types = {s.signal_type for s in (lead.signals or [])}
    if signal_types & _DIRECT_ASK_SIGNALS:
        return 'decision_ready'
    if signal_types & _RESEARCH_SIGNALS:
        return 'solution_aware'
    if (lead.pain_flags or []) or (signal_types & (_ACQUISITION_SIGNALS | _CONSTRUCTION_SIGNALS)):
        return 'problem_aware'
    if signal_types & _LOW_INTENT_WEB_SIGNALS:
        return 'unaware'
    if lead.primary_source in _TRIGGER_ONLY_SOURCES:
        return 'unaware'
    return 'unknown'
