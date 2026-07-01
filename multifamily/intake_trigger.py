"""
Contactless trigger intake — builds a MultifamilyLead from a third-party
signal (permit filing, news mention, SERP result) that has no named
contact. This is the "trigger" counterpart to intake.py's form-based
build_lead_from_intake(): same downstream shape (scored, explained, ready
for matching/merge/ingest), but requires only company + state + a
recognized trigger signal_type — never a contact name/email, since a
trigger feed never has one. intake.py's build_lead_from_intake() is
unchanged and untouched; this is a new, separate path.

The existing mock collectors (permit_feed, news_monitor) already build
leads this shape as in-memory demo objects with contacts=[] — this module
is their real-world counterpart, so the same trigger signal types can flow
through the real ingest pipeline (spam gate -> matching -> merge ->
source-run logging -> snapshot) instead of only existing as demo data.
"""
from typing import Any, Dict, List, Optional, Tuple

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, SIGNAL_SOURCES, SIGNAL_TYPES, SUPPORTED_STATES, new_id, utc_now_iso,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.scoring.multifamily_score_explanations import explain_why_warm, explain_likely_pain
from multifamily.daily_brief.multifamily_next_best_action import next_best_action_for_lead
from multifamily.pipeline import build_opener

# Deliberately no name/email — a third-party trigger feed never has a
# named contact. That is the entire reason this module exists separately
# from intake.py's REQUIRED_FIELDS (which requires name/email/leadSituation).
REQUIRED_TRIGGER_FIELDS = ['company', 'state', 'source', 'signalType']

MAX_TRIGGER_FIELD_LENGTHS = {
    'company': 200, 'city': 100, 'propertyName': 200, 'notes': 4000,
    'sourcePage': 300, 'sourceUrl': 500, 'searchQuery': 500, 'searchCategory': 100,
}


class TriggerValidationError(Exception):
    def __init__(self, errors: List[str]):
        super().__init__('; '.join(errors))
        self.errors = errors


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def validate_trigger(payload: Dict[str, Any]) -> List[str]:
    """Return a list of human-readable validation errors (empty = valid)."""
    errors = []

    for field_name in REQUIRED_TRIGGER_FIELDS:
        if not _clean(payload.get(field_name)):
            errors.append(f'{field_name} is required')

    state = _clean(payload.get('state'))
    if state and state.upper() not in SUPPORTED_STATES:
        errors.append(f"state must be one of {SUPPORTED_STATES} (got '{state}')")

    source = _clean(payload.get('source'))
    if source and source not in SIGNAL_SOURCES:
        errors.append(f"source must be one of {SIGNAL_SOURCES} (got '{source}')")

    signal_type = _clean(payload.get('signalType'))
    if signal_type and signal_type not in SIGNAL_TYPES:
        errors.append(f"signalType must be one of {SIGNAL_TYPES} (got '{signal_type}')")

    confidence = payload.get('confidence')
    if confidence not in (None, ''):
        try:
            c = float(confidence)
            if not (0.0 <= c <= 1.0):
                errors.append('confidence must be between 0.0 and 1.0')
        except (TypeError, ValueError):
            errors.append('confidence must be a number')

    for field_name, max_len in MAX_TRIGGER_FIELD_LENGTHS.items():
        value = payload.get(field_name)
        if value and len(str(value)) > max_len:
            errors.append(f'{field_name} must be {max_len} characters or fewer')

    return errors


def build_lead_from_trigger(
    payload: Dict[str, Any],
    *,
    spam_status: str = 'clean',
    spam_reason_codes: Optional[List[str]] = None,
) -> Tuple[Optional[MultifamilyLead], List[str]]:
    """Validate, build, score, and explain a real, contactless
    MultifamilyLead from a third-party trigger payload (permit, news,
    SERP). No contact is fabricated — `lead.contacts` stays empty.

    Expected payload keys: company, state, source, signalType (required);
    city, propertyName, sourceUrl, sourcePage, searchCategory, searchQuery,
    publishedDate, confidence, notes (optional).
    """
    errors = validate_trigger(payload)
    if errors:
        return None, errors

    company = MultifamilyCompany(id=new_id(), name=_clean(payload['company']))
    prop = MultifamilyProperty(
        id=new_id(),
        name=_clean(payload.get('propertyName')) or f'{company.name} Property',
        city=_clean(payload.get('city')),
        state=(_clean(payload['state']) or '').upper() or None,
        company_id=company.id,
    )

    source = _clean(payload['source'])
    signal_type = _clean(payload['signalType'])
    confidence = float(payload.get('confidence', 0.5) or 0.5)
    detail = {
        k: v for k, v in {
            'search_category': _clean(payload.get('searchCategory')),
            'search_query': _clean(payload.get('searchQuery')),
            'published_date': _clean(payload.get('publishedDate')),
        }.items() if v is not None
    }
    primary_signal = MultifamilySignal(
        id=new_id(), signal_type=signal_type, source=source,
        source_url=_clean(payload.get('sourceUrl')), confidence=confidence,
        detail=detail, property_id=prop.id, company_id=company.id,
    )

    lead = MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[primary_signal], contacts=[],
        state=prop.state, city=prop.city, primary_signal_type=signal_type,
        primary_source=source, source_url=primary_signal.source_url,
        source_page=_clean(payload.get('sourcePage')), confidence=confidence,
        last_verified_at=utc_now_iso(), pain_flags=[],
        notes=_clean(payload.get('notes')), is_demo=False,
        spam_status=spam_status, spam_reason_codes=spam_reason_codes or [],
    )

    lead.score = score_lead(lead)
    lead.why_warm = explain_why_warm(lead)
    lead.likely_pain = explain_likely_pain(lead)
    lead.next_best_action = next_best_action_for_lead(lead)
    lead.suggested_opener = build_opener(lead)

    return lead, []
