"""
Real lead intake — validates, builds, and scores a MultifamilyLead from
raw form input (the public benchmark form or internal manual entry).

This is the "real" counterpart to the mock signal_collectors: instead of
hardcoded demo data, build_lead_from_intake() turns an actual submission
into the same MultifamilyLead shape the rest of the system already knows
how to score, explain, and display.

No LinkedIn scraping, no invented contact info — every field here comes
directly from what the submitter typed.
"""
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilyContact,
    MultifamilySignal, SIGNAL_SOURCES, SUPPORTED_STATES, new_id, utc_now_iso,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.scoring.multifamily_score_explanations import explain_why_warm, explain_likely_pain
from multifamily.daily_brief.multifamily_next_best_action import next_best_action_for_lead
from multifamily.pipeline import build_opener
from multifamily.forms.form_variants import form_variant_for_offer_type

LEAD_SITUATIONS = ['renewal', 'acquisition', 'refinance', 'construction', 'completion', 'operating', 'benchmark']

# Primary concern options map 1:1 to the scoring engine's pain-flag keys
# (multifamily/scoring/multifamily_score_rules.py: PAIN_POINTS) so a real
# submission scores exactly like the equivalent mock pain flag.
PRIMARY_CONCERN_OPTIONS = [
    'premium_increase', 'deductible_concern', 'lender_requirement',
    'cat_exposed_geography', 'builders_risk_need', 'gl_excess_concern',
]

DECISION_MAKER_KEYWORDS = (
    'owner', 'president', 'ceo', 'cfo', 'coo', 'principal', 'partner',
    'vp', 'vice president', 'director', 'head of', 'chief', 'founder',
)

REQUIRED_FIELDS = ['name', 'company', 'email', 'state', 'leadSituation', 'source']

# Hard length caps — rejected outright with a normal validation error
# (distinct from multifamily/spam_guard.py's probabilistic content
# heuristics, which tag-but-don't-block).
MAX_FIELD_LENGTHS = {
    'name': 200, 'company': 200, 'role': 200, 'city': 100,
    'notes': 4000, 'sourcePage': 300, 'sourceUrl': 500,
    'utmSource': 200, 'utmMedium': 200, 'utmCampaign': 200,
    'utmTerm': 200, 'utmContent': 200, 'referrer': 500, 'landingPage': 500,
    'pageVariant': 100, 'campaignId': 200,
    # Offer-page conditional fields (Funnel Phase 2) — free-text ones only;
    # date/select fields are validated by their own <input type> client-side
    # and are short enough not to need a separate cap.
    'propertyName': 200, 'hardCosts': 100, 'softCosts': 100,
}


class IntakeValidationError(Exception):
    def __init__(self, errors: List[str]):
        super().__init__('; '.join(errors))
        self.errors = errors


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _is_decision_maker(role: Optional[str]) -> bool:
    if not role:
        return False
    role_lower = role.lower()
    return any(kw in role_lower for kw in DECISION_MAKER_KEYWORDS)


def _days_until(date_str: Optional[str]) -> Optional[int]:
    if not date_str:
        return None
    try:
        target = datetime.strptime(str(date_str)[:10], '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None
    return (target - date.today()).days


def validate_intake(payload: Dict[str, Any]) -> List[str]:
    """Return a list of human-readable validation errors (empty = valid)."""
    errors = []

    for field_name in REQUIRED_FIELDS:
        if not _clean(payload.get(field_name)):
            errors.append(f'{field_name} is required')

    state = _clean(payload.get('state'))
    if state and state.upper() not in SUPPORTED_STATES:
        errors.append(f"state must be one of {SUPPORTED_STATES} (got '{state}')")

    source = _clean(payload.get('source'))
    if source and source not in SIGNAL_SOURCES:
        errors.append(f"source must be one of {SIGNAL_SOURCES} (got '{source}')")

    lead_situation = _clean(payload.get('leadSituation'))
    if lead_situation and lead_situation not in LEAD_SITUATIONS:
        errors.append(f"leadSituation must be one of {LEAD_SITUATIONS} (got '{lead_situation}')")

    email = _clean(payload.get('email'))
    if email and '@' not in email:
        errors.append('email is not a valid email address')

    units = payload.get('numberOfUnits')
    if units not in (None, ''):
        try:
            int(units)
        except (TypeError, ValueError):
            errors.append('numberOfUnits must be a whole number')

    for field_name, max_len in MAX_FIELD_LENGTHS.items():
        value = payload.get(field_name)
        if value and len(str(value)) > max_len:
            errors.append(f'{field_name} must be {max_len} characters or fewer')

    return errors


def _situation_signals(payload: Dict[str, Any], property_id: str, company_id: str) -> List[MultifamilySignal]:
    """Translate leadSituation (+ its offer-page conditional fields) into
    the secondary timing/trigger signal that feeds insurance_timing
    scoring. The extra conditional fields below (targetCloseDate,
    lenderDeadline, hardCosts, etc.) ride in `detail` only — scoring never
    reads `detail` for points, so none of this changes scoring math. They
    exist for the timing/sales-intelligence layers and the funnel_urgency
    layer (Funnel Phase 4) to read."""
    situation = _clean(payload.get('leadSituation')) or ''
    source = payload.get('source')
    signals = []

    if situation == 'renewal':
        days = _days_until(payload.get('renewalDate'))
        detail = {'renewal_date': payload.get('renewalDate'), 'self_reported': True}
        if days is not None:
            detail['days_until_renewal'] = days
        if payload.get('currentPremiumRange'):
            detail['current_premium_range'] = _clean(payload.get('currentPremiumRange'))
        signals.append(MultifamilySignal(
            id=new_id(), signal_type='renewal_date_known', source=source, confidence=0.85,
            detail=detail, property_id=property_id, company_id=company_id,
        ))
    elif situation == 'acquisition':
        detail = {'self_reported': True}
        if payload.get('targetCloseDate'):
            detail['target_close_date'] = _clean(payload.get('targetCloseDate'))
        if payload.get('propertyName'):
            detail['acquisition_property_name'] = _clean(payload.get('propertyName'))
        if payload.get('relyingOnSellerNumbers'):
            detail['relying_on_seller_numbers'] = _clean(payload.get('relyingOnSellerNumbers'))
        if payload.get('yearBuilt'):
            # Vintage — a key targeting/deliverable input (Section 8 item 5's
            # Acquisition Review inputs) — rides in signal detail only, same
            # as every other conditional field here; scoring never reads it.
            detail['year_built'] = _clean(payload.get('yearBuilt'))
        signals.append(MultifamilySignal(
            id=new_id(), signal_type='acquisition', source=source, confidence=0.8,
            detail=detail, property_id=property_id, company_id=company_id,
        ))
    elif situation == 'refinance':
        detail = {'self_reported': True}
        if payload.get('lenderDeadline'):
            detail['lender_deadline'] = _clean(payload.get('lenderDeadline'))
        if payload.get('issueType'):
            detail['lender_issue_type'] = _clean(payload.get('issueType'))
        signals.append(MultifamilySignal(
            id=new_id(), signal_type='refinance', source=source, confidence=0.8,
            detail=detail, property_id=property_id, company_id=company_id,
        ))
    elif situation == 'construction':
        days = _days_until(payload.get('projectStartDate'))
        stage = 'vertical_construction' if (days is not None and days <= 0) else 'groundbreaking'
        detail = {'project_start_date': payload.get('projectStartDate'), 'self_reported': True}
        if payload.get('hardCosts'):
            detail['hard_costs'] = _clean(payload.get('hardCosts'))
        if payload.get('softCosts'):
            detail['soft_costs'] = _clean(payload.get('softCosts'))
        if payload.get('controlType'):
            detail['control_type'] = _clean(payload.get('controlType'))
        if payload.get('constructionStage'):
            detail['construction_stage_selfreport'] = _clean(payload.get('constructionStage'))
        signals.append(MultifamilySignal(
            id=new_id(), signal_type=stage, source=source, confidence=0.75,
            detail=detail, property_id=property_id, company_id=company_id,
        ))
    elif situation == 'completion':
        detail = {'self_reported': True}
        if payload.get('expectedCompletionDate'):
            detail['expected_completion_date'] = _clean(payload.get('expectedCompletionDate'))
        if payload.get('firstOccupancyDate'):
            detail['first_occupancy_date'] = _clean(payload.get('firstOccupancyDate'))
        if payload.get('phasing'):
            detail['phasing'] = _clean(payload.get('phasing'))
        if payload.get('operatingCoveragePlaced'):
            detail['operating_coverage_placed'] = _clean(payload.get('operatingCoveragePlaced'))
        signals.append(MultifamilySignal(
            id=new_id(), signal_type='completion', source=source, confidence=0.8,
            detail=detail, property_id=property_id, company_id=company_id,
        ))
    # 'operating' and 'benchmark' add no secondary timing signal — that's
    # honest: there's no known trigger driving urgency yet.

    return signals


def build_lead_from_intake(
    payload: Dict[str, Any],
    *,
    ip_hash: Optional[str] = None,
    user_agent_summary: Optional[str] = None,
    spam_status: str = 'clean',
    spam_reason_codes: Optional[List[str]] = None,
) -> Tuple[Optional[MultifamilyLead], List[str]]:
    """Validate, build, score, and explain a real MultifamilyLead from raw
    form input. Returns (lead, []) on success or (None, errors) if the
    submission is incomplete/invalid.

    `ip_hash`/`user_agent_summary`/`spam_status`/`spam_reason_codes` are
    NOT read from `payload` — they're server-computed (multifamily/
    spam_guard.py) and passed in explicitly by the route, so a submitter
    can never just set spam_status=clean themselves."""
    errors = validate_intake(payload)
    if errors:
        return None, errors

    company = MultifamilyCompany(
        id=new_id(),
        name=_clean(payload['company']),
        decision_maker_role=_clean(payload.get('role')),
    )
    prop = MultifamilyProperty(
        id=new_id(),
        name=f"{company.name} Property",
        city=_clean(payload.get('city')),
        state=(_clean(payload.get('state')) or '').upper() or None,
        unit_count=int(payload['numberOfUnits']) if payload.get('numberOfUnits') not in (None, '') else None,
        asset_type=_clean(payload.get('assetType')),
        company_id=company.id,
    )
    contact = MultifamilyContact(
        id=new_id(),
        full_name=_clean(payload['name']),
        title=_clean(payload.get('role')),
        email=_clean(payload.get('email')),
        phone=_clean(payload.get('phone')),
        is_decision_maker=_is_decision_maker(payload.get('role')),
        company_id=company.id,
    )

    situation = _clean(payload.get('leadSituation')) or ''
    source = _clean(payload['source'])
    primary_signal = MultifamilySignal(
        id=new_id(), signal_type='benchmark_form_submit', source=source,
        source_url=_clean(payload.get('sourceUrl')), confidence=0.9,
        detail={'lead_situation': situation, 'source_page': _clean(payload.get('sourcePage'))},
        property_id=prop.id, company_id=company.id,
    )
    signals = [primary_signal] + _situation_signals(payload, prop.id, company.id)

    primary_concern = _clean(payload.get('primaryConcern'))
    pain_flags = [primary_concern] if primary_concern in PRIMARY_CONCERN_OPTIONS else []

    offer_type = _clean(payload.get('offerType'))
    page_variant = _clean(payload.get('pageVariant'))
    if not page_variant and offer_type:
        # A submission that carries offer_type but no explicit page_variant
        # (e.g. today's benchmark form, or an outbound link that only sets
        # offerType) still gets an accurate page_variant recorded, purely
        # server-side — the form's own fields/behavior are unchanged.
        matched_variant = form_variant_for_offer_type(offer_type)
        if matched_variant:
            page_variant = matched_variant.slug

    lead = MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=signals, contacts=[contact],
        state=prop.state, city=prop.city, primary_signal_type='benchmark_form_submit',
        primary_source=source, source_url=primary_signal.source_url,
        source_page=_clean(payload.get('sourcePage')), confidence=0.9,
        last_verified_at=utc_now_iso(), pain_flags=pain_flags,
        notes=_clean(payload.get('notes')), is_demo=False,
        utm_source=_clean(payload.get('utmSource')),
        utm_medium=_clean(payload.get('utmMedium')),
        utm_campaign=_clean(payload.get('utmCampaign')),
        utm_term=_clean(payload.get('utmTerm')),
        utm_content=_clean(payload.get('utmContent')),
        referrer=_clean(payload.get('referrer')),
        landing_page=_clean(payload.get('landingPage')),
        offer_type=offer_type,
        page_variant=page_variant,
        campaign_id=_clean(payload.get('campaignId')),
        spam_status=spam_status,
        spam_reason_codes=spam_reason_codes or [],
        submitted_ip_hash=ip_hash,
        user_agent_summary=user_agent_summary,
    )

    lead.score = score_lead(lead)
    lead.why_warm = explain_why_warm(lead)
    lead.likely_pain = explain_likely_pain(lead)
    lead.next_best_action = next_best_action_for_lead(lead)
    lead.suggested_opener = build_opener(lead)

    return lead, []
