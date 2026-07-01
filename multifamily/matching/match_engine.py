"""
Match engine — decide whether an incoming lead is the same opportunity as
an existing one, and at what confidence.

Lead grain is (company, property): two submissions for the same normalized
company+property are the same lead. Email is a strong cross-link. Anything
weaker (fuzzy company, same city/state, same source URL, conflicting
fields) is a REVIEW candidate a human confirms — never auto-merged.

Pure analytics over already-loaded leads — no DB, no scoring.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from multifamily.types import MultifamilyLead
from multifamily.matching import identity_keys as ik

# Reason codes + their contribution to the ranking score.
_AUTO_REASONS = {'exact_email', 'exact_company_property', 'exact_phone_and_company'}
_REASON_WEIGHTS = {
    'exact_email': 1.0,
    'exact_company_property': 0.9,
    'exact_phone_and_company': 0.8,
    'exact_phone': 0.55,
    'same_company_domain': 0.5,
    'same_company_location': 0.5,
    'fuzzy_company_same_state': 0.5,
    'same_property_same_state': 0.45,
    'same_source_url': 0.4,
    'same_landing_and_campaign': 0.35,
    'company_state_conflict': 0.3,
}

FUZZY_COMPANY_THRESHOLD = 0.6


@dataclass
class MatchCandidate:
    lead: MultifamilyLead
    tier: str  # 'auto' | 'review'
    score: float
    reasons: List[str] = field(default_factory=list)


def _reasons_for(incoming: MultifamilyLead, existing: MultifamilyLead) -> List[str]:
    reasons: List[str] = []

    emails_i, emails_e = ik.lead_emails(incoming), ik.lead_emails(existing)
    phones_i, phones_e = ik.lead_phones(incoming), ik.lead_phones(existing)
    comp_i, comp_e = ik.normalize_company(incoming.company.name), ik.normalize_company(existing.company.name)
    prop_i, prop_e = ik.normalize_property(incoming.property.name), ik.normalize_property(existing.property.name)
    state_i, state_e = ik.normalize_text(incoming.state), ik.normalize_text(existing.state)
    city_i, city_e = ik.normalize_text(incoming.city), ik.normalize_text(existing.city)

    company_exact = bool(comp_i and comp_i == comp_e)
    property_exact = bool(prop_i and prop_i == prop_e)
    phone_exact = bool(phones_i & phones_e)

    # ---- AUTO reasons ----
    if emails_i & emails_e:
        reasons.append('exact_email')
    if company_exact and property_exact:
        reasons.append('exact_company_property')
    if phone_exact and company_exact:
        reasons.append('exact_phone_and_company')

    # ---- REVIEW reasons (only matter if not already auto) ----
    if phone_exact and not company_exact:
        reasons.append('exact_phone')
    if ik.lead_domains(incoming) & ik.lead_domains(existing):
        reasons.append('same_company_domain')
    if company_exact and not property_exact and ((state_i and state_i == state_e) or (city_i and city_i == city_e)):
        reasons.append('same_company_location')
    if not company_exact and ik.token_jaccard(incoming.company.name, existing.company.name) >= FUZZY_COMPANY_THRESHOLD and state_i and state_i == state_e:
        reasons.append('fuzzy_company_same_state')
    if not company_exact:
        pf_i, pf_e = ik.normalize_property_fuzzy(incoming.property.name), ik.normalize_property_fuzzy(existing.property.name)
        if pf_i and pf_i == pf_e and state_i and state_i == state_e:
            reasons.append('same_property_same_state')
    su_i, su_e = ik.normalize_text(incoming.source_url), ik.normalize_text(existing.source_url)
    if su_i and su_i == su_e:
        reasons.append('same_source_url')
    lp_i, lp_e = ik.normalize_text(incoming.landing_page), ik.normalize_text(existing.landing_page)
    camp_i, camp_e = ik.normalize_text(incoming.utm_campaign), ik.normalize_text(existing.utm_campaign)
    if lp_i and lp_i == lp_e and camp_i and camp_i == camp_e:
        reasons.append('same_landing_and_campaign')
    # Conflicting field: same company name but different state — flag, don't merge.
    if company_exact and state_i and state_e and state_i != state_e:
        reasons.append('company_state_conflict')

    return reasons


def classify(incoming: MultifamilyLead, existing_leads: List[MultifamilyLead]) -> Dict[str, object]:
    """Return {'auto': MatchCandidate|None, 'review': [MatchCandidate]}.

    `existing_leads` should be the ACTIVE real leads (callers pass
    repository.get_real_leads(), which already excludes rejected leads and
    merged tombstones). The incoming lead must NOT be in the list.
    """
    autos: List[MatchCandidate] = []
    reviews: List[MatchCandidate] = []

    for existing in existing_leads:
        if existing.id == incoming.id:
            continue
        reasons = _reasons_for(incoming, existing)
        if not reasons:
            continue
        # A pure conflict flag is informational only — not a real match.
        if reasons == ['company_state_conflict']:
            continue
        score = sum(_REASON_WEIGHTS.get(r, 0.1) for r in reasons)
        is_auto = any(r in _AUTO_REASONS for r in reasons)
        candidate = MatchCandidate(lead=existing, tier='auto' if is_auto else 'review', score=score, reasons=reasons)
        (autos if is_auto else reviews).append(candidate)

    autos.sort(key=lambda c: c.score, reverse=True)
    reviews.sort(key=lambda c: c.score, reverse=True)
    return {'auto': autos[0] if autos else None, 'review': reviews}
