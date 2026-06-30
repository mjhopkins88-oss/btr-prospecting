"""
Signal collector (mock/stub): public construction-permit feeds.

Real integration (not yet built): municipal/county open-permit-data
portals (all public records — no scraping of private/authenticated
systems).
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, new_id, utc_now_iso,
)


def collect():
    """Return mock construction-permit/trigger leads."""
    leads = []

    # --- Scenario 4: California permit-only lead (MOCK DATA, NEAR-MISS) --
    # Deliberately strong on fit/pain (100+ units, portfolio owner,
    # decision-maker on file, two pain flags) to demonstrate that a
    # permit-only lead is capped well below Hot/Call Today even when
    # everything else about the account looks great — permit_filed is an
    # early-stage signal, not a "very strong" trigger, and there is no
    # inbound intent at all.
    company = MultifamilyCompany(
        id=new_id(), name='Westshore Development Co. (MOCK)', company_type='developer',
        is_owner_operator_developer=True, portfolio_property_count=3,
        decision_maker_role='Director of Construction',
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Westshore Commons (MOCK)', city='Long Beach', state='CA',
        unit_count=160, asset_type='mid_rise', cat_exposed=True, company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='permit_filed', source='permit',
        source_url='https://example.gov/permits/MOCK-CA-2026-00417', confidence=0.6,
        detail={'permit_number': 'MOCK-CA-2026-00417', 'permit_type': 'New Multifamily Construction'},
        property_id=prop.id, company_id=company.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[signal],
        state='CA', city='Long Beach', primary_signal_type='permit_filed',
        primary_source='permit', source_url=signal.source_url, confidence=0.6,
        last_verified_at=utc_now_iso(), pain_flags=['builders_risk_need', 'gl_excess_concern'],
    ))

    # --- Scenario 5: Texas builder's risk construction trigger (MOCK, NEAR-MISS) --
    # Active vertical construction is a "very strong" trigger (Phase 2
    # Hot-eligibility rule), paired with strong fit/pain — but still a
    # permit-only/news-only lead, so it can never be Call Today, and the
    # raw point total (no inbound, timing capped at 18) realistically
    # lands in Nurture, not Hot.
    company2 = MultifamilyCompany(
        id=new_id(), name='Cypress Creek Builders (MOCK)', company_type='developer',
        is_owner_operator_developer=True, portfolio_property_count=2,
        decision_maker_role='VP of Construction',
    )
    prop2 = MultifamilyProperty(
        id=new_id(), name='Cypress Creek Residences (MOCK)', city='Houston', state='TX',
        unit_count=240, asset_type='garden', company_id=company2.id,
    )
    signal2 = MultifamilySignal(
        id=new_id(), signal_type='vertical_construction', source='permit',
        source_url='https://example.gov/permits/MOCK-TX-2026-08821', confidence=0.65,
        detail={'permit_number': 'MOCK-TX-2026-08821', 'stage': 'Vertical construction underway'},
        property_id=prop2.id, company_id=company2.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company2, property=prop2, signals=[signal2],
        state='TX', city='Houston', primary_signal_type='vertical_construction',
        primary_source='permit', source_url=signal2.source_url, confidence=0.65,
        last_verified_at=utc_now_iso(), pain_flags=['builders_risk_need', 'lender_requirement'],
    ))

    return leads
