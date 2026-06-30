"""
Signal collector (mock/stub): on-site behavioral intent.

Real integration (not yet built): first-party analytics events (e.g. a
pixel/event endpoint on the marketing site) for visits to multifamily
insurance pages. No third-party or authenticated-site scraping involved.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, new_id, utc_now_iso,
)


def collect():
    """Return mock website-intent leads."""
    leads = []

    # --- Scenario 6: Repeat website visitor from California page (MOCK) --
    company = MultifamilyCompany(
        id=new_id(), name='Golden Gate Apartment Partners (MOCK)',
        company_type='operator', is_owner_operator_developer=True,
        portfolio_property_count=3,
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Mission Bay Flats (MOCK)', city='San Francisco', state='CA',
        unit_count=140, asset_type='high_rise', cat_exposed=True, company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='repeat_website_visit', source='website',
        source_url='https://example.com/multifamily-insurance', confidence=0.55,
        detail={'page': '/multifamily-insurance', 'visit_count': 4},
        property_id=prop.id, company_id=company.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[signal],
        state='CA', city='San Francisco', primary_signal_type='repeat_website_visit',
        primary_source='website', source_url=signal.source_url, confidence=0.55,
        last_verified_at=utc_now_iso(),
    ))

    # --- Additional mock: single website visit, Texas (low intent) -------
    company2 = MultifamilyCompany(id=new_id(), name='Hill Country Multifamily LLC (MOCK)')
    prop2 = MultifamilyProperty(
        id=new_id(), name='Cedar Ridge Apartments (MOCK)', city='San Antonio', state='TX',
        unit_count=64, asset_type='garden', company_id=company2.id,
    )
    signal2 = MultifamilySignal(
        id=new_id(), signal_type='website_visit', source='website',
        source_url='https://example.com/multifamily-insurance', confidence=0.3,
        detail={'page': '/multifamily-insurance', 'visit_count': 1},
        property_id=prop2.id, company_id=company2.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company2, property=prop2, signals=[signal2],
        state='TX', city='San Antonio', primary_signal_type='website_visit',
        primary_source='website', source_url=signal2.source_url, confidence=0.3,
        last_verified_at=utc_now_iso(),
    ))

    return leads
