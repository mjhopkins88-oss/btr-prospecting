"""
Signal collector (mock/stub): Google Ads paid search clicks.

Real integration (not yet built): Google Ads API conversion/click data
for high-intent multifamily landing pages.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, new_id, utc_now_iso,
)


def collect():
    """Return mock paid-search-click leads."""
    leads = []

    # --- California paid search click (MOCK DATA) -------------------------
    company = MultifamilyCompany(id=new_id(), name='Sierra Multifamily Investors (MOCK)')
    prop = MultifamilyProperty(
        id=new_id(), name='Sierra Vista Apartments (MOCK)', city='Sacramento', state='CA',
        unit_count=72, asset_type='garden', cat_exposed=True, company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='paid_search_click', source='google_ads',
        source_url='https://example.com/multifamily-insurance/quote', confidence=0.45,
        detail={'campaign': 'CA Multifamily - High Intent (MOCK)', 'landing_page': '/multifamily-insurance/quote'},
        property_id=prop.id, company_id=company.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), is_demo=True, company=company, property=prop, signals=[signal],
        state='CA', city='Sacramento', primary_signal_type='paid_search_click',
        primary_source='google_ads', source_url=signal.source_url, confidence=0.45,
        last_verified_at=utc_now_iso(), pain_flags=['cat_exposed_geography'],
    ))

    # --- Scenario: Texas paid search click (MOCK DATA, STRONG) ------------
    # Clicked straight through to the quote landing page (not just the
    # generic insurance page) — higher-intent paid click than a blind ad
    # impression, paired with solid account fit.
    company2 = MultifamilyCompany(
        id=new_id(), name='Permian Basin Apartment Holdings (MOCK)',
        company_type='owner', is_owner_operator_developer=True, portfolio_property_count=2,
    )
    prop2 = MultifamilyProperty(
        id=new_id(), name='Permian Crossing (MOCK)', city='Midland', state='TX',
        unit_count=104, asset_type='garden', company_id=company2.id,
    )
    signal2 = MultifamilySignal(
        id=new_id(), signal_type='paid_search_click', source='google_ads',
        source_url='https://example.com/multifamily-insurance/texas/quote', confidence=0.5,
        detail={'campaign': 'TX Multifamily - High Intent (MOCK)', 'landing_page': '/multifamily-insurance/texas/quote'},
        property_id=prop2.id, company_id=company2.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), is_demo=True, company=company2, property=prop2, signals=[signal2],
        state='TX', city='Midland', primary_signal_type='paid_search_click',
        primary_source='google_ads', source_url=signal2.source_url, confidence=0.5,
        last_verified_at=utc_now_iso(),
    ))

    return leads
