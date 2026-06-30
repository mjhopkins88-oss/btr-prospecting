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
    lead = MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[signal],
        state='CA', city='Sacramento', primary_signal_type='paid_search_click',
        primary_source='google_ads', source_url=signal.source_url, confidence=0.45,
        last_verified_at=utc_now_iso(), pain_flags=['cat_exposed_geography'],
    )
    return [lead]
