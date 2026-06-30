"""
Signal collector (mock/stub): Search Console keyword intent.

Real integration (not yet built): Google Search Console API, scoped to
the multifamily marketing pages/site property.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, MultifamilySearchIntentKeyword, new_id, utc_now_iso,
)


def collect():
    """Return mock keyword-intent leads (organic search)."""
    keyword = MultifamilySearchIntentKeyword(
        id=new_id(), keyword='apartment complex insurance broker texas (MOCK)',
        source='search_console', clicks=6, impressions=140,
        landing_page='/multifamily-insurance/texas', high_intent=True,
    )

    company = MultifamilyCompany(id=new_id(), name='Brazos Valley Apartment Group (MOCK)')
    prop = MultifamilyProperty(
        id=new_id(), name='Brazos Pointe (MOCK)', city='Waco', state='TX',
        unit_count=96, asset_type='garden', company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='keyword_intent', source='search_console',
        source_url='https://example.com/multifamily-insurance/texas', confidence=0.4,
        detail={'keyword': keyword.keyword, 'clicks': keyword.clicks},
        property_id=prop.id, company_id=company.id,
    )

    lead = MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[signal],
        state='TX', city='Waco', primary_signal_type='keyword_intent',
        primary_source='search_console', source_url=signal.source_url, confidence=0.4,
        last_verified_at=utc_now_iso(),
    )
    return [lead]
