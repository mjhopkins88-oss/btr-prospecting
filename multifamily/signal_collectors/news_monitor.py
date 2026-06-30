"""
Signal collector (mock/stub): public news/press monitoring.

Real integration (not yet built): news/press-release API or RSS
monitoring for acquisition, refinance, and financing announcements.
Public sources only.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, new_id, utc_now_iso,
)


def collect():
    """Return mock news-derived leads."""
    leads = []

    # --- Scenario 3: Texas acquisition/financing announcement (MOCK) -----
    company = MultifamilyCompany(
        id=new_id(), name='Meridian Multifamily Capital (MOCK)',
        company_type='owner', is_owner_operator_developer=True, portfolio_property_count=12,
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Riverwalk Apartments (MOCK)', city='Fort Worth', state='TX',
        unit_count=304, asset_type='garden', company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='acquisition', source='news',
        source_url='https://example.com/news/MOCK-meridian-riverwalk-acquisition', confidence=0.7,
        detail={'headline': 'Meridian Multifamily Capital closes acquisition of Riverwalk Apartments (MOCK)'},
        property_id=prop.id, company_id=company.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[signal],
        state='TX', city='Fort Worth', primary_signal_type='acquisition',
        primary_source='news', source_url=signal.source_url, confidence=0.7,
        last_verified_at=utc_now_iso(), pain_flags=['lender_requirement'],
    ))

    # --- Scenario 7: Low-confidence news-only lead (MOCK DATA) -----------
    # Deliberately thin: unknown state/asset type to exercise the scoring
    # engine's penalty + "permit/news-only caps below Hot" gating rules.
    company2 = MultifamilyCompany(id=new_id(), name='Unverified Holdings LLC (MOCK)')
    prop2 = MultifamilyProperty(
        id=new_id(), name='Unnamed Multifamily Asset (MOCK)', city=None, state=None,
        unit_count=None, asset_type=None, company_id=company2.id,
    )
    signal2 = MultifamilySignal(
        id=new_id(), signal_type='portfolio_growth', source='news',
        source_url='https://example.com/news/MOCK-unverified-holdings-brief', confidence=0.25,
        detail={'headline': 'Unverified Holdings LLC reportedly expanding multifamily footprint (MOCK, low confidence)'},
        property_id=prop2.id, company_id=company2.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company2, property=prop2, signals=[signal2],
        state=None, city=None, primary_signal_type='portfolio_growth',
        primary_source='news', source_url=signal2.source_url, confidence=0.25,
        last_verified_at=utc_now_iso(),
    ))

    return leads
