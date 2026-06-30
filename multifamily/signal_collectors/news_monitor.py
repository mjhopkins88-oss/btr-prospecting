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

    # --- Scenario 3: Texas news-only acquisition lead (MOCK, NEAR-MISS) --
    # Acquisition is a "very strong" trigger (Phase 2 Hot-eligibility
    # rule) and this account has excellent fit (large portfolio owner,
    # named decision-maker) plus two pain flags — but it's a news-only
    # lead with zero inbound intent, so it can never be Call Today, and
    # realistically lands in Nurture given the timing-trigger point cap.
    company = MultifamilyCompany(
        id=new_id(), name='Meridian Multifamily Capital (MOCK)',
        company_type='owner', is_owner_operator_developer=True, portfolio_property_count=12,
        decision_maker_role='Chief Financial Officer',
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
        id=new_id(), is_demo=True, company=company, property=prop, signals=[signal],
        state='TX', city='Fort Worth', primary_signal_type='acquisition',
        primary_source='news', source_url=signal.source_url, confidence=0.7,
        last_verified_at=utc_now_iso(), pain_flags=['lender_requirement', 'gl_excess_concern'],
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
        id=new_id(), is_demo=True, company=company2, property=prop2, signals=[signal2],
        state=None, city=None, primary_signal_type='portfolio_growth',
        primary_source='news', source_url=signal2.source_url, confidence=0.25,
        last_verified_at=utc_now_iso(),
    ))

    return leads
