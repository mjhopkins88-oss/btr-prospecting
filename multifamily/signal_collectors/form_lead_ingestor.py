"""
Signal collector (mock/stub): inbound form submissions.

Real integration (not yet built): webhook receiver for the multifamily
benchmark/quote/meeting-request/guide-download forms on the marketing
site. Until that's wired up, this returns clearly labeled mock leads so
the rest of the pipeline (scoring, outreach, daily brief, UI) can be
built and tested end-to-end.

This collector NEVER scrapes LinkedIn or any authenticated site, and
never invents contact details — every contact below is fabricated
*mock* data for demo purposes only and is labeled as such.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, MultifamilyContact, new_id, utc_now_iso,
)


def collect():
    """Return mock inbound form-submission leads."""
    leads = []

    # --- Scenario 1: Texas benchmark form submission (MOCK DATA, STRONG) -
    # Paired with a known renewal inside the 120-day window — a real
    # benchmark request from an in-footprint, well-fit, soon-to-renew
    # owner is exactly the kind of lead that should reach Call Today.
    company = MultifamilyCompany(
        id=new_id(), name='Lone Star Multifamily Holdings (MOCK)',
        company_type='owner', is_owner_operator_developer=True,
        portfolio_property_count=4, decision_maker_role='VP of Risk Management',
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Trinity Yards Apartments (MOCK)', city='Austin', state='TX',
        unit_count=212, asset_type='garden', cat_exposed=True, company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='benchmark_form_submit', source='form',
        source_url=None, confidence=0.95,
        detail={'form_name': 'Multifamily Insurance Benchmark Request'},
        property_id=prop.id, company_id=company.id,
    )
    renewal_signal = MultifamilySignal(
        id=new_id(), signal_type='renewal_date_known', source='form', confidence=0.9,
        detail={'days_until_renewal': 45, 'renewal_date': '2026-08-14', 'self_reported': True},
        property_id=prop.id, company_id=company.id,
    )
    contact = MultifamilyContact(
        id=new_id(), full_name='J. Whitfield (MOCK)', title='VP of Risk Management',
        email='mock-contact-1@example.com', is_decision_maker=True, company_id=company.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company, property=prop, signals=[signal, renewal_signal], contacts=[contact],
        state='TX', city='Austin', primary_signal_type='benchmark_form_submit',
        primary_source='form', source_url=None, confidence=0.95,
        last_verified_at=utc_now_iso(), pain_flags=['premium_increase'],
        relationship_flags=['prior_reply'],
    ))

    # --- Scenario 2: California renewal checklist download (MOCK, STRONG) -
    # Guide download paired with a known (but not imminent) renewal date —
    # shows real inbound intent plus confirmed insurance timing, even
    # though the renewal itself is still a few months out.
    company2 = MultifamilyCompany(
        id=new_id(), name='Pacific Coast Residential Group (MOCK)',
        company_type='owner', is_owner_operator_developer=True,
        portfolio_property_count=2, decision_maker_role='Director of Operations',
    )
    prop2 = MultifamilyProperty(
        id=new_id(), name='Bayview Terrace (MOCK)', city='Oakland', state='CA',
        unit_count=88, asset_type='mid_rise', cat_exposed=True, company_id=company2.id,
    )
    signal2 = MultifamilySignal(
        id=new_id(), signal_type='guide_download', source='form',
        source_url=None, confidence=0.85,
        detail={'asset_name': 'Multifamily Renewal Readiness Checklist'},
        property_id=prop2.id, company_id=company2.id,
    )
    renewal_signal2 = MultifamilySignal(
        id=new_id(), signal_type='renewal_date_known', source='form', confidence=0.75,
        detail={'days_until_renewal': 150, 'renewal_date': '2026-11-27', 'self_reported': True},
        property_id=prop2.id, company_id=company2.id,
    )
    contact2 = MultifamilyContact(
        id=new_id(), full_name='R. Castillo (MOCK)', title='Director of Operations',
        email='mock-contact-2@example.com', is_decision_maker=True, company_id=company2.id,
    )
    leads.append(MultifamilyLead(
        id=new_id(), company=company2, property=prop2, signals=[signal2, renewal_signal2], contacts=[contact2],
        state='CA', city='Oakland', primary_signal_type='guide_download',
        primary_source='form', source_url=None, confidence=0.85,
        last_verified_at=utc_now_iso(), pain_flags=['cat_exposed_geography'],
    ))

    return leads
