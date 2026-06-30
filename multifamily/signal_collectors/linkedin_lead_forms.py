"""
Signal collector (mock/stub): LinkedIn Lead Gen Form submissions.

Real integration (not yet built): LinkedIn Marketing API lead form
webhook/export. This is the official ads lead-gen API — NOT scraping
LinkedIn profiles or any authenticated page.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, MultifamilyContact, new_id, utc_now_iso,
)


def collect():
    """Return mock LinkedIn Lead Gen Form leads."""
    company = MultifamilyCompany(
        id=new_id(), name='Alamo Heights Property Partners (MOCK)',
        company_type='developer', is_owner_operator_developer=True,
        portfolio_property_count=5, decision_maker_role='Head of Insurance & Risk',
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Alamo Heights Lofts (MOCK)', city='San Antonio', state='TX',
        unit_count=180, asset_type='mid_rise', company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='linkedin_lead_form_submit', source='linkedin_lead_form',
        source_url=None, confidence=0.7,
        detail={'campaign': 'Multifamily Insurance Benchmark (MOCK)'},
        property_id=prop.id, company_id=company.id,
    )
    contact = MultifamilyContact(
        id=new_id(), full_name='D. Okafor (MOCK)', title='Head of Insurance & Risk',
        is_decision_maker=True, company_id=company.id,
    )
    lead = MultifamilyLead(
        id=new_id(), is_demo=True, company=company, property=prop, signals=[signal], contacts=[contact],
        state='TX', city='San Antonio', primary_signal_type='linkedin_lead_form_submit',
        primary_source='linkedin_lead_form', source_url=None, confidence=0.7,
        last_verified_at=utc_now_iso(),
    )
    return [lead]
