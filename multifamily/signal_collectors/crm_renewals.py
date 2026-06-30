"""
Signal collector (mock/stub): CRM renewal-date pull.

Real integration (not yet built): read-only pull from the agency's CRM
for known clients/prospects with an on-file renewal date.
"""
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilySignal, MultifamilyContact, new_id, utc_now_iso,
)


def collect():
    """Return mock CRM-sourced renewal-opportunity leads."""
    # --- Scenario 8: Existing CRM renewal opportunity (MOCK DATA) --------
    company = MultifamilyCompany(
        id=new_id(), name='Coastal Bend Realty Partners (MOCK)',
        company_type='owner', is_owner_operator_developer=True,
        portfolio_property_count=3, decision_maker_role='Owner',
    )
    prop = MultifamilyProperty(
        id=new_id(), name='Coastal Bend Apartments (MOCK)', city='Corpus Christi', state='TX',
        unit_count=110, asset_type='garden', cat_exposed=True, company_id=company.id,
    )
    signal = MultifamilySignal(
        id=new_id(), signal_type='renewal_date_known', source='crm',
        source_url=None, confidence=0.9,
        detail={'days_until_renewal': 75, 'renewal_date': '2026-09-13'},
        property_id=prop.id, company_id=company.id,
    )
    contact = MultifamilyContact(
        id=new_id(), full_name='M. Alvarez (MOCK)', title='Owner',
        is_decision_maker=True, company_id=company.id,
    )
    lead = MultifamilyLead(
        id=new_id(), is_demo=True, company=company, property=prop, signals=[signal], contacts=[contact],
        state='TX', city='Corpus Christi', primary_signal_type='renewal_date_known',
        primary_source='crm', source_url=None, confidence=0.9,
        last_verified_at=utc_now_iso(), pain_flags=['cat_exposed_geography'],
        relationship_flags=['existing_client_or_referral'],
    )
    return [lead]
