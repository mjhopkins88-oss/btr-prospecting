"""
Daily brief builder — aggregates scored multifamily leads into the
sections the Multifamily Command dashboard and daily digest need.
"""
from typing import Any, Dict, List

from multifamily.types import MultifamilyLead, SUPPORTED_STATES
from multifamily.scoring.multifamily_score_rules import UNKNOWN_ASSET_TYPE_VALUES
from multifamily.daily_brief.multifamily_next_best_action import next_best_action_for_lead

INBOUND_SOURCES = {'form', 'website', 'search_console', 'google_ads', 'linkedin_lead_form'}
RENEWAL_SIGNAL_TYPES = {'renewal_date_known'}
ACQUISITION_SIGNAL_TYPES = {'acquisition', 'refinance', 'financing'}
CONSTRUCTION_SIGNAL_TYPES = {
    'permit_filed', 'planning_approval', 'groundbreaking', 'vertical_construction', 'completion',
}


def _has_signal_type(lead: MultifamilyLead, types: set) -> bool:
    return any(s.signal_type in types for s in lead.signals)


def _lead_summary(lead: MultifamilyLead) -> Dict[str, Any]:
    return {
        'lead_id': lead.id,
        'company': lead.company.name,
        'property': lead.property.name,
        'city': lead.city,
        'state': lead.state,
        'score': lead.score.total if lead.score else None,
        'category': lead.score.category if lead.score else None,
        'next_best_action': lead.next_best_action or next_best_action_for_lead(lead),
        'suggested_opener': lead.suggested_opener,
    }


def build_daily_brief(leads: List[MultifamilyLead]) -> Dict[str, Any]:
    scored = [l for l in leads if l.score is not None]

    new_inbound_leads = [l for l in leads if l.primary_source in INBOUND_SOURCES]
    call_today_leads = [l for l in scored if l.score.category == 'call_today']
    hot_leads = [l for l in scored if l.score.category == 'hot']
    warm_leads = [l for l in scored if l.score.category == 'warm']
    renewal_opportunities = [l for l in leads if _has_signal_type(l, RENEWAL_SIGNAL_TYPES) or l.primary_source == 'crm']
    acquisition_triggers = [l for l in leads if _has_signal_type(l, ACQUISITION_SIGNAL_TYPES)]
    construction_triggers = [l for l in leads if _has_signal_type(l, CONSTRUCTION_SIGNAL_TYPES)]

    leads_needing_more_info = [
        l for l in leads
        if (l.score and l.score.disqualified)
        or not l.source_url and l.primary_source not in ('form', 'crm')
        or l.state not in SUPPORTED_STATES
        or l.property.asset_type in UNKNOWN_ASSET_TYPE_VALUES
    ]

    ranked = sorted(
        (l for l in scored if not l.score.disqualified),
        key=lambda l: l.score.total, reverse=True,
    )
    top_3_actions_today = [_lead_summary(l) for l in ranked[:3]]

    callable_leads = [l for l in ranked if l.contacts]
    best_first_call = _lead_summary(callable_leads[0]) if callable_leads else None

    emailable_leads = [l for l in ranked if any(c.email for c in l.contacts) and l.suggested_opener]
    best_email_draft = None
    if emailable_leads:
        lead = emailable_leads[0]
        contact = next(c for c in lead.contacts if c.email)
        best_email_draft = {
            **_lead_summary(lead),
            'to': contact.email,
            'subject': f'Quick multifamily insurance benchmark for {lead.property.name}',
            'body': lead.suggested_opener,
        }

    linkedin_leads = [
        l for l in ranked
        if l.primary_source == 'linkedin_lead_form' or any(c.linkedin_url for c in l.contacts)
    ]
    best_linkedin_touch = _lead_summary(linkedin_leads[0]) if linkedin_leads else None

    return {
        'new_inbound_leads': [_lead_summary(l) for l in new_inbound_leads],
        'call_today_leads': [_lead_summary(l) for l in call_today_leads],
        'hot_leads': [_lead_summary(l) for l in hot_leads],
        'warm_leads': [_lead_summary(l) for l in warm_leads],
        'renewal_opportunities': [_lead_summary(l) for l in renewal_opportunities],
        'acquisition_triggers': [_lead_summary(l) for l in acquisition_triggers],
        'construction_triggers': [_lead_summary(l) for l in construction_triggers],
        'top_3_actions_today': top_3_actions_today,
        'best_first_call': best_first_call,
        'best_email_draft': best_email_draft,
        'best_linkedin_touch': best_linkedin_touch,
        'leads_needing_more_info': [_lead_summary(l) for l in leads_needing_more_info],
    }
