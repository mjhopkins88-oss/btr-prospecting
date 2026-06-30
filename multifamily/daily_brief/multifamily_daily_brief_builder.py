"""
Daily brief builder — aggregates scored multifamily leads into the
sections the Multifamily Command dashboard and daily digest need.

Phase 2: the brief is split along two independent axes so the team can
see both "what kind of signal is this" and "how hot is it right now":

  - By signal source: inbound_leads, website_intent_leads,
    renewal_opportunities, trigger_based_opportunities. A lead lands in
    every bucket it has a matching signal for — e.g. a benchmark-form
    submission that *also* has a known renewal date shows up in both
    inbound_leads and renewal_opportunities, since both facts matter
    operationally (this is real inbound intent that ALSO has a clock on
    it). These are not a strict partition.
  - By score category (mutually exclusive, covers every scored lead):
    call_today_leads, hot_leads, warm_leads, nurture_watchlist_leads.
"""
from typing import Any, Dict, List

from multifamily.types import MultifamilyLead
from multifamily.daily_brief.multifamily_next_best_action import next_best_action_for_lead

# True inbound intent — an explicit submission/action, not just browsing.
DIRECT_INBOUND_SIGNAL_TYPES = {
    'benchmark_form_submit', 'quote_request', 'meeting_request',
    'calculator_submit', 'linkedin_lead_form_submit', 'guide_download',
}
# Passive on-site/search behavior — intent, but not yet a submission.
WEBSITE_INTENT_SIGNAL_TYPES = {
    'website_visit', 'repeat_website_visit', 'keyword_intent', 'paid_search_click',
}
RENEWAL_SIGNAL_TYPES = {'renewal_date_known'}
# Market/construction triggers — non-inbound, third-party-sourced events.
TRIGGER_SIGNAL_TYPES = {
    'acquisition', 'refinance', 'financing', 'permit_filed', 'planning_approval',
    'groundbreaking', 'vertical_construction', 'completion', 'portfolio_growth',
}


def _has_any_signal_type(lead: MultifamilyLead, types: set) -> bool:
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
        'reason_codes': lead.score.reason_codes if lead.score else [],
        'disqualifier_codes': lead.score.disqualifier_codes if lead.score else [],
        'next_best_action': lead.next_best_action or next_best_action_for_lead(lead),
        'suggested_opener': lead.suggested_opener,
    }


def build_daily_brief(leads: List[MultifamilyLead]) -> Dict[str, Any]:
    # `leads` arrives pre-sorted by pipeline.sort_leads_by_priority() —
    # Call Today > Hot > Warm > Nurture > Watchlist, then by score — so
    # every bucket below is already ranked best-first.
    scored = [l for l in leads if l.score is not None]

    inbound_leads = [l for l in leads if _has_any_signal_type(l, DIRECT_INBOUND_SIGNAL_TYPES)]
    website_intent_leads = [l for l in leads if _has_any_signal_type(l, WEBSITE_INTENT_SIGNAL_TYPES)]
    renewal_opportunities = [
        l for l in leads if _has_any_signal_type(l, RENEWAL_SIGNAL_TYPES) or l.primary_source == 'crm'
    ]
    trigger_based_opportunities = [l for l in leads if _has_any_signal_type(l, TRIGGER_SIGNAL_TYPES)]

    call_today_leads = [l for l in scored if l.score.category == 'call_today']
    hot_leads = [l for l in scored if l.score.category == 'hot']
    warm_leads = [l for l in scored if l.score.category == 'warm']
    nurture_watchlist_leads = [l for l in scored if l.score.category in ('nurture', 'watchlist')]

    leads_needing_more_info = [
        l for l in leads
        if (l.score and l.score.disqualified) or (l.score and l.score.disqualifier_codes)
    ]

    ranked = [l for l in scored if not l.score.disqualified]
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
        # By signal source — a lead can appear in more than one bucket.
        'inbound_leads': [_lead_summary(l) for l in inbound_leads],
        'website_intent_leads': [_lead_summary(l) for l in website_intent_leads],
        'renewal_opportunities': [_lead_summary(l) for l in renewal_opportunities],
        'trigger_based_opportunities': [_lead_summary(l) for l in trigger_based_opportunities],
        # By score category — mutually exclusive, covers every scored lead.
        'call_today_leads': [_lead_summary(l) for l in call_today_leads],
        'hot_leads': [_lead_summary(l) for l in hot_leads],
        'warm_leads': [_lead_summary(l) for l in warm_leads],
        'nurture_watchlist_leads': [_lead_summary(l) for l in nurture_watchlist_leads],
        # Action picks.
        'top_3_actions_today': top_3_actions_today,
        'best_first_call': best_first_call,
        'best_email_draft': best_email_draft,
        'best_linkedin_touch': best_linkedin_touch,
        'leads_needing_more_info': [_lead_summary(l) for l in leads_needing_more_info],
    }
