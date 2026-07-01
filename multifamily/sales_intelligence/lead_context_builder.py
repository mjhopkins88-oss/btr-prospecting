"""
Builds a complete SalesLeadContext from a lead's already-computed data —
score, process-stage timing, signals, activities, outcomes. Pure and
read-only: never recomputes scoring math, never mutates the lead, never
makes a network/DB call itself (callers pass in whatever history they
already have, same pattern as multifamily/snapshots.py).
"""
from typing import Any, Dict, List, Optional

from multifamily.types import MultifamilyLead
from multifamily.timing.process_stage_types import ProcessStageResult
from multifamily.sales_intelligence.nepq_types import SalesLeadContext

_DIRECT_ASK_SIGNALS = {'quote_request', 'meeting_request'}
_RESEARCH_SIGNALS = {'benchmark_form_submit', 'linkedin_lead_form_submit', 'calculator_submit'}
_LOW_INTENT_WEB_SIGNALS = {'website_visit', 'repeat_website_visit', 'keyword_intent', 'paid_search_click', 'guide_download'}
_TRIGGER_ONLY_SOURCES = {'permit', 'news'}
_CONSTRUCTION_STAGES = {'construction_loan_closing', 'construction_start', 'entitlement_or_permit'}
_CONSTRUCTION_SIGNALS = {'permit_filed', 'planning_approval', 'groundbreaking', 'vertical_construction'}
_ACQUISITION_SIGNALS = {'acquisition', 'refinance', 'financing'}

_ORIGIN_BY_SOURCE = {
    'benchmark_form': 'benchmark_request',
    'form': 'inbound_form',
    'manual': 'manual',
    'website': 'website_intent',
    'search_console': 'paid_search',
    'google_ads': 'paid_search',
    'linkedin_lead_form': 'linkedin_lead_form',
    'crm': 'crm',
    'permit': 'permit_trigger',
    'news': 'news_trigger',
}

_DECISION_MAKER_TITLE_MAP = [
    (('owner', 'principal', 'president', 'ceo', 'founder', 'partner'), 'Owner / Principal'),
    (('cfo', 'controller', 'vp of finance', 'finance', 'treasurer'), 'CFO / Finance'),
    (('risk manager', 'vp of risk', 'insurance'), 'Risk Manager / Insurance'),
    (('development', 'construction', 'project executive', 'project manager'), 'Development / Construction'),
    (('asset management', 'operations', 'property manager', 'coo'), 'Asset Management / Operations'),
]

_EMOTIONAL_DRIVER_BY_SCENARIO = {
    'premium_increase': 'frustration over rising cost eating into NOI',
    'deductible_concern': 'anxiety about being underinsured or overexposed at claim time',
    'lender_requirement': 'pressure to satisfy a lender deadline without slowing the deal',
    'builders_risk': 'concern about being exposed mid-construction',
    'gl_excess_concern': 'worry about liability exposure across the portfolio',
    'renewal_pressure': 'fatigue with the current renewal process or broker',
    'acquisition_due_diligence': 'need for certainty before committing capital',
    'refinance_or_financing': 'pressure to clear lender conditions on time',
    'completion_or_lease_up': 'concern about a coverage gap during the transition to operating',
    'claims_or_service_issue': 'frustration with how a claim or service issue was handled',
    'just_benchmarking': 'curiosity / routine due diligence, no acute pain yet',
    'unknown': 'unclear — not enough signal yet',
}


def _infer_origin(lead: MultifamilyLead) -> str:
    mapped = _ORIGIN_BY_SOURCE.get(lead.primary_source or '')
    if mapped:
        return mapped
    signal_types = {s.signal_type for s in (lead.signals or [])}
    if signal_types & _ACQUISITION_SIGNALS:
        return 'acquisition_trigger'
    if signal_types & _CONSTRUCTION_SIGNALS:
        return 'construction_trigger'
    utm = ((lead.utm_source or '') + ' ' + (lead.utm_campaign or '')).lower()
    if 'referral' in utm:
        return 'referral'
    return 'unknown'


def _infer_scenario(lead: MultifamilyLead, process_stage: Optional[str]) -> str:
    pain = set(lead.pain_flags or [])
    if 'premium_increase' in pain:
        return 'premium_increase'
    if 'deductible_concern' in pain:
        return 'deductible_concern'
    if 'lender_requirement' in pain:
        return 'lender_requirement'
    if 'builders_risk_need' in pain:
        return 'builders_risk'
    if 'gl_excess_concern' in pain:
        return 'gl_excess_concern'
    situation = None
    for s in (lead.signals or []):
        if (s.detail or {}).get('lead_situation'):
            situation = s.detail['lead_situation']
            break
    if situation == 'renewal' or process_stage in ('renewal_window', 'post_renewal'):
        return 'renewal_pressure'
    if situation == 'acquisition' or process_stage == 'acquisition_due_diligence':
        return 'acquisition_due_diligence'
    if situation == 'refinance' or process_stage == 'refinance_or_financing':
        return 'refinance_or_financing'
    if situation == 'construction' or process_stage in _CONSTRUCTION_STAGES:
        return 'builders_risk'
    if process_stage == 'completion_or_lease_up':
        return 'completion_or_lease_up'
    if situation == 'benchmark':
        return 'just_benchmarking'
    return 'unknown'


def _infer_buyer_awareness(lead: MultifamilyLead) -> str:
    signal_types = {s.signal_type for s in (lead.signals or [])}
    if signal_types & _DIRECT_ASK_SIGNALS:
        return 'decision_ready'
    if signal_types & _RESEARCH_SIGNALS:
        return 'solution_aware'
    if (lead.pain_flags or []) or (signal_types & (_ACQUISITION_SIGNALS | _CONSTRUCTION_SIGNALS)):
        return 'problem_aware'
    if signal_types & _LOW_INTENT_WEB_SIGNALS:
        return 'unaware'
    if lead.primary_source in _TRIGGER_ONLY_SOURCES:
        return 'unaware'
    return 'unknown'


def _infer_resistance_risk(lead: MultifamilyLead) -> str:
    category = lead.score.category if lead.score else None
    if lead.primary_source in _TRIGGER_ONLY_SOURCES:
        return 'high'
    if category in ('nurture', 'watchlist'):
        return 'high'
    if lead.score and lead.score.disqualifier_codes:
        return 'medium'
    if getattr(lead, 'spam_status', 'clean') == 'suspicious':
        return 'medium'
    if category == 'warm':
        return 'medium'
    return 'low'


def _infer_decision_maker(lead: MultifamilyLead) -> Optional[str]:
    contact = lead.contacts[0] if lead.contacts else None
    title = (contact.title if contact else None) or ''
    title_lower = title.lower()
    for keywords, label in _DECISION_MAKER_TITLE_MAP:
        if any(k in title_lower for k in keywords):
            return label
    return None


def _missing_information(lead: MultifamilyLead, activities: List[Dict[str, Any]], scenario: str) -> List[str]:
    missing = []
    has_renewal_signal = any(s.signal_type == 'renewal_date_known' for s in (lead.signals or []))
    if scenario in ('renewal_pressure', 'premium_increase', 'deductible_concern') and not has_renewal_signal:
        missing.append('renewal date')
    if not (lead.contacts and lead.contacts[0].title):
        missing.append('decision-maker role')
    if not lead.property.unit_count:
        missing.append('unit count')
    missing.append('current premium/deductible figures')  # never captured at intake
    if not activities:
        missing.append('no engagement history yet')
    return missing


def _conversation_risk_notes(lead: MultifamilyLead) -> List[str]:
    notes = []
    if getattr(lead, 'spam_status', 'clean') == 'suspicious':
        notes.append('flagged suspicious at intake — proceed carefully, verify before investing time')
    if lead.score and lead.score.disqualified:
        notes.append(f'disqualified: {lead.score.disqualified_reason or "missing required data"}')
    if lead.primary_source in _TRIGGER_ONLY_SOURCES:
        notes.append('third-party trigger only — no direct engagement from this contact yet')
    if lead.is_demo:
        notes.append('demo data — no real activity/outcome history available')
    return notes


def build_lead_context(
    lead: MultifamilyLead,
    stage_result: Optional[ProcessStageResult] = None,
    activities: Optional[List[Dict[str, Any]]] = None,
    outcomes: Optional[List[Dict[str, Any]]] = None,
) -> SalesLeadContext:
    activities = activities or []
    outcomes = outcomes or []
    score = lead.score
    process_stage = stage_result.process_stage if stage_result else None
    scenario = _infer_scenario(lead, process_stage)

    renewal_signal = next((s for s in (lead.signals or []) if s.signal_type == 'renewal_date_known'), None)
    renewal_detail = (renewal_signal.detail or {}) if renewal_signal else {}
    project_signal = next(
        (s for s in (lead.signals or []) if s.signal_type in ('permit_filed', 'planning_approval', 'groundbreaking')), None
    )
    project_detail = (project_signal.detail or {}) if project_signal else {}

    contact = lead.contacts[0] if lead.contacts else None

    return SalesLeadContext(
        lead_id=lead.id,
        company_name=lead.company.name,
        is_demo=lead.is_demo,
        score_total=(score.total if score else None),
        score_category=(score.category if score else None),
        reason_codes=list(score.reason_codes) if score else [],
        disqualifier_codes=list(score.disqualifier_codes) if score else [],
        pain_flags=list(lead.pain_flags or []),
        relationship_flags=list(lead.relationship_flags or []),
        primary_source=lead.primary_source,
        signal_count=len(lead.signals or []),
        signal_types=sorted({s.signal_type for s in (lead.signals or [])}),
        process_stage=process_stage,
        outreach_window=(stage_result.outreach_window if stage_result else None),
        timing_reason=(stage_result.timing_reason if stage_result else None),
        timing_confidence=(stage_result.timing_confidence if stage_result else None),
        lead_situation=next((s.detail.get('lead_situation') for s in (lead.signals or []) if (s.detail or {}).get('lead_situation')), None),
        asset_type=lead.property.asset_type,
        unit_count=lead.property.unit_count,
        state=lead.state,
        city=lead.city,
        contact_first_name=((contact.full_name or '').strip().split()[0] if contact and contact.full_name else None),
        contact_title=(contact.title if contact else None),
        renewal_date=renewal_detail.get('renewal_date'),
        days_until_renewal=renewal_detail.get('days_until_renewal'),
        project_start_date=project_detail.get('project_start_date'),
        utm_source=lead.utm_source,
        utm_campaign=lead.utm_campaign,
        activity_count=len(activities),
        last_activity_type=(activities[0].get('activity_type') if activities else None),
        replied=any(a.get('activity_type') == 'replied' for a in activities),
        followup_due=bool(activities and activities[0].get('next_follow_up_date')),
        current_outcome_type=(outcomes[0].get('outcome_type') if outcomes else None),
        spam_status=getattr(lead, 'spam_status', 'clean'),
        is_suspicious=(getattr(lead, 'spam_status', 'clean') == 'suspicious'),
        lead_temperature=(score.category if score else 'watchlist'),
        lead_origin=_infer_origin(lead),
        insurance_scenario=scenario,
        buyer_awareness_level=_infer_buyer_awareness(lead),
        resistance_risk=_infer_resistance_risk(lead),
        likely_decision_maker_type=_infer_decision_maker(lead),
        likely_emotional_driver=_EMOTIONAL_DRIVER_BY_SCENARIO.get(scenario, _EMOTIONAL_DRIVER_BY_SCENARIO['unknown']),
        missing_information=_missing_information(lead, activities, scenario),
        conversation_risk_notes=_conversation_risk_notes(lead),
    )
