"""
Multifamily Command pipeline orchestrator.

Runs all signal collectors (currently mock/stub), dedupes, scores,
explains, and attaches a suggested opener + next-best-action to every
lead. Entirely in-memory — no DB writes — so it can be exercised from
the demo/test scripts and the Flask API layer alike.
"""
import hashlib
from typing import Any, Callable, List, Optional, Tuple

from multifamily.types import MultifamilyLead, MultifamilySourceRun, INBOUND_INTENT_SOURCES, new_id, utc_now_iso
from multifamily.dedupe import dedupe_leads
from multifamily.funnel.urgency import compute_funnel_urgency


def _stable_demo_id(lead: MultifamilyLead) -> str:
    """Deterministic id for a demo lead so it stays the same across pipeline
    runs (otherwise the single-lead drawer fetch would 404 because demo ids
    are regenerated every request). Keyed on company + property + source."""
    key = '|'.join([
        (lead.company.name or '').strip().lower(),
        (lead.property.name or '').strip().lower(),
        lead.primary_source or '',
    ])
    return 'demo-' + hashlib.md5(key.encode('utf-8')).hexdigest()[:16]
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.scoring.multifamily_score_explanations import explain_why_warm, explain_likely_pain
from multifamily.daily_brief.multifamily_next_best_action import next_best_action_for_lead

# Higher rank sorts first — keeps Call Today/Hot leads at the top of every
# dashboard list regardless of raw point ties, so the dashboard prioritizes
# real inbound intent over generic trigger-based leads.
_CATEGORY_PRIORITY_RANK = {'call_today': 4, 'hot': 3, 'warm': 2, 'nurture': 1, 'watchlist': 0}

# Funnel Phase 4: tie-break within the same category/score by how close
# the lead's OWN reported deadline is (acquisition close, lender
# deadline, etc.) — never overrides category or score, only breaks ties
# between otherwise-equal leads.
_URGENCY_PRIORITY_RANK = {'high': 3, 'medium': 2, 'low': 1, 'none': 0}

from multifamily.signal_collectors import (
    form_lead_ingestor, website_intent, search_console, google_ads,
    linkedin_lead_forms, permit_feed, news_monitor, crm_renewals,
)
from multifamily.outreach import (
    renewal_opener_generator, acquisition_opener_generator,
    construction_opener_generator, website_intent_opener_generator,
    nepq_multifamily_angle_builder,
)

COLLECTORS: List[Tuple[str, Any]] = [
    ('form', form_lead_ingestor.collect),
    ('website', website_intent.collect),
    ('search_console', search_console.collect),
    ('google_ads', google_ads.collect),
    ('linkedin_lead_form', linkedin_lead_forms.collect),
    ('permit', permit_feed.collect),
    ('news', news_monitor.collect),
    ('crm', crm_renewals.collect),
]

_RENEWAL_TYPES = {'renewal_date_known'}
_ACQUISITION_TYPES = {'acquisition', 'refinance', 'financing'}
_CONSTRUCTION_TYPES = {
    'permit_filed', 'planning_approval', 'groundbreaking', 'vertical_construction', 'completion',
}
_WEBSITE_INTENT_TYPES = {
    'website_visit', 'repeat_website_visit', 'keyword_intent', 'paid_search_click',
    'calculator_submit', 'guide_download',
}


def build_opener(lead: MultifamilyLead) -> str:
    """Pick the right outreach opener generator for a lead's signal mix.
    Public so multifamily/intake.py can reuse it for real leads."""
    signal_types = {s.signal_type for s in lead.signals}
    if signal_types & _RENEWAL_TYPES:
        return renewal_opener_generator.generate(lead)
    if signal_types & _ACQUISITION_TYPES:
        return acquisition_opener_generator.generate(lead)
    if signal_types & _CONSTRUCTION_TYPES:
        return construction_opener_generator.generate(lead)
    if signal_types & _WEBSITE_INTENT_TYPES:
        return website_intent_opener_generator.generate(lead)
    return nepq_multifamily_angle_builder.build_angle(lead)


def run_pipeline() -> Tuple[List[MultifamilyLead], List[MultifamilySourceRun]]:
    """Run every signal collector, then dedupe/score/explain every lead."""
    leads: List[MultifamilyLead] = []
    source_runs: List[MultifamilySourceRun] = []

    for source_name, collector_fn in COLLECTORS:
        run = MultifamilySourceRun(id=new_id(), source=source_name, started_at=utc_now_iso())
        try:
            collected = collector_fn()
        except Exception as exc:  # collector failures must never crash the pipeline
            collected = []
            run.notes = f'collector_error: {exc}'
        run.completed_at = utc_now_iso()
        run.records_found = len(collected)
        source_runs.append(run)
        leads.extend(collected)

    leads = dedupe_leads(leads)

    for lead in leads:
        lead.id = _stable_demo_id(lead)  # stable across requests for drawer fetches
        lead.score = score_lead(lead)
        lead.why_warm = explain_why_warm(lead)
        lead.likely_pain = explain_likely_pain(lead)
        lead.suggested_opener = build_opener(lead)
        lead.next_best_action = next_best_action_for_lead(lead)

    leads = sort_leads_by_priority(leads)

    return leads, source_runs


def sort_leads_by_priority(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    """Rank by score category first (Call Today > Hot > Warm > Nurture >
    Watchlist), then by raw total — so real inbound intent always surfaces
    above generic trigger-based leads, even on point ties. Funnel urgency
    (Phase 4) only breaks ties WITHIN the same category+total — it never
    changes scoring math or moves a lead into a different category."""
    def _key(lead: MultifamilyLead):
        if not lead.score:
            return (-1, 0, 0)
        urgency_rank = _URGENCY_PRIORITY_RANK.get(compute_funnel_urgency(lead).get('level'), 0)
        return (_CATEGORY_PRIORITY_RANK.get(lead.score.category, -1), lead.score.total, urgency_rank)

    return sorted(leads, key=_key, reverse=True)


def filter_leads(
    leads: List[MultifamilyLead],
    state: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    signal_type: Optional[str] = None,
) -> List[MultifamilyLead]:
    result = leads
    if state:
        result = [l for l in result if l.state == state]
    if category:
        result = [l for l in result if l.score and l.score.category == category]
    if source:
        result = [l for l in result if l.primary_source == source]
    if signal_type:
        result = [l for l in result if any(s.signal_type == signal_type for s in l.signals)]
    return result


def website_intent_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if {s.signal_type for s in l.signals} & _WEBSITE_INTENT_TYPES]


def renewal_opportunity_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if {s.signal_type for s in l.signals} & _RENEWAL_TYPES or l.primary_source == 'crm']


def acquisition_trigger_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if {s.signal_type for s in l.signals} & _ACQUISITION_TYPES]


def construction_trigger_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if {s.signal_type for s in l.signals} & _CONSTRUCTION_TYPES]


def inbound_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if l.primary_source in INBOUND_INTENT_SOURCES]


def call_today_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if l.score and l.score.category == 'call_today']


def completion_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    """Completion / lease-up: a completion construction signal (the
    builder's-risk -> operating-coverage transition window)."""
    return [l for l in leads if any(s.signal_type == 'completion' for s in l.signals)]


def nurture_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    return [l for l in leads if l.score and l.score.category in ('nurture', 'watchlist')]


def with_demo_fallback(
    real_leads: List[MultifamilyLead],
    mock_leads: List[MultifamilyLead],
    filter_fn: Callable[[List[MultifamilyLead]], List[MultifamilyLead]],
) -> List[MultifamilyLead]:
    """Apply `filter_fn` to real leads first. Real leads always win and are
    never silently mixed with mock/demo leads — if (and only if) this
    specific view has zero matching real leads, fall back to the same
    filter applied to the mock/demo pipeline (every mock lead carries
    is_demo=True, so the UI can label it clearly)."""
    real_filtered = sort_leads_by_priority(filter_fn(real_leads))
    if real_filtered:
        return real_filtered
    return sort_leads_by_priority(filter_fn(mock_leads))
