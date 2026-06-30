"""
API Routes: Multifamily Command
Flask Blueprint for the standalone multifamily insurance lead
intelligence module. Entirely separate from the BTR `li_*` lead queue —
multifamily leads are never merged into BTR endpoints/tables.

Real leads (captured via POST /api/multifamily/leads) always take
priority over mock/demo leads. Mock data is a per-view fallback only —
every `/leads/*` view independently falls back to demo data (clearly
flagged via `is_demo` on each lead, and `is_demo_data` on aggregate
responses) only when it has zero matching real leads.
"""
import dataclasses

from flask import Blueprint, request, jsonify

from multifamily.pipeline import (
    run_pipeline, filter_leads, website_intent_leads,
    renewal_opportunity_leads, acquisition_trigger_leads,
    construction_trigger_leads, inbound_leads, with_demo_fallback,
    sort_leads_by_priority,
)
from multifamily.daily_brief.multifamily_daily_brief_builder import build_daily_brief
from multifamily.intake import build_lead_from_intake
from multifamily import repository

multifamily_bp = Blueprint('multifamily', __name__, url_prefix='/api/multifamily')


def _serialize_leads(leads):
    return [dataclasses.asdict(l) for l in leads]


def _real_and_mock():
    """Real (persisted) leads + the mock/demo pipeline output, both ranked
    Call Today > Hot > Warm > Nurture > Watchlist. The mock pipeline is
    pure/in-memory and cheap at demo-data volume, so it's recomputed per
    request rather than cached."""
    real_leads = repository.get_real_leads()
    mock_leads, source_runs = run_pipeline()
    return real_leads, mock_leads, source_runs


def _view(filter_fn):
    real_leads, mock_leads, _ = _real_and_mock()
    leads = with_demo_fallback(real_leads, mock_leads, filter_fn)
    return jsonify({
        'leads': _serialize_leads(leads),
        'count': len(leads),
        'is_demo_data': bool(leads) and all(l.is_demo for l in leads),
    })


@multifamily_bp.route('/leads', methods=['GET'])
def get_leads():
    """GET /api/multifamily/leads?state=&category=&source=&signal_type="""
    state = request.args.get('state')
    category = request.args.get('category')
    source = request.args.get('source')
    signal_type = request.args.get('signal_type')
    return _view(lambda ls: filter_leads(ls, state=state, category=category, source=source, signal_type=signal_type))


@multifamily_bp.route('/leads', methods=['POST'])
def create_lead():
    """POST /api/multifamily/leads — real lead intake (public benchmark
    form or internal manual entry). Accepts: name, company, email, phone,
    role, state, city, assetType, numberOfUnits, leadSituation,
    renewalDate, projectStartDate, primaryConcern, notes, source,
    sourcePage, sourceUrl. Scores the lead immediately and persists it."""
    payload = request.get_json(silent=True) or {}
    lead, errors = build_lead_from_intake(payload)
    if errors:
        return jsonify({'success': False, 'errors': errors}), 400

    repository.insert_lead(lead)
    return jsonify({'success': True, 'lead': dataclasses.asdict(lead)}), 201


@multifamily_bp.route('/leads/inbound', methods=['GET'])
def get_inbound_leads():
    return _view(inbound_leads)


@multifamily_bp.route('/leads/website-intent', methods=['GET'])
def get_website_intent_leads():
    return _view(website_intent_leads)


@multifamily_bp.route('/leads/renewal-opportunities', methods=['GET'])
def get_renewal_opportunities():
    return _view(renewal_opportunity_leads)


@multifamily_bp.route('/leads/acquisition-triggers', methods=['GET'])
def get_acquisition_triggers():
    return _view(acquisition_trigger_leads)


@multifamily_bp.route('/leads/construction-triggers', methods=['GET'])
def get_construction_triggers():
    return _view(construction_trigger_leads)


@multifamily_bp.route('/leads/california', methods=['GET'])
def get_california_leads():
    return _view(lambda ls: filter_leads(ls, state='CA'))


@multifamily_bp.route('/leads/texas', methods=['GET'])
def get_texas_leads():
    return _view(lambda ls: filter_leads(ls, state='TX'))


@multifamily_bp.route('/outreach-workbench', methods=['GET'])
def get_outreach_workbench():
    """Leads worth an outreach touch today, ranked Call Today > Hot > Warm."""
    def _actionable(ls):
        return [l for l in ls if l.score and not l.score.disqualified and l.score.category in ('call_today', 'hot', 'warm')]
    return _view(_actionable)


@multifamily_bp.route('/daily-brief', methods=['GET'])
def get_daily_brief():
    real_leads, mock_leads, _ = _real_and_mock()
    leads = real_leads if real_leads else mock_leads
    brief = build_daily_brief(sort_leads_by_priority(leads))
    brief['is_demo_data'] = bool(leads) and all(l.is_demo for l in leads)
    return jsonify(brief)


@multifamily_bp.route('/overview', methods=['GET'])
def get_overview():
    """Summary stats for the Multifamily Overview dashboard section."""
    real_leads, mock_leads, source_runs = _real_and_mock()
    leads = real_leads if real_leads else mock_leads
    is_demo_data = bool(leads) and all(l.is_demo for l in leads)

    scored = [l for l in leads if l.score]
    by_category = {}
    for l in scored:
        by_category[l.score.category] = by_category.get(l.score.category, 0) + 1
    by_state = {}
    for l in leads:
        key = l.state or 'unknown'
        by_state[key] = by_state.get(key, 0) + 1
    by_source = {}
    for l in leads:
        by_source[l.primary_source] = by_source.get(l.primary_source, 0) + 1

    return jsonify({
        'total_leads': len(leads),
        'real_lead_count': len(real_leads),
        'is_demo_data': is_demo_data,
        'by_category': by_category,
        'by_state': by_state,
        'by_source': by_source,
        'source_runs': [dataclasses.asdict(r) for r in source_runs],
    })
