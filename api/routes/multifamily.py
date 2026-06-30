"""
API Routes: Multifamily Command
Flask Blueprint for the standalone multifamily insurance lead
intelligence module. Entirely separate from the BTR `li_*` lead queue —
multifamily leads are never merged into BTR endpoints/tables.
"""
import dataclasses

from flask import Blueprint, request, jsonify

from multifamily.pipeline import (
    run_pipeline, filter_leads, website_intent_leads,
    renewal_opportunity_leads, acquisition_trigger_leads,
    construction_trigger_leads, inbound_leads,
)
from multifamily.daily_brief.multifamily_daily_brief_builder import build_daily_brief

multifamily_bp = Blueprint('multifamily', __name__, url_prefix='/api/multifamily')


def _serialize_leads(leads):
    return [dataclasses.asdict(l) for l in leads]


def _run():
    """Re-run the (mock) pipeline for this request.

    The pipeline is pure/in-memory and cheap at mock-data volume, so we
    recompute per-request rather than caching — keeps this endpoint
    trivially correct as collectors are swapped for real integrations.
    """
    leads, source_runs = run_pipeline()
    return leads, source_runs


@multifamily_bp.route('/leads', methods=['GET'])
def get_leads():
    """GET /api/multifamily/leads?state=&category=&source=&signal_type="""
    leads, _ = _run()
    leads = filter_leads(
        leads,
        state=request.args.get('state'),
        category=request.args.get('category'),
        source=request.args.get('source'),
        signal_type=request.args.get('signal_type'),
    )
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/inbound', methods=['GET'])
def get_inbound_leads():
    leads, _ = _run()
    leads = inbound_leads(leads)
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/website-intent', methods=['GET'])
def get_website_intent_leads():
    leads, _ = _run()
    leads = website_intent_leads(leads)
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/renewal-opportunities', methods=['GET'])
def get_renewal_opportunities():
    leads, _ = _run()
    leads = renewal_opportunity_leads(leads)
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/acquisition-triggers', methods=['GET'])
def get_acquisition_triggers():
    leads, _ = _run()
    leads = acquisition_trigger_leads(leads)
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/construction-triggers', methods=['GET'])
def get_construction_triggers():
    leads, _ = _run()
    leads = construction_trigger_leads(leads)
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/california', methods=['GET'])
def get_california_leads():
    leads, _ = _run()
    leads = filter_leads(leads, state='CA')
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/leads/texas', methods=['GET'])
def get_texas_leads():
    leads, _ = _run()
    leads = filter_leads(leads, state='TX')
    return jsonify({'leads': _serialize_leads(leads), 'count': len(leads)})


@multifamily_bp.route('/outreach-workbench', methods=['GET'])
def get_outreach_workbench():
    """Leads worth an outreach touch today, ranked by score."""
    leads, _ = _run()
    ranked = sorted(
        (l for l in leads if l.score and not l.score.disqualified and l.score.category in ('call_today', 'hot', 'warm')),
        key=lambda l: l.score.total, reverse=True,
    )
    return jsonify({'leads': _serialize_leads(ranked), 'count': len(ranked)})


@multifamily_bp.route('/daily-brief', methods=['GET'])
def get_daily_brief():
    leads, _ = _run()
    return jsonify(build_daily_brief(leads))


@multifamily_bp.route('/overview', methods=['GET'])
def get_overview():
    """Summary stats for the Multifamily Overview dashboard section."""
    leads, source_runs = _run()
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
        'by_category': by_category,
        'by_state': by_state,
        'by_source': by_source,
        'source_runs': [dataclasses.asdict(r) for r in source_runs],
    })
