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
from multifamily import spam_guard

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
    sourcePage, sourceUrl, plus utmSource/utmMedium/utmCampaign/utmTerm/
    utmContent/referrer/landingPage/offerType and a hidden honeypot field
    (multifamily/spam_guard.HONEYPOT_FIELD). Scores the lead immediately
    and persists it.

    Layered abuse protection (see multifamily/spam_guard.py):
      - oversized payloads and rate-limited IPs/emails are rejected
        outright (413 / 429) before any lead is built
      - field validation still returns clean, specific 400 errors for
        legitimate users
      - honeypot / garbage-content detection never blocks the request
        (so a bot gets the same 201 a real user would) — it only tags
        the persisted lead's spam_status so it's excluded from normal
        dashboard views
    """
    if not spam_guard.check_payload_size(request.content_length):
        return jsonify({'success': False, 'errors': ['Submission too large.']}), 413

    payload = request.get_json(silent=True) or {}

    ip = spam_guard.get_client_ip(dict(request.headers), request.remote_addr)
    ip_hash = spam_guard.hash_ip(ip)
    user_agent_summary = spam_guard.summarize_user_agent(request.headers.get('User-Agent'))
    email = (payload.get('email') or '').strip().lower() or None

    rate_limit_reason = spam_guard.check_rate_limit(ip_hash, email)
    if rate_limit_reason:
        event_type = 'rate_limited_ip' if rate_limit_reason == 'RATE_LIMIT_IP' else 'rate_limited_email'
        repository.record_intake_event(event_type, ip_hash, email)
        return jsonify({'success': False, 'errors': ['Too many submissions from this source. Please try again later.']}), 429

    spam_status, spam_reason_codes = spam_guard.classify_spam(payload)

    lead, errors = build_lead_from_intake(
        payload, ip_hash=ip_hash, user_agent_summary=user_agent_summary,
        spam_status=spam_status, spam_reason_codes=spam_reason_codes,
    )
    if errors:
        repository.record_intake_event('invalid', ip_hash, email, {'errors': errors})
        return jsonify({'success': False, 'errors': errors}), 400

    repository.insert_lead(lead)

    if spam_status == 'rejected':
        event_type = 'rejected_honeypot' if 'HONEYPOT_FILLED' in spam_reason_codes else 'rejected_garbage'
    elif spam_status == 'suspicious':
        event_type = 'accepted_suspicious'
    else:
        event_type = 'accepted_clean'
    repository.record_intake_event(event_type, ip_hash, email, {'spam_reason_codes': spam_reason_codes})

    # Always a normal-looking success — never reveal spam detection to the submitter.
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


@multifamily_bp.route('/admin/intake-stats', methods=['GET'])
def get_intake_stats():
    """Admin/debug view: recent submissions (including rejected/suspicious
    — repository.get_intake_stats() does NOT filter by spam_status, unlike
    every other endpoint in this blueprint), spam-status counts, rate
    limit hits, and source/campaign breakdown.

    NOTE: like the rest of this blueprint, this route has no server-side
    auth check of its own — it's gated client-side (Multifamily Admin
    tab, super_admin only), consistent with the multifamily blueprint's
    current security model. Adding real session-based auth here is a
    reasonable follow-up once the blueprint as a whole gets an auth pass."""
    return jsonify(repository.get_intake_stats())
