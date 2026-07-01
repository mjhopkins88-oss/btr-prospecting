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
import re
from datetime import date, datetime, timedelta
from typing import Any, Dict

from flask import Blueprint, request, jsonify

from multifamily.pipeline import (
    run_pipeline, filter_leads, website_intent_leads,
    renewal_opportunity_leads, acquisition_trigger_leads,
    construction_trigger_leads, inbound_leads, with_demo_fallback,
    sort_leads_by_priority, call_today_leads, completion_leads, nurture_leads,
)
from multifamily.daily_brief.multifamily_daily_brief_builder import build_daily_brief
from multifamily.intake import build_lead_from_intake
from multifamily import repository
from multifamily import spam_guard
from multifamily.types import (
    ACTIVITY_TYPES, OUTCOME_TYPES, CAMPAIGN_STATUSES, CAMPAIGN_TARGET_STATUSES, CAMPAIGN_TARGET_TOUCH_STEPS,
)
from multifamily.stage_timing import compute_stage_timing
from multifamily.timing import detect_process_stage, estimate_first_renewal
from multifamily.timing.process_stage_types import OUTREACH_WINDOW_RANK
from multifamily.outreach.outreach_bundle_builder import build_outreach_bundle
from multifamily import matching as mf_matching
from multifamily.snapshots import snapshot_lead, SNAPSHOT_REASONS
from multifamily import notifications as mf_notifications
from multifamily.sales_intelligence.engine import build_sales_intelligence
from multifamily.sales_intelligence.follow_up_suggestions import (
    build_follow_up_suggestion as _follow_up_suggestion,
    attach_follow_up_suggestions as _attach_follow_up_suggestions,
)
from multifamily.sales_intelligence.tone_guardrails import check_message_package, worst_status
from multifamily.serp.query_templates import SerpQueryConfig, SERP_CATEGORIES, SERP_LAUNCH_STATES, SERP_FUTURE_STATES
from multifamily.forms.form_variants import (
    FORM_VARIANTS, FORM_VARIANT_SLUGS, DEFAULT_FORM_VARIANT_SLUG,
    recommend_form_variant_for_situation, recommendation_reason_for_slug,
)
from multifamily.funnel.urgency import compute_funnel_urgency
from multifamily.funnel.overview_widgets import best_inbound_handraiser, build_funnel_widgets
from multifamily.serp.serp_collector import run_serp_collection

multifamily_bp = Blueprint('multifamily', __name__, url_prefix='/api/multifamily')

# Per-lead fields that must NEVER reach a non-super-admin client (Part 5).
# `spam_status` is also stripped for non-admins; a coarse `is_suspicious`
# boolean is injected instead so the SUSPICIOUS badge still works without
# exposing the raw reason codes / hashed IP / user-agent.
_ADMIN_ONLY_LEAD_FIELDS = ('spam_reason_codes', 'submitted_ip_hash', 'user_agent_summary')


def _requester_is_super_admin():
    """Non-rejecting check of the current session — used only to decide
    whether sensitive spam/debug fields are included in the response.
    Lazy import of app avoids the circular import (app.py imports this
    blueprint before defining these helpers); by request time app is
    fully loaded in sys.modules. Any failure (no session, no users yet)
    safely returns False."""
    try:
        import app as _app
        user, _ = _app._get_session_user()
        if not user:
            return False
        return bool(
            user.get('role') == 'admin'
            and user.get('is_super_admin')
            and user.get('email') == _app.SUPER_ADMIN_EMAIL
        )
    except Exception:
        return False


def _signal_timeline(lead):
    """Chronological signal timeline derived from the lead's own signals
    (lead_json is the source of truth — no DB query needed, works for real
    and demo leads alike)."""
    items = []
    for s in (lead.signals or []):
        items.append({
            'id': s.id, 'signal_type': s.signal_type, 'source': s.source,
            'source_url': s.source_url, 'confidence': s.confidence,
            'occurred_at': s.occurred_at, 'detail': s.detail or {},
        })
    items.sort(key=lambda x: (x.get('occurred_at') or ''))
    return items


def _sales_intelligence_summary(lead, stage_result, activities, outcomes, pkg=None):
    """Compact Sales Intelligence snapshot for the drawer's "Sales
    Intelligence" tab and the Overview's Mission cards (Part 10) — not the
    full package (that's the dedicated /sales-intelligence endpoint used by
    the Outreach Workbench, which also includes messages + the objection
    playbook). Pass a precomputed `pkg` to avoid recomputing the engine
    twice when the caller already needed the full package (e.g. the
    Mission's best-email-draft card)."""
    if pkg is None:
        try:
            pkg = build_sales_intelligence(lead, stage_result=stage_result, activities=activities, outcomes=outcomes)
        except Exception:
            return None
    return {
        'recommended_action': pkg.strategy.recommended_action,
        'nepq_stage': pkg.strategy.starting_nepq_stage,
        'conversation_mode': pkg.strategy.conversation_mode,
        'buyer_awareness_level': pkg.context.buyer_awareness_level,
        'resistance_risk': pkg.context.resistance_risk,
        'likely_emotional_driver': pkg.context.likely_emotional_driver,
        'primary_question': pkg.question_path.connection_question,
        'message_angle': pkg.strategy.primary_objective,
        'what_to_avoid': pkg.strategy.do_not,
        'reasoning_summary': pkg.reasoning.why_this_stage,
        'confidence_score': pkg.reasoning.confidence_score,
        'follow_up_type': pkg.follow_up_strategy.follow_up_type,
        'follow_up_wait_days': pkg.follow_up_strategy.recommended_wait_days,
    }


def _serialize_lead(lead, is_admin, stage_result=None, with_history=False, current_outcome=None):
    """Serialize one lead, attaching LIVE timing intelligence (never
    persisted — it's time-dependent) and redacting admin-only fields for
    non-super-admins. With `with_history` (the single-lead drawer), also
    attach the full attribution history (Phase C) and outcome history
    (outcome-tracking phase). `current_outcome` (a lightweight dict or
    None) is bulk-fetched by the caller so list views don't cost one query
    per lead — see _serialize_leads."""
    d = dataclasses.asdict(lead)
    d['stage_timing'] = compute_stage_timing(lead)
    sr = stage_result or detect_process_stage(lead)
    d['process_stage'] = dataclasses.asdict(sr)
    d['is_suspicious'] = (getattr(lead, 'spam_status', 'clean') == 'suspicious')
    # Signal architecture (Phase C): cheap, always-on.
    d['signal_count'] = len(lead.signals or [])
    d['signal_timeline'] = _signal_timeline(lead)
    # Funnel Phase 4: derived, read-only — never touches score_total/category.
    d['funnel_urgency'] = compute_funnel_urgency(lead)
    # Section 8 item 2: first-renewal watchlist — derived, read-only, only
    # set for acquisition-origin leads with a known close date.
    first_renewal = estimate_first_renewal(lead)
    d['first_renewal_estimate'] = first_renewal['first_renewal_estimate'] if first_renewal else None
    d['renewal_window_opens_at'] = first_renewal['renewal_window_opens_at'] if first_renewal else None
    # Outcome tracking: cheap (bulk-fetched), always-on. Demo leads never
    # carry a persisted outcome.
    d['current_outcome'] = current_outcome
    if with_history:
        if lead.is_demo:
            # Demo leads aren't persisted; derive a one-touch summary from
            # the lead's own source/UTM fields.
            d['attribution'] = {
                'first_touch': {'source': lead.primary_source, 'utm_source': lead.utm_source,
                                'utm_campaign': lead.utm_campaign, 'occurred_at': lead.last_verified_at},
                'latest_touch': {'source': lead.primary_source, 'utm_source': lead.utm_source,
                                 'utm_campaign': lead.utm_campaign, 'occurred_at': lead.last_verified_at},
                'conversion_source': lead.primary_source, 'touches': [],
                'utm_history': [], 'landing_page_history': [], 'referrer_history': [],
            }
            d['outcomes'] = []
            d['snapshots'] = []
            activities, outcomes = [], []
        else:
            d['attribution'] = repository.get_attribution_summary(lead.id)
            outcomes = repository.get_outcomes_for_lead(lead.id)
            d['outcomes'] = outcomes
            d['snapshots'] = repository.get_snapshots_for_lead(lead.id)
            activities = repository.get_activities_for_lead(lead.id)
        d['sales_intelligence'] = _sales_intelligence_summary(lead, sr, activities, outcomes)
        if not lead.is_demo:
            d['recommended_form_variant'] = _recommended_form_variant(lead)
            d['outbound_links'] = repository.get_outbound_links_for_lead(lead.id)
    if not is_admin:
        for f in _ADMIN_ONLY_LEAD_FIELDS:
            d.pop(f, None)
        d.pop('spam_status', None)  # internal triage state — admin only
    return d


def _recommended_form_variant(lead) -> Dict[str, Any]:
    """Which offer page best fits sending THIS lead next, and why —
    surfaced by the Outreach Workbench alongside a "generate link"
    action (Funnel Phase 3). Never auto-sent; just a recommendation an
    operator acts on manually."""
    situation = repository.lead_situation_of(lead)
    variant = recommend_form_variant_for_situation(situation)
    return {
        'slug': variant.slug,
        'headline': variant.headline,
        'cta': variant.cta,
        'reason': recommendation_reason_for_slug(variant.slug),
    }


def _serialize_leads(leads):
    is_admin = _requester_is_super_admin()
    real_ids = [l.id for l in leads if not l.is_demo]
    outcome_map = repository.get_current_outcomes_for_leads(real_ids) if real_ids else {}
    return [_serialize_lead(l, is_admin, current_outcome=outcome_map.get(l.id)) for l in leads]


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


@multifamily_bp.route('/form-variants', methods=['GET'])
def get_form_variants():
    """Public, read-only config for every offer-page/form variant
    (multifamily/forms/form_variants.py — single source of truth). Used
    by the public offer pages (Multifamily Funnel Phase 2) to render
    headline/subheadline/CTA/fields/confirmation without duplicating
    copy in multiple HTML files, and by the Outreach Workbench's
    page-recommendation (Phase 3). No auth — this is public marketing
    copy, not lead data."""
    variants = {slug: dataclasses.asdict(v) for slug, v in FORM_VARIANTS.items()}
    return jsonify({
        'variants': variants,
        'default_slug': DEFAULT_FORM_VARIANT_SLUG,
        'slugs': FORM_VARIANT_SLUGS,
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
        mf_notifications.check_spam_spike()
        return jsonify({'success': False, 'errors': ['Too many submissions from this source. Please try again later.']}), 429

    spam_status, spam_reason_codes = spam_guard.classify_spam(payload)

    lead, errors = build_lead_from_intake(
        payload, ip_hash=ip_hash, user_agent_summary=user_agent_summary,
        spam_status=spam_status, spam_reason_codes=spam_reason_codes,
    )
    if errors:
        repository.record_intake_event('invalid', ip_hash, email, {'errors': errors})
        return jsonify({'success': False, 'errors': errors}), 400

    # Captured before any merge reassigns `lead` to the survivor — reflects
    # THIS submission, not whatever the resolved lead ends up looking like.
    raw_source = (payload.get('source') or '').strip()
    incoming_signal_id = lead.signals[0].id if lead.signals else None

    # ---- Pilot Campaign conversion (Campaign Phase 2) ----
    # A submission carrying ?t=<token> came from a specific campaign
    # target's tracked link — highest precedence, since a named campaign
    # is a more specific, more deliberate identity resolution than an
    # ad-hoc outbound link. An unknown/already-converted token silently
    # falls through to the mfRef / normal-matching paths below (never
    # surfaced to the submitter).
    campaign_token = (payload.get('campaignToken') or '').strip() or None
    campaign_target = repository.get_campaign_target_by_token(campaign_token) if campaign_token else None
    if campaign_target and campaign_target.get('converted_at'):
        campaign_target = None
    campaign_row = repository.get_campaign(campaign_target['campaign_id']) if campaign_target else None
    if campaign_target and not campaign_row:
        campaign_target = None  # campaign itself was deleted — nothing sane to resolve to

    # ---- Outbound-to-form merge-back (Funnel Phase 3) ----
    # A submission carrying ?mf_ref=<token> came from a link an operator
    # generated for a SPECIFIC known lead — identity is already resolved,
    # so this merges deterministically into that lead rather than running
    # find_candidates() against the whole pool. An unknown/already-used
    # token, or one whose target lead no longer resolves, silently falls
    # through to the normal fuzzy-matching path below (never surfaced to
    # the submitter).
    outbound_token = (payload.get('mfRef') or '').strip() or None
    outbound_link = repository.get_outbound_link(outbound_token) if (outbound_token and not campaign_target) else None
    outbound_target = None
    if outbound_link and not outbound_link.get('converted_at'):
        outbound_target = repository.get_active_lead_by_id(outbound_link['lead_id'])

    # ---- Matching / merge (signal-architecture Phase B) ----
    # Rejected/spam submissions are persisted for audit but NEVER matched,
    # merged, or used to strengthen an existing lead — and (Campaign
    # Phase 2) never convert a campaign target or an outbound link either,
    # since this branch is checked BEFORE either token is ever resolved
    # into an action.
    merged_into = None
    review_count = 0
    outbound_conversion = False
    campaign_conversion = False
    if spam_status == 'rejected':
        repository.insert_lead(lead)
        repository.persist_lead_signals(lead)
        repository.record_lead_attribution_touch(lead, touch_type='first')
    elif campaign_target:
        # The campaign's own page_variant/offer_type/UTM fields are the
        # authoritative identity for this conversion — stamp the incoming
        # lead with them rather than trusting whatever the submitted
        # payload happened to carry (defensive against a stale/edited URL).
        lead.page_variant = campaign_row['page_variant']
        lead.offer_type = campaign_row['offer_type']
        lead.campaign_id = campaign_row['id']

        existing_target_lead = (
            repository.get_active_lead_by_id(campaign_target['lead_id']) if campaign_target.get('lead_id') else None
        )
        if existing_target_lead:
            # This target was already linked to a known lead (e.g. an
            # operator attached one manually, or a prior partial
            # conversion) — merge deterministically, same as an
            # outbound-link conversion.
            mf_matching.merge_incoming_on_intake(existing_target_lead, lead, touch_type='conversion')
            lead = repository.get_lead_by_id(existing_target_lead.id) or existing_target_lead
            merged_into = lead.id
            snapshot_lead(lead, 'merged')
        else:
            # Cold prospect: route through the SAME matching engine every
            # other submission uses, so an exact-identity match still
            # auto-merges instead of creating a duplicate lead.
            result = mf_matching.classify(lead, repository.get_real_leads())
            auto = result.get('auto')
            if auto:
                mf_matching.merge_incoming_on_intake(auto.lead, lead, touch_type='conversion')
                lead = repository.get_lead_by_id(auto.lead.id) or auto.lead
                merged_into = lead.id
                snapshot_lead(lead, 'merged')
            else:
                repository.insert_lead(lead)
                repository.persist_lead_signals(lead)
                repository.record_lead_attribution_touch(lead, touch_type='conversion')
                snapshot_lead(lead, 'created')
        campaign_conversion = True
        repository.mark_campaign_target_converted(campaign_target['id'], lead.id)
        mf_notifications.notify_campaign_conversion(lead.id, lead.company.name, campaign_row['name'], campaign_row['page_variant'])
        if lead.score and lead.score.category == 'call_today':
            mf_notifications.notify_new_call_today_lead(lead.id, lead.company.name)
    elif outbound_target:
        mf_matching.merge_incoming_on_intake(outbound_target, lead, touch_type='conversion')
        merged_into = outbound_target.id
        outbound_conversion = True
        lead = repository.get_lead_by_id(outbound_target.id) or outbound_target
        repository.mark_outbound_link_converted(outbound_token, lead.id)
        snapshot_lead(lead, 'merged')
        if raw_source == 'benchmark_form':
            mf_notifications.notify_outbound_conversion(lead.id, lead.company.name, lead.page_variant, outbound_token)
        if lead.score and lead.score.category == 'call_today':
            mf_notifications.notify_new_call_today_lead(lead.id, lead.company.name)
    else:
        result = mf_matching.classify(lead, repository.get_real_leads())
        auto = result.get('auto')
        if auto:
            # High-confidence match -> fold into the survivor, re-score.
            # No new card is created.
            mf_matching.merge_incoming_on_intake(auto.lead, lead)
            merged_into = auto.lead.id
            lead = repository.get_lead_by_id(auto.lead.id) or auto.lead
            snapshot_lead(lead, 'merged')
            mf_notifications.notify_high_confidence_merge(lead.id, lead.company.name, incoming_signal_id)
        else:
            repository.insert_lead(lead)
            repository.persist_lead_signals(lead)
            repository.record_lead_attribution_touch(lead, touch_type='first')
            primary_sig_id = lead.signals[0].id if lead.signals else None
            for cand in result.get('review', []):
                candidate_row = repository.insert_match_candidate(
                    incoming_signal_id=primary_sig_id, candidate_lead_id=cand.lead.id,
                    match_tier='review', match_reasons=cand.reasons, score=cand.score,
                    incoming_lead_id=lead.id,
                )
                mf_notifications.notify_fuzzy_match_review(candidate_row['id'], lead.company.name, cand.lead.company.name, cand.lead.id)
                review_count += 1
            snapshot_lead(lead, 'created')

        if raw_source == 'benchmark_form':
            variant = FORM_VARIANTS.get(lead.page_variant) if lead.page_variant else None
            priority = variant.notification_priority if variant else 'same_day'
            mf_notifications.notify_new_form_submission(
                lead.id, lead.company.name, lead.page_variant, lead.offer_type,
                priority=priority, signal_id=incoming_signal_id,
            )
        if lead.score and lead.score.category == 'call_today':
            mf_notifications.notify_new_call_today_lead(lead.id, lead.company.name)

    if spam_status == 'rejected':
        event_type = 'rejected_honeypot' if 'HONEYPOT_FILLED' in spam_reason_codes else 'rejected_garbage'
        mf_notifications.check_spam_spike()
    elif campaign_conversion:
        event_type = 'accepted_converted_from_campaign'
    elif outbound_conversion:
        event_type = 'accepted_converted_from_outbound'
    elif merged_into:
        event_type = 'accepted_merged'
    elif spam_status == 'suspicious':
        event_type = 'accepted_suspicious'
    else:
        event_type = 'accepted_clean'
    repository.record_intake_event(event_type, ip_hash, email, {
        'spam_reason_codes': spam_reason_codes, 'merged_into': merged_into, 'review_candidates': review_count,
        'outbound_conversion': outbound_conversion, 'campaign_conversion': campaign_conversion,
    })

    # Always a normal-looking success — never reveal spam detection to the
    # submitter. Serialized through the same redaction path as every other
    # endpoint (an anonymous public submitter is non-admin -> spam fields
    # stripped), with live process-stage + stage-timing attached.
    lead_dict = _serialize_lead(lead, _requester_is_super_admin())
    lead_dict['merged_into_existing'] = bool(merged_into)
    return jsonify({'success': True, 'lead': lead_dict}), 201


@multifamily_bp.route('/leads/call-today', methods=['GET'])
def get_call_today_leads():
    """Who to call today: leads scored 'call_today' (real-first, demo fallback)."""
    return _view(call_today_leads)


@multifamily_bp.route('/leads/completion', methods=['GET'])
def get_completion_leads():
    """Completion / lease-up: the builder's-risk -> operating-coverage transition window."""
    return _view(completion_leads)


@multifamily_bp.route('/leads/nurture', methods=['GET'])
def get_nurture_leads():
    """Nurture: long-cycle leads (nurture/watchlist category)."""
    return _view(nurture_leads)


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


@multifamily_bp.route('/leads/construction-timing', methods=['GET'])
def get_construction_timing():
    """Phase 5: construction-trigger leads ranked by timing urgency
    (overdue first, then due_soon, then on_track/completed/unknown) —
    a focused ops view for "is this stalled?" rather than the raw,
    score-ranked /leads/construction-triggers list. Pure analytics on
    top of the same leads; does not affect scoring."""
    _URGENCY_RANK = {'overdue': 3, 'due_soon': 2, 'on_track': 1, 'unknown': 0, 'completed': -1}
    real_leads, mock_leads, _ = _real_and_mock()
    leads = with_demo_fallback(real_leads, mock_leads, construction_trigger_leads)

    def _urgency(lead):
        timing = compute_stage_timing(lead)
        return _URGENCY_RANK.get(timing['timing_status'], 0) if timing else 0

    leads = sorted(leads, key=_urgency, reverse=True)
    return jsonify({
        'leads': _serialize_leads(leads),
        'count': len(leads),
        'is_demo_data': bool(leads) and all(l.is_demo for l in leads),
    })


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


def _stage_timing_summary(leads):
    """Phase 5: counts of construction-trigger leads by timing status,
    for the overview/daily-brief widgets. Pure analytics — read-only."""
    counts = {'on_track': 0, 'due_soon': 0, 'overdue': 0, 'completed': 0, 'unknown': 0}
    for lead in leads:
        timing = compute_stage_timing(lead)
        if timing:
            counts[timing['timing_status']] = counts.get(timing['timing_status'], 0) + 1
    return counts


@multifamily_bp.route('/daily-brief', methods=['GET'])
def get_daily_brief():
    real_leads, mock_leads, _ = _real_and_mock()
    leads = real_leads if real_leads else mock_leads
    leads = sort_leads_by_priority(leads)
    brief = build_daily_brief(leads)
    brief['is_demo_data'] = bool(leads) and all(l.is_demo for l in leads)

    # Phase 5: surface stalled/due-soon construction leads in the brief
    # without touching multifamily_daily_brief_builder.py's own contract.
    timed = [(l, compute_stage_timing(l)) for l in leads]
    stalled = [(l, t) for l, t in timed if t and t['timing_status'] in ('overdue', 'due_soon')]
    stalled.sort(key=lambda pair: pair[1]['timing_status'] == 'overdue', reverse=True)
    brief['stalled_construction_leads'] = [
        {'lead_id': l.id, 'company': l.company.name, 'property': l.property.name,
         'city': l.city, 'state': l.state, **t}
        for l, t in stalled
    ]
    return jsonify(brief)


def _mission_activities_outcomes(lead):
    """Real leads carry persisted activity/outcome history; demo leads
    don't (they're regenerated on every pipeline run), so the Mission's
    sales-intelligence read just treats them as having none yet."""
    if lead.is_demo:
        return [], []
    return repository.get_activities_for_lead(lead.id), repository.get_outcomes_for_lead(lead.id)


def _mission_item(lead, stage_result=None, activities=None, outcomes=None, pkg=None):
    """Compact, action-oriented summary of a lead for the Overview's
    'Today's Mission' cards. Additive `sales_intelligence` key reflects the
    same NEPQ engine reasoning surfaced in the Outreach Workbench/drawer."""
    sr = stage_result or detect_process_stage(lead)
    contact = lead.contacts[0] if lead.contacts else None
    return {
        'lead_id': lead.id,
        'company': lead.company.name,
        'contact': (contact.full_name if contact else None),
        'contact_email': (contact.email if contact else None),
        'state': lead.state,
        'city': lead.city,
        'score': lead.score.total if lead.score else None,
        'category': lead.score.category if lead.score else None,
        'source': lead.primary_source,
        'process_stage': sr.process_stage,
        'urgency_label': sr.urgency_label,
        'reason': sr.timing_reason,
        'next_best_action': lead.next_best_action,
        'is_demo': lead.is_demo,
        'sales_intelligence': _sales_intelligence_summary(lead, sr, activities or [], outcomes or [], pkg=pkg),
    }


# Process stages that count toward each Overview tile.
_ACQ_FIN_STAGES = {'acquisition_due_diligence', 'refinance_or_financing', 'construction_loan_closing'}
_CONSTRUCTION_STAGES = {'entitlement_or_permit', 'construction_loan_closing', 'construction_start'}


@multifamily_bp.route('/overview', methods=['GET'])
def get_overview():
    """Home-base summary for the Multifamily Overview: count tiles,
    'Today's Multifamily Mission', top source/campaign, and best first
    action. Counts/mission run over the active lead set (real-first, demo
    fallback). Additive to the prior payload — existing keys unchanged."""
    real_leads, mock_leads, source_runs = _real_and_mock()
    leads = sort_leads_by_priority(real_leads if real_leads else mock_leads)
    is_demo_data = bool(leads) and all(l.is_demo for l in leads)
    is_admin = _requester_is_super_admin()

    scored = [l for l in leads if l.score]
    by_category = {}
    for l in scored:
        by_category[l.score.category] = by_category.get(l.score.category, 0) + 1
    by_state = {}
    for l in leads:
        by_state[l.state or 'unknown'] = by_state.get(l.state or 'unknown', 0) + 1
    by_source = {}
    for l in leads:
        by_source[l.primary_source] = by_source.get(l.primary_source, 0) + 1

    # Process-stage tally (one detect per lead, reused below).
    staged = [(l, detect_process_stage(l)) for l in leads]
    stage_counts = {}
    for _, sr in staged:
        stage_counts[sr.process_stage] = stage_counts.get(sr.process_stage, 0) + 1

    counts = {
        'call_today': by_category.get('call_today', 0),
        'hot': by_category.get('hot', 0),
        'warm': by_category.get('warm', 0),
        'new_inbound': len(inbound_leads(leads)),
        'renewal_window': stage_counts.get('renewal_window', 0),
        'acquisition_financing': sum(stage_counts.get(s, 0) for s in _ACQ_FIN_STAGES),
        'construction_buildersrisk': sum(stage_counts.get(s, 0) for s in _CONSTRUCTION_STAGES),
        'completion_leaseup': stage_counts.get('completion_or_lease_up', 0),
        'nurture': by_category.get('nurture', 0) + by_category.get('watchlist', 0),
    }

    # Top source / campaign (real-lead attribution where available).
    perf = repository.get_source_performance()
    top_source = max(perf['leads_by_source'].items(), key=lambda kv: kv[1])[0] if perf['leads_by_source'] else (
        max(by_source.items(), key=lambda kv: kv[1])[0] if by_source else None)
    campaigns = {k: v for k, v in perf['leads_by_campaign'].items() if k not in ('none', 'unknown')}
    top_campaign = max(campaigns.items(), key=lambda kv: kv[1])[0] if campaigns else None

    # --- Today's Multifamily Mission ---
    actionable = [(l, sr) for l, sr in staged if l.score and not l.score.disqualified]
    best_first_call = next(((l, sr) for l, sr in actionable if l.contacts), None)
    best_email = next(((l, sr) for l, sr in actionable if any(c.email for c in l.contacts)), None)
    best_followup = next(
        ((l, sr) for l, sr in actionable if sr.outreach_window in ('this_week', 'next_30_days')
         and (not best_first_call or l.id != best_first_call[0].id)),
        None,
    )
    best_nurture = next(((l, sr) for l, sr in staged if l.score and l.score.category in ('nurture', 'watchlist')), None)
    needs_info = next(((l, sr) for l, sr in staged if l.score and l.score.disqualifier_codes), None)

    best_email_item = None
    if best_email:
        lead, sr = best_email
        activities, outcomes = _mission_activities_outcomes(lead)
        try:
            pkg = build_sales_intelligence(lead, stage_result=sr, activities=activities, outcomes=outcomes)
            email_draft = {'subject': pkg.messages.first_email_subject, 'body': pkg.messages.first_email_body}
        except Exception:
            # Defensive fallback only — the sales-intelligence engine is the
            # primary path; the legacy bundle builder covers the exceptional
            # case where it errors, so the Mission card never comes up empty.
            pkg = None
            email_draft = build_outreach_bundle(lead, sr)['email_draft']
        best_email_item = {**_mission_item(lead, sr, activities, outcomes, pkg=pkg), 'email_draft': email_draft}

    def _mission_item_for(pair):
        if not pair:
            return None
        lead, sr = pair
        activities, outcomes = _mission_activities_outcomes(lead)
        return _mission_item(lead, sr, activities, outcomes)

    mission = {
        'best_first_call': _mission_item_for(best_first_call),
        'best_email_draft': best_email_item,
        'best_followup': _mission_item_for(best_followup),
        'best_nurture_action': _mission_item_for(best_nurture),
        'lead_needing_info': _mission_item_for(needs_info),
    }
    best_first_action = mission['best_first_call'] or mission['best_email_draft'] or mission['best_followup']

    # --- Funnel widgets (Funnel Phase 7) ---
    # `leads` is already priority-sorted (category > score > urgency), so
    # the first real benchmark-form submission in it is the single best
    # inbound hand-raiser to work right now.
    stage_by_id = {l.id: sr for l, sr in staged}
    handraiser = best_inbound_handraiser(leads)
    best_handraiser = None
    if handraiser:
        activities, outcomes = _mission_activities_outcomes(handraiser)
        best_handraiser = {
            **_mission_item(handraiser, stage_by_id.get(handraiser.id), activities, outcomes),
            'page_variant': handraiser.page_variant,
            'offer_type': handraiser.offer_type,
        }
    campaign_perf = repository.get_campaign_performance()
    funnel = {**build_funnel_widgets(perf, campaign_perf), 'best_inbound_handraiser': best_handraiser}

    payload = {
        'total_leads': len(leads),
        'real_lead_count': len(real_leads),
        'is_demo_data': is_demo_data,
        'by_category': by_category,
        'by_state': by_state,
        'by_source': by_source,
        'source_runs': [dataclasses.asdict(r) for r in source_runs],
        'construction_stage_timing': _stage_timing_summary(leads),
        # New command-center home payload (Part 3).
        'counts': counts,
        'process_stage_counts': stage_counts,
        'top_source': top_source,
        'top_campaign': top_campaign,
        'best_first_action': best_first_action,
        'mission': mission,
        'funnel': funnel,
    }
    # Suspicious/spam count — admin only (Part 3).
    if is_admin:
        payload['counts']['suspicious'] = repository.get_intake_stats().get('counts_by_spam_status', {}).get('suspicious', 0)
    return jsonify(payload)


def _find_lead(lead_id):
    """Look up a single lead by id across real + demo (real wins). Returns
    (lead, None) or (None, response_tuple) on 404."""
    real_leads, mock_leads, _ = _real_and_mock()
    for lead in real_leads + mock_leads:
        if lead.id == lead_id:
            return lead, None
    return None, (jsonify({'error': 'Lead not found'}), 404)


@multifamily_bp.route('/leads/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    """Single lead for the detail drawer — real + demo, redacted, with
    live process-stage/stage-timing attached."""
    lead, err = _find_lead(lead_id)
    if err:
        return err
    current_outcome = None if lead.is_demo else repository.get_current_outcome(lead_id)
    return jsonify({
        'lead': _serialize_lead(lead, _requester_is_super_admin(), with_history=True, current_outcome=current_outcome),
        'is_demo': lead.is_demo,
    })


@multifamily_bp.route('/leads/<lead_id>/outreach', methods=['GET'])
def get_lead_outreach(lead_id):
    """The full Outreach Workbench message bundle for one lead (call
    opener, email, LinkedIn note, follow-ups, soft bump, discovery
    questions). Drafts only — nothing is ever sent."""
    lead, err = _find_lead(lead_id)
    if err:
        return err
    return jsonify({'lead_id': lead_id, 'company': lead.company.name, 'outreach': build_outreach_bundle(lead)})


@multifamily_bp.route('/leads/<lead_id>/sales-intelligence', methods=['GET'])
def get_lead_sales_intelligence(lead_id):
    """Full NEPQ-based Sales Intelligence package for one lead: lead
    context, conversation strategy, question path, message drafts, the
    objection playbook, and the reasoning explainer. Used by the Outreach
    Workbench and (a compact summary of it) the lead drawer. Real leads
    only get activity/outcome history factored in; demo leads still get a
    full package computed from their in-memory signals. `?variant=N`
    rotates among equivalent phrasings for "Regenerate approach" — never
    sends anything, drafts only. Never persists on demo leads."""
    lead, err = _find_lead(lead_id)
    if err:
        return err
    try:
        variant = int(request.args.get('variant', 0))
    except (TypeError, ValueError):
        variant = 0
    activities = [] if lead.is_demo else repository.get_activities_for_lead(lead_id)
    outcomes = [] if lead.is_demo else repository.get_outcomes_for_lead(lead_id)
    pkg = build_sales_intelligence(lead, activities=activities, outcomes=outcomes, variant=variant)
    guardrail_results = check_message_package(pkg.messages)
    tone_guardrail = {
        'status': worst_status(guardrail_results),
        'warnings': [
            {'field': field, 'status': r.status, 'reasons': r.reasons}
            for field, r in guardrail_results.items() if r.status != 'pass'
        ],
    }
    return jsonify({
        'lead_id': lead_id,
        'company': lead.company.name,
        'variant': variant,
        'context': dataclasses.asdict(pkg.context),
        'strategy': dataclasses.asdict(pkg.strategy),
        'question_path': dataclasses.asdict(pkg.question_path),
        'messages': dataclasses.asdict(pkg.messages),
        'objection_playbook': [dataclasses.asdict(o) for o in pkg.objection_playbook],
        'follow_up_strategy': dataclasses.asdict(pkg.follow_up_strategy),
        'reasoning': dataclasses.asdict(pkg.reasoning),
        'tone_guardrail': tone_guardrail,
    })


def _admin_only(fn):
    """Run `fn` only for an authenticated super-admin (same lazy-import
    pattern as /admin/intake-stats)."""
    import app as _app

    @_app.require_auth
    @_app.require_super_admin
    def _authorized():
        return fn()

    return _authorized()


@multifamily_bp.route('/match-candidates', methods=['GET'])
def get_match_candidates():
    """Data-quality review queue: possible-duplicate leads needing a human
    to confirm or dismiss a merge. Super-admin only."""
    def _fn():
        return jsonify({'candidates': repository.get_match_candidates(status=request.args.get('status', 'pending'))})
    return _admin_only(_fn)


@multifamily_bp.route('/admin/source-runs', methods=['GET'])
def get_source_runs():
    """Source-run history (populated by automated/manual collectors,
    including the SERP admin runner below). Super-admin only. Optional
    `?source=serp` filters to one collector's runs."""
    def _fn():
        return jsonify({'source_runs': repository.get_source_runs(
            limit=int(request.args.get('limit', 50)), source=request.args.get('source'),
        )})
    return _admin_only(_fn)


@multifamily_bp.route('/admin/serp-config', methods=['GET'])
def get_serp_config():
    """Static config for the SERP admin runner's dropdowns — single
    source of truth is multifamily/serp/query_templates.py. Super-admin
    only (matches the runner itself)."""
    def _fn():
        return jsonify({
            'categories': SERP_CATEGORIES,
            'launch_states': SERP_LAUNCH_STATES,
            'future_states': SERP_FUTURE_STATES,
        })
    return _admin_only(_fn)


@multifamily_bp.route('/admin/serp-run', methods=['POST'])
def run_serp_search():
    """Manually trigger one Multifamily SERP category/state search
    (Multifamily SERP Phase C). This is the only control surface for SERP
    in this phase — there is no automated scheduling yet. Runs every
    query template for the given category/state[/city], filters results,
    and (unless dryRun) ingests accepted ones as contactless trigger
    signals through the same real pipeline as any other collector
    (spam gate -> matching -> merge/create -> source-run logging ->
    snapshot). Super-admin only. Never sends anything, never scrapes
    LinkedIn, never calls any API beyond the existing SerpAPI client."""
    def _fn():
        payload = request.get_json(silent=True) or {}
        try:
            config = SerpQueryConfig(
                category=(payload.get('category') or ''),
                state=(payload.get('state') or ''),
                city=(payload.get('city') or None),
                lookback_days=int(payload.get('lookbackDays', 30)),
                limit=int(payload.get('limit', 10)),
                confidence_threshold=float(payload.get('confidenceThreshold', 0.35)),
            )
        except (ValueError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        dry_run = bool(payload.get('dryRun', False))
        result = run_serp_collection(config, dry_run=dry_run)
        return jsonify({'success': result.get('error') is None, **result})
    return _admin_only(_fn)


@multifamily_bp.route('/match-candidates/<candidate_id>/merge', methods=['POST'])
def merge_match_candidate(candidate_id):
    """Confirm a review candidate: merge the incoming lead into the
    existing (survivor) lead and tombstone the incoming. Super-admin only."""
    from flask import g

    def _fn():
        cand = repository.get_match_candidate(candidate_id)
        if not cand:
            return jsonify({'success': False, 'error': 'Candidate not found'}), 404
        if cand.get('status') != 'pending':
            return jsonify({'success': False, 'error': 'Candidate already resolved'}), 409
        survivor_id = cand.get('candidate_lead_id')   # the existing/older lead survives
        loser_id = cand.get('incoming_lead_id')        # the newer incoming lead is folded in
        if not survivor_id or not loser_id:
            return jsonify({'success': False, 'error': 'Candidate is missing lead references'}), 422
        survivor = mf_matching.merge_existing(survivor_id, loser_id)
        if not survivor:
            return jsonify({'success': False, 'error': 'Merge failed (lead missing)'}), 422
        snapshot_lead(survivor, 'merged')
        resolver = (g.user or {}).get('email') if getattr(g, 'user', None) else None
        repository.resolve_match_candidate(candidate_id, 'merged', resolved_by=resolver)
        return jsonify({'success': True, 'survivor_id': survivor_id, 'merged_lead_id': loser_id})

    return _admin_only(_fn)


@multifamily_bp.route('/match-candidates/<candidate_id>/dismiss', methods=['POST'])
def dismiss_match_candidate(candidate_id):
    """Dismiss a review candidate (leave both leads separate). Super-admin only."""
    from flask import g

    def _fn():
        cand = repository.get_match_candidate(candidate_id)
        if not cand:
            return jsonify({'success': False, 'error': 'Candidate not found'}), 404
        resolver = (g.user or {}).get('email') if getattr(g, 'user', None) else None
        repository.resolve_match_candidate(candidate_id, 'dismissed', resolved_by=resolver)
        return jsonify({'success': True})

    return _admin_only(_fn)


@multifamily_bp.route('/source-performance', methods=['GET'])
def get_source_performance():
    """Part 8: source/UTM/campaign/offer performance over real leads."""
    data = repository.get_source_performance()
    data['is_demo_data'] = (data.get('total_real_leads', 0) == 0)
    # Campaign Phase 5: Pilot Campaign performance — additive, entirely
    # separate rollup from the lead-source view above (campaigns/targets,
    # not leads/signals).
    data['campaign_performance'] = repository.get_campaign_performance()
    return jsonify(data)


@multifamily_bp.route('/source-roi', methods=['GET'])
def get_source_roi():
    """Outcome-aware ROI report (outcome/snapshot/notification phase):
    leads/signals/funnel milestones/revenue/quality metrics grouped by
    source, source_page, offer_type, utm_source, utm_campaign,
    first_touch_source, conversion_source, and latest_signal_source.
    Login required — includes revenue/premium figures, more sensitive
    than the public lead-count view at /source-performance."""
    import app as _app

    @_app.require_auth
    def _authorized():
        return jsonify({'roi': repository.get_source_roi()})

    return _authorized()


@multifamily_bp.route('/admin/calibration', methods=['GET'])
def get_admin_calibration():
    """Descriptive-only (no ML) calibration dataset: score-band ->
    meeting/win rate, timing-stage -> reply rate, process-stage -> win
    rate, revenue by source, and disqualifier-code -> outcome mix. Super-
    admin only (raw per-lead financials feed into this)."""
    def _fn():
        return jsonify(repository.get_calibration_dataset())
    return _admin_only(_fn)


@multifamily_bp.route('/leads/<lead_id>/activity', methods=['POST'])
def log_activity(lead_id):
    """Log a manual activity / follow-up on a lead (Part 7). Login
    required (internal operator action). Never sends anything."""
    import app as _app
    from flask import g

    @_app.require_auth
    def _authorized():
        payload = request.get_json(silent=True) or {}
        activity_type = (payload.get('activity_type') or '').strip()
        if activity_type not in ACTIVITY_TYPES:
            return jsonify({'success': False, 'errors': [f'activity_type must be one of {ACTIVITY_TYPES}']}), 400
        user_email = (g.user or {}).get('email') if getattr(g, 'user', None) else None
        activity = repository.insert_activity(
            lead_id, activity_type,
            note=(payload.get('note') or None),
            next_follow_up_date=(payload.get('next_follow_up_date') or None),
            user_email=user_email,
        )
        if activity_type in ('replied', 'meeting_booked'):
            lead_row = repository.get_lead_row(lead_id)
            company_name = (lead_row or {}).get('company_name') or 'A lead'
            if activity_type == 'replied':
                mf_notifications.notify_lead_replied(lead_id, company_name, activity['id'])
            else:
                mf_notifications.notify_meeting_booked(lead_id, company_name, activity['id'])
        next_suggested_follow_up = _follow_up_suggestion(repository.get_lead_by_id(lead_id))
        return jsonify({'success': True, 'activity': activity, 'next_suggested_follow_up': next_suggested_follow_up}), 201

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/activities', methods=['GET'])
def list_activities(lead_id):
    """All logged activities for one lead (newest first). Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        return jsonify({'lead_id': lead_id, 'activities': repository.get_activities_for_lead(lead_id)})

    return _authorized()


def _num_field(payload, key, errors):
    """Coerce an optional numeric payload field, collecting a validation
    error instead of raising (mirrors the activity endpoint's error-list
    pattern)."""
    v = payload.get(key)
    if v in (None, ''):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        errors.append(f'{key} must be a number')
        return None


@multifamily_bp.route('/leads/<lead_id>/outcome', methods=['POST'])
def record_lead_outcome(lead_id):
    """Record a real business-outcome event on a lead (outcome-tracking
    phase). Login required (internal operator action). Real leads only —
    demo lead ids regenerate every pipeline run, so an outcome recorded
    against one would silently vanish; reject with a clear error instead."""
    import app as _app
    from flask import g

    @_app.require_auth
    def _authorized():
        lead, err = _find_lead(lead_id)
        if err:
            return err
        if lead.is_demo:
            return jsonify({'success': False, 'errors': ['Cannot record an outcome on demo data.']}), 400
        payload = request.get_json(silent=True) or {}
        outcome_type = (payload.get('outcome_type') or '').strip()
        errors = []
        if outcome_type not in OUTCOME_TYPES:
            errors.append(f'outcome_type must be one of {OUTCOME_TYPES}')
        estimated_premium = _num_field(payload, 'estimated_premium', errors)
        estimated_revenue = _num_field(payload, 'estimated_revenue', errors)
        quoted_premium = _num_field(payload, 'quoted_premium', errors)
        bound_premium = _num_field(payload, 'bound_premium', errors)
        if errors:
            return jsonify({'success': False, 'errors': errors}), 400
        user_email = (g.user or {}).get('email') if getattr(g, 'user', None) else None
        outcome = repository.record_outcome(
            lead_id, outcome_type,
            outcome_date=(payload.get('outcome_date') or None),
            estimated_premium=estimated_premium, estimated_revenue=estimated_revenue,
            quoted_premium=quoted_premium, bound_premium=bound_premium,
            effective_date=(payload.get('effective_date') or None),
            renewal_date=(payload.get('renewal_date') or None),
            lost_reason=(payload.get('lost_reason') or None),
            won_reason=(payload.get('won_reason') or None),
            notes=(payload.get('notes') or None),
            created_by=user_email,
        )
        snapshot_lead(lead, 'outcome_changed')
        if outcome_type == 'meeting_booked':
            mf_notifications.notify_meeting_booked(lead_id, lead.company.name, outcome['id'])
        return jsonify({
            'success': True, 'outcome': outcome,
            'current_outcome': repository.get_current_outcome(lead_id),
        }), 201

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/outcomes', methods=['GET'])
def list_lead_outcomes(lead_id):
    """Full outcome history for one lead (newest first). Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        lead, err = _find_lead(lead_id)
        if err:
            return err
        if lead.is_demo:
            return jsonify({'lead_id': lead_id, 'outcomes': [], 'current_outcome': None})
        return jsonify({
            'lead_id': lead_id,
            'outcomes': repository.get_outcomes_for_lead(lead_id),
            'current_outcome': repository.get_current_outcome(lead_id),
        })

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/snapshots', methods=['GET'])
def list_lead_snapshots(lead_id):
    """Score/timing snapshot history for one lead, newest first (drawer's
    Score History tab). Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        lead, err = _find_lead(lead_id)
        if err:
            return err
        if lead.is_demo:
            return jsonify({'lead_id': lead_id, 'snapshots': []})
        return jsonify({'lead_id': lead_id, 'snapshots': repository.get_snapshots_for_lead(lead_id)})

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/snapshot', methods=['POST'])
def create_lead_snapshot(lead_id):
    """Force a fresh score/timing snapshot ('manual_rerun') — e.g. after an
    operator manually reviews/corrects a lead's data. Login required. Real
    leads only; never recomputes/changes scoring, just records the current
    (already-computed) state."""
    import app as _app

    @_app.require_auth
    def _authorized():
        lead, err = _find_lead(lead_id)
        if err:
            return err
        if lead.is_demo:
            return jsonify({'success': False, 'errors': ['Cannot snapshot demo data.']}), 400
        row = snapshot_lead(lead, 'manual_rerun')
        return jsonify({'success': True, 'snapshot': row}), 201

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/outbound-link', methods=['POST'])
def create_lead_outbound_link(lead_id):
    """Mint an outbound-to-form merge-back token for a specific lead
    (Funnel Phase 3, part of the outbound-to-form lane of the funnel
    strategy). An operator picks the offer page that best fits this
    lead's situation, generates a link, and sends it manually through
    whatever channel they'd already use (email, a call follow-up, a
    LinkedIn message) — this never sends anything itself. When the
    prospect submits that page carrying ?mf_ref=<token>, create_lead()
    merges the submission straight into this lead. Login required."""
    import app as _app
    from flask import g

    @_app.require_auth
    def _authorized():
        lead, err = _find_lead(lead_id)
        if err:
            return err
        if lead.is_demo:
            return jsonify({'success': False, 'errors': ['Cannot generate an outbound link for demo data.']}), 400

        payload = request.get_json(silent=True) or {}
        page_variant = (payload.get('pageVariant') or payload.get('page_variant') or '').strip() or None
        variant = FORM_VARIANTS.get(page_variant) if page_variant else None
        if page_variant and not variant:
            return jsonify({'success': False, 'errors': [f'Unknown page_variant. Must be one of {FORM_VARIANT_SLUGS}']}), 400

        campaign_id = (payload.get('campaignId') or payload.get('campaign_id') or '').strip() or None
        source = (payload.get('source') or '').strip() or 'outbound_email'
        user_email = (g.user or {}).get('email') if getattr(g, 'user', None) else None

        row = repository.create_outbound_link(
            lead_id=lead.id,
            offer_type=(variant.offer_type if variant else None),
            page_variant=page_variant,
            campaign_id=campaign_id,
            source=source,
            created_by=user_email,
        )
        url = f'/mf-review/{page_variant}?mf_ref={row["token"]}' if page_variant else None
        return jsonify({'success': True, 'link': row, 'url': url}), 201

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/outbound-links', methods=['GET'])
def list_lead_outbound_links(lead_id):
    """Every outbound link ever generated for this lead (newest first) —
    lets the Outreach Workbench show "link already sent" instead of
    minting a fresh token on every drawer open. Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        lead, err = _find_lead(lead_id)
        if err:
            return err
        if lead.is_demo:
            return jsonify({'lead_id': lead_id, 'links': []})
        return jsonify({'lead_id': lead_id, 'links': repository.get_outbound_links_for_lead(lead_id)})

    return _authorized()


# ---- Pilot Campaign Control Center -----------------------------------------
# A campaign is a controlled outbound/manual prospecting effort tied to
# ONE offer page. Every endpoint here is internal/operator-facing
# (require_auth) — the only PUBLIC surface a campaign ever touches is
# the existing /mf-review/<page_variant> page + POST /leads (a target's
# tracked link is just that URL with a ?t=<token> param).

def _campaign_tracked_url(campaign_row, token):
    from multifamily.campaigns.tracked_link import build_tracked_url
    return build_tracked_url(campaign_row, token)


@multifamily_bp.route('/campaigns', methods=['POST'])
def create_campaign():
    """Create a campaign bound to one offer page. offer_type is always
    derived from page_variant (multifamily/forms/form_variants.py is
    the single source of truth) — never accepted independently, so the
    two can never drift apart. Login required."""
    import app as _app
    from flask import g

    @_app.require_auth
    def _authorized():
        payload = request.get_json(silent=True) or {}
        name = (payload.get('name') or '').strip()
        page_variant = (payload.get('pageVariant') or payload.get('page_variant') or '').strip()
        if not name:
            return jsonify({'success': False, 'errors': ['name is required.']}), 400
        variant = FORM_VARIANTS.get(page_variant)
        if not variant:
            return jsonify({'success': False, 'errors': [f'page_variant must be one of {FORM_VARIANT_SLUGS}']}), 400
        status = (payload.get('status') or 'draft').strip()
        if status not in CAMPAIGN_STATUSES:
            return jsonify({'success': False, 'errors': [f'status must be one of {CAMPAIGN_STATUSES}']}), 400

        user_email = (g.user or {}).get('email') if getattr(g, 'user', None) else None
        row = repository.create_campaign(
            name=name, page_variant=page_variant, offer_type=variant.offer_type,
            description=(payload.get('description') or None),
            target_state=(payload.get('targetState') or payload.get('target_state') or None),
            target_city=(payload.get('targetCity') or payload.get('target_city') or None),
            target_segment=(payload.get('targetSegment') or payload.get('target_segment') or None),
            campaign_source=(payload.get('campaignSource') or payload.get('campaign_source') or None),
            utm_source=(payload.get('utmSource') or payload.get('utm_source') or None),
            utm_medium=(payload.get('utmMedium') or payload.get('utm_medium') or None),
            utm_campaign=(payload.get('utmCampaign') or payload.get('utm_campaign') or None),
            status=status, created_by=user_email,
        )
        return jsonify({'success': True, 'campaign': row}), 201

    return _authorized()


@multifamily_bp.route('/campaigns', methods=['GET'])
def list_campaigns():
    """All campaigns (newest first), each annotated with target/
    contacted/converted/meeting counts for the campaign list view.
    Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        status = request.args.get('status')
        campaigns = repository.list_campaigns(status=status)
        for c in campaigns:
            targets = repository.list_campaign_targets(c['id'])
            c['target_count'] = len(targets)
            c['contacted_count'] = sum(1 for t in targets if t['status'] not in ('planned',))
            c['converted_count'] = sum(1 for t in targets if t['status'] == 'converted')
            c['meeting_count'] = sum(1 for t in targets if t['status'] == 'meeting_booked')
            last_activity = [t['last_activity_at'] for t in targets if t.get('last_activity_at')]
            c['last_activity_at'] = max(last_activity) if last_activity else None
        return jsonify({'campaigns': campaigns})

    return _authorized()


@multifamily_bp.route('/campaigns/<campaign_id>', methods=['GET'])
def get_campaign_detail(campaign_id):
    """Campaign summary + its full targets list, each target's tracked
    URL computed fresh (never stored). Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        campaign = repository.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        targets = repository.list_campaign_targets(campaign_id)
        for t in targets:
            t['tracked_url'] = _campaign_tracked_url(campaign, t['tracking_token'])
        return jsonify({'campaign': campaign, 'targets': targets})

    return _authorized()


@multifamily_bp.route('/campaigns/<campaign_id>/status', methods=['POST'])
def update_campaign_status(campaign_id):
    """Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        campaign = repository.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        payload = request.get_json(silent=True) or {}
        status = (payload.get('status') or '').strip()
        if status not in CAMPAIGN_STATUSES:
            return jsonify({'success': False, 'errors': [f'status must be one of {CAMPAIGN_STATUSES}']}), 400
        repository.update_campaign_status(campaign_id, status)
        return jsonify({'success': True, 'campaign': repository.get_campaign(campaign_id)})

    return _authorized()


@multifamily_bp.route('/campaigns/<campaign_id>/targets', methods=['POST'])
def create_campaign_target(campaign_id):
    """Add one prospect to a campaign and mint their tracked link. A
    target may have no known lead yet (a cold prospect Max is about to
    reach out to) — lead_id backfills once they convert. An optional
    `leadId` pre-links the target to an ALREADY-known lead (Campaign
    Phase 4: the Outreach Workbench generating a campaign-tracked link
    for a specific lead already sitting in the pipeline) — that target
    then merges deterministically into this exact lead on conversion,
    the same as an outbound-link one-off. Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        campaign = repository.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        payload = request.get_json(silent=True) or {}
        row = repository.create_campaign_target(
            campaign_id,
            company=(payload.get('company') or None),
            contact_name=(payload.get('contactName') or payload.get('contact_name') or None),
            email=(payload.get('email') or None),
            phone=(payload.get('phone') or None),
            linkedin_url=(payload.get('linkedinUrl') or payload.get('linkedin_url') or None),
            city=(payload.get('city') or None),
            state=(payload.get('state') or None),
            segment=(payload.get('segment') or None),
            notes=(payload.get('notes') or None),
        )
        lead_id = (payload.get('leadId') or payload.get('lead_id') or '').strip() or None
        if lead_id:
            repository.set_campaign_target_lead(row['id'], lead_id)
            row['lead_id'] = lead_id
        row['tracked_url'] = _campaign_tracked_url(campaign, row['tracking_token'])
        return jsonify({'success': True, 'target': row}), 201

    return _authorized()


@multifamily_bp.route('/campaigns/<campaign_id>/targets/import', methods=['POST'])
def import_campaign_targets(campaign_id):
    """Bulk-add prospects from a CSV (file upload or a raw `csv` string
    in the JSON body — either works, so this is scriptable without a
    browser too). Columns: company (required), contact_name, email,
    phone, linkedin_url, city, state, segment, notes, property_name,
    units, year_built, close_date. A row with a real email is run
    through the SAME create-or-match path every other real submission
    uses (multifamily.campaigns.csv_import), so it strengthens an
    existing lead instead of duplicating one; a row with close_date is
    ingested with acquisition context regardless of this campaign's own
    offer, so first_renewal_estimator can see it later. Login
    required."""
    import app as _app
    from multifamily.campaigns.csv_import import import_targets_from_csv

    @_app.require_auth
    def _authorized():
        campaign = repository.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        file_content = None
        uploaded = request.files.get('file')
        if uploaded:
            file_content = uploaded.read().decode('utf-8', errors='replace')
        else:
            payload = request.get_json(silent=True) or {}
            file_content = payload.get('csv')

        if not file_content:
            return jsonify({'success': False, 'errors': ['No CSV file or csv text provided.']}), 400

        summary = import_targets_from_csv(campaign, file_content)
        return jsonify({'success': True, **summary}), 201

    return _authorized()


@multifamily_bp.route('/campaigns/<campaign_id>/targets', methods=['GET'])
def list_campaign_targets_route(campaign_id):
    """Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        campaign = repository.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        targets = repository.list_campaign_targets(campaign_id)
        for t in targets:
            t['tracked_url'] = _campaign_tracked_url(campaign, t['tracking_token'])
        return jsonify({'targets': targets})

    return _authorized()


@multifamily_bp.route('/campaign-targets/<target_id>/status', methods=['POST'])
def update_campaign_target_status(target_id):
    """Mark a target contacted/replied/meeting_booked/not_fit/nurture
    (or back to planned), optionally with a note. If the target already
    has a lead attached, also logs a matching lead activity so the
    lead's activity history and reply/meeting notifications fire the
    same way they would from the drawer's own activity log. Login
    required."""
    import app as _app
    from flask import g

    @_app.require_auth
    def _authorized():
        target = repository.get_campaign_target(target_id)
        if not target:
            return jsonify({'error': 'Campaign target not found'}), 404
        payload = request.get_json(silent=True) or {}
        status = (payload.get('status') or '').strip()
        if status not in CAMPAIGN_TARGET_STATUSES:
            return jsonify({'success': False, 'errors': [f'status must be one of {CAMPAIGN_TARGET_STATUSES}']}), 400
        notes = payload.get('notes')
        repository.update_campaign_target_status(target_id, status, notes=notes)

        if target.get('lead_id') and status in ('contacted', 'replied', 'meeting_booked', 'not_fit', 'nurture'):
            activity_type = {
                'contacted': 'emailed', 'replied': 'replied', 'meeting_booked': 'meeting_booked',
                'not_fit': 'not_a_fit', 'nurture': 'moved_to_nurture',
            }[status]
            user_email = (g.user or {}).get('email') if getattr(g, 'user', None) else None
            activity = repository.insert_activity(target['lead_id'], activity_type, note=notes, user_email=user_email)
            lead_row = repository.get_lead_row(target['lead_id'])
            company_name = (lead_row or {}).get('company_name') or target.get('company') or 'A lead'
            if status == 'replied':
                mf_notifications.notify_lead_replied(target['lead_id'], company_name, activity['id'])
            elif status == 'meeting_booked':
                mf_notifications.notify_meeting_booked(target['lead_id'], company_name, activity['id'])

        return jsonify({'success': True, 'target': repository.get_campaign_target(target_id)})

    return _authorized()


@multifamily_bp.route('/campaign-targets/<target_id>/touch', methods=['POST'])
def mark_campaign_target_touch_route(target_id):
    """Mark one Section 7 sequence step (touch_1_sent/connected/
    touch_2_sent/called/breakup_sent) or the 'bounced' data-quality flag
    with a timestamp — a SEPARATE axis from `status` (see
    CAMPAIGN_TARGET_TOUCH_STEPS). Idempotent: re-marking the same step
    just updates its timestamp. Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        target = repository.get_campaign_target(target_id)
        if not target:
            return jsonify({'error': 'Campaign target not found'}), 404
        payload = request.get_json(silent=True) or {}
        step = (payload.get('step') or '').strip()
        if step not in CAMPAIGN_TARGET_TOUCH_STEPS:
            return jsonify({'success': False, 'errors': [f'step must be one of {CAMPAIGN_TARGET_TOUCH_STEPS}']}), 400
        repository.mark_campaign_target_touch(target_id, step)
        return jsonify({'success': True, 'target': repository.get_campaign_target(target_id)})

    return _authorized()


@multifamily_bp.route('/campaign-targets/<target_id>/renewal-month', methods=['POST'])
def set_campaign_target_renewal_month_route(target_id):
    """Capture a coarse ('YYYY-MM') renewal estimate an operator picked
    up in conversation — used by the timing engine only when no precise
    renewal_date_known signal exists on the linked lead. Login
    required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        target = repository.get_campaign_target(target_id)
        if not target:
            return jsonify({'error': 'Campaign target not found'}), 404
        payload = request.get_json(silent=True) or {}
        renewal_month = (payload.get('renewalMonth') or payload.get('renewal_month') or '').strip()
        if not re.match(r'^\d{4}-\d{2}$', renewal_month):
            return jsonify({'success': False, 'errors': ["renewal_month must be in 'YYYY-MM' format"]}), 400
        repository.set_campaign_target_renewal_month(target_id, renewal_month)
        return jsonify({'success': True, 'target': repository.get_campaign_target(target_id)})

    return _authorized()


@multifamily_bp.route('/notifications', methods=['GET'])
def get_notifications():
    """In-app notification feed (outcome/snapshot/notification phase).
    Login required — any authenticated user, not admin-only (these are
    operational alerts for whoever's working the dashboard). Runs the
    time-derived sweep (follow-up due/overdue, hot-lead-stale) first —
    there's no background scheduler, so this is the only clock those
    notifications have; sweep() is idempotent so repeated calls are safe."""
    import app as _app

    @_app.require_auth
    def _authorized():
        mf_notifications.sweep()
        unread_only = request.args.get('unread_only', '').lower() in ('1', 'true', 'yes')
        limit = int(request.args.get('limit', 50))
        return jsonify({
            'notifications': repository.get_notifications(unread_only=unread_only, limit=limit),
            'unread_count': repository.count_unread_notifications(),
        })

    return _authorized()


@multifamily_bp.route('/notifications/<notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    """Mark one notification read. Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        repository.mark_notification_read(notification_id)
        return jsonify({'success': True, 'unread_count': repository.count_unread_notifications()})

    return _authorized()


@multifamily_bp.route('/notifications/read-all', methods=['POST'])
def mark_all_notifications_read():
    """Mark every notification read. Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        repository.mark_all_notifications_read()
        return jsonify({'success': True, 'unread_count': repository.count_unread_notifications()})

    return _authorized()


@multifamily_bp.route('/activity/dashboard', methods=['GET'])
def activity_dashboard():
    """Follow-up & activity dashboard (Part 7): follow-ups due today,
    stale hot leads, replied/needs-response, meetings booked, needs-info.
    Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        today = date.today().isoformat()
        follow_ups_due = repository.get_followups_due(today)
        replied = repository.get_activities_by_type(['replied'])
        meetings_booked = repository.get_activities_by_type(['meeting_booked'])
        needs_info = repository.get_activities_by_type(['needs_info'])

        # Stale hot leads: real leads scored hot/call_today with no activity
        # in the last 3 days (needs live scoring, so computed here).
        real_leads = repository.get_real_leads()
        last_activity = repository.last_activity_at_by_lead()
        cutoff = (datetime.utcnow() - timedelta(days=3)).isoformat()
        stale_hot = []
        for l in real_leads:
            if not (l.score and l.score.category in ('call_today', 'hot')):
                continue
            last = last_activity.get(l.id)
            if last is None or last < cutoff:
                stale_hot.append({
                    'lead_id': l.id, 'company': l.company.name, 'state': l.state, 'city': l.city,
                    'category': l.score.category, 'score': l.score.total,
                    'last_activity_at': last,
                })

        return jsonify({
            'follow_ups_due': _attach_follow_up_suggestions(follow_ups_due),
            'stale_hot_leads': _attach_follow_up_suggestions(stale_hot),
            'replied_needs_response': replied,
            'meetings_booked': meetings_booked,
            'needs_info': needs_info,
        })

    return _authorized()


@multifamily_bp.route('/admin/intake-stats', methods=['GET'])
def get_intake_stats():
    """Admin/debug view: recent submissions (including rejected/suspicious
    — repository.get_intake_stats() does NOT filter by spam_status, unlike
    every other endpoint in this blueprint), spam-status counts, rate
    limit hits, and source/campaign breakdown.

    Server-side gated with the app's existing require_auth/require_super_admin
    decorators (app.py) — same check used by every other super-admin-only
    route (e.g. /api/admin/users/<id>/disable). Imported lazily inside the
    function body rather than at module level: app.py imports this blueprint
    (to register it) before require_auth/require_super_admin are defined
    further down in app.py, so a top-level `from app import ...` here would
    be a circular import. By the time any request actually reaches this
    handler, app.py has finished loading and `app` is already the fully
    initialized entry in sys.modules, so the deferred import just looks it
    up — it doesn't re-execute app.py or create a real cycle."""
    import app as _app

    @_app.require_auth
    @_app.require_super_admin
    def _authorized():
        return jsonify(repository.get_intake_stats())

    return _authorized()
