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
from datetime import date, datetime, timedelta

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
from multifamily.types import ACTIVITY_TYPES
from multifamily.stage_timing import compute_stage_timing
from multifamily.timing import detect_process_stage
from multifamily.timing.process_stage_types import OUTREACH_WINDOW_RANK
from multifamily.outreach.outreach_bundle_builder import build_outreach_bundle
from multifamily import matching as mf_matching

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


def _serialize_lead(lead, is_admin, stage_result=None, with_history=False):
    """Serialize one lead, attaching LIVE timing intelligence (never
    persisted — it's time-dependent) and redacting admin-only fields for
    non-super-admins. With `with_history` (the single-lead drawer), also
    attach the full attribution history (Phase C)."""
    d = dataclasses.asdict(lead)
    d['stage_timing'] = compute_stage_timing(lead)
    sr = stage_result or detect_process_stage(lead)
    d['process_stage'] = dataclasses.asdict(sr)
    d['is_suspicious'] = (getattr(lead, 'spam_status', 'clean') == 'suspicious')
    # Signal architecture (Phase C): cheap, always-on.
    d['signal_count'] = len(lead.signals or [])
    d['signal_timeline'] = _signal_timeline(lead)
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
        else:
            d['attribution'] = repository.get_attribution_summary(lead.id)
    if not is_admin:
        for f in _ADMIN_ONLY_LEAD_FIELDS:
            d.pop(f, None)
        d.pop('spam_status', None)  # internal triage state — admin only
    return d


def _serialize_leads(leads):
    is_admin = _requester_is_super_admin()
    return [_serialize_lead(l, is_admin) for l in leads]


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

    # ---- Matching / merge (signal-architecture Phase B) ----
    # Rejected/spam submissions are persisted for audit but NEVER matched,
    # merged, or used to strengthen an existing lead.
    merged_into = None
    review_count = 0
    if spam_status == 'rejected':
        repository.insert_lead(lead)
        repository.persist_lead_signals(lead)
        repository.record_lead_attribution_touch(lead, touch_type='first')
    else:
        result = mf_matching.classify(lead, repository.get_real_leads())
        auto = result.get('auto')
        if auto:
            # High-confidence match -> fold into the survivor, re-score.
            # No new card is created.
            mf_matching.merge_incoming_on_intake(auto.lead, lead)
            merged_into = auto.lead.id
            lead = repository.get_lead_by_id(auto.lead.id) or auto.lead
        else:
            repository.insert_lead(lead)
            repository.persist_lead_signals(lead)
            repository.record_lead_attribution_touch(lead, touch_type='first')
            primary_sig_id = lead.signals[0].id if lead.signals else None
            for cand in result.get('review', []):
                repository.insert_match_candidate(
                    incoming_signal_id=primary_sig_id, candidate_lead_id=cand.lead.id,
                    match_tier='review', match_reasons=cand.reasons, score=cand.score,
                    incoming_lead_id=lead.id,
                )
                review_count += 1

    if spam_status == 'rejected':
        event_type = 'rejected_honeypot' if 'HONEYPOT_FILLED' in spam_reason_codes else 'rejected_garbage'
    elif merged_into:
        event_type = 'accepted_merged'
    elif spam_status == 'suspicious':
        event_type = 'accepted_suspicious'
    else:
        event_type = 'accepted_clean'
    repository.record_intake_event(event_type, ip_hash, email, {
        'spam_reason_codes': spam_reason_codes, 'merged_into': merged_into, 'review_candidates': review_count,
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


def _mission_item(lead, stage_result=None):
    """Compact, action-oriented summary of a lead for the Overview's
    'Today's Mission' cards."""
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
        bundle = build_outreach_bundle(lead, sr)
        best_email_item = {**_mission_item(lead, sr), 'email_draft': bundle['email_draft']}

    mission = {
        'best_first_call': _mission_item(*best_first_call) if best_first_call else None,
        'best_email_draft': best_email_item,
        'best_followup': _mission_item(*best_followup) if best_followup else None,
        'best_nurture_action': _mission_item(*best_nurture) if best_nurture else None,
        'lead_needing_info': _mission_item(*needs_info) if needs_info else None,
    }
    best_first_action = mission['best_first_call'] or mission['best_email_draft'] or mission['best_followup']

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
    return jsonify({'lead': _serialize_lead(lead, _requester_is_super_admin(), with_history=True), 'is_demo': lead.is_demo})


@multifamily_bp.route('/leads/<lead_id>/outreach', methods=['GET'])
def get_lead_outreach(lead_id):
    """The full Outreach Workbench message bundle for one lead (call
    opener, email, LinkedIn note, follow-ups, soft bump, discovery
    questions). Drafts only — nothing is ever sent."""
    lead, err = _find_lead(lead_id)
    if err:
        return err
    return jsonify({'lead_id': lead_id, 'company': lead.company.name, 'outreach': build_outreach_bundle(lead)})


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
    return jsonify(data)


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
        return jsonify({'success': True, 'activity': activity}), 201

    return _authorized()


@multifamily_bp.route('/leads/<lead_id>/activities', methods=['GET'])
def list_activities(lead_id):
    """All logged activities for one lead (newest first). Login required."""
    import app as _app

    @_app.require_auth
    def _authorized():
        return jsonify({'lead_id': lead_id, 'activities': repository.get_activities_for_lead(lead_id)})

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
            'follow_ups_due': follow_ups_due,
            'stale_hot_leads': stale_hot,
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
