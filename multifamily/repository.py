"""
Persistence layer for REAL (non-demo) multifamily leads.

Mock/demo leads stay exactly where they were (multifamily/signal_collectors/),
generated fresh in-memory on every pipeline run. Real leads — captured
through POST /api/multifamily/leads — are durable: this module owns the
`multifamily_leads` table (lead records) and `multifamily_intake_events`
table (every submission attempt, including ones rejected before a lead
was ever built — e.g. rate-limited or oversized) and is the only place
that reads/writes either.

Uses the same DB engine abstraction as the rest of the app (db.py /
shared.database — SQLite locally, Postgres in production via DATABASE_URL)
so it's consistent with existing tables like `crm_leads` and `sales_leads`.
Schema is self-contained here (rather than added to app.py's giant
init_db()) so the multifamily module — including its test scripts — works
standalone without importing the full Flask app, and so this work never
has to touch app.py / the BTR module.
"""
import dataclasses
import json
from typing import Any, Dict, List, Optional

from shared.database import fetch_all, execute

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilyContact, MultifamilySignal, MultifamilyLeadScore,
)

_SCHEMA_READY = False

# Columns added after the initial v1 launch — applied via ALTER TABLE so
# existing rows/deployments aren't lost (CREATE TABLE IF NOT EXISTS only
# helps on a brand new table).
_ADDED_COLUMNS = [
    ('utm_source', 'TEXT'),
    ('utm_medium', 'TEXT'),
    ('utm_campaign', 'TEXT'),
    ('utm_term', 'TEXT'),
    ('utm_content', 'TEXT'),
    ('referrer', 'TEXT'),
    ('landing_page', 'TEXT'),
    ('offer_type', 'TEXT'),
    ('spam_status', "TEXT NOT NULL DEFAULT 'clean'"),
    ('spam_reason_codes', 'TEXT'),
    ('submitted_ip_hash', 'TEXT'),
    ('user_agent_summary', 'TEXT'),
    # Signal-architecture phase: dedupe/merge bookkeeping.
    ('merge_status', "TEXT NOT NULL DEFAULT 'active'"),  # active | merged
    ('merged_into_id', 'TEXT'),                          # survivor id when merged away
    ('signal_count', 'INTEGER'),                         # number of signals combined into this lead
    # Outcome-tracking phase: cache of the latest recorded outcome event —
    # kept in sync by record_outcome() so filtering/reporting never has to
    # replay the append-only multifamily_lead_outcomes history.
    ('current_outcome', 'TEXT'),
    ('current_outcome_at', 'TEXT'),
    # Funnel phase: which offer-page variant produced this lead
    # (multifamily/forms/form_variants.py slug) and which outreach
    # campaign drove the visit, if any.
    ('page_variant', 'TEXT'),
    ('campaign_id', 'TEXT'),
]


def _safe_add_column(table: str, column: str, ddl: str) -> None:
    """Add a column if it doesn't already exist. Tolerant of both engines
    and of being called repeatedly (IF NOT EXISTS isn't universally
    supported for ADD COLUMN across SQLite versions, so we just swallow
    the duplicate-column error)."""
    try:
        execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')
    except Exception:
        pass


def ensure_schema() -> None:
    """Idempotent CREATE TABLE + ALTER TABLE — safe to call on every
    import/request."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_leads (
            id TEXT PRIMARY KEY,
            is_demo INTEGER NOT NULL DEFAULT 0,
            company_name TEXT NOT NULL,
            property_name TEXT,
            contact_name TEXT,
            contact_email TEXT,
            contact_phone TEXT,
            contact_role TEXT,
            state TEXT,
            city TEXT,
            asset_type TEXT,
            unit_count INTEGER,
            lead_situation TEXT,
            primary_concern TEXT,
            notes TEXT,
            source TEXT NOT NULL,
            source_page TEXT,
            source_url TEXT,
            confidence REAL,
            score_total INTEGER,
            score_category TEXT,
            lead_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    for column, ddl in _ADDED_COLUMNS:
        _safe_add_column('multifamily_leads', column, ddl)

    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_intake_events (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            ip_hash TEXT,
            email TEXT,
            detail_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # --- Signal architecture (signal-architecture phase) ---------------
    # Queryable projection of every REAL signal. lead_json remains the
    # dataclass source of truth; these rows are kept consistent with it.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_signals (
            id TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            signal_type TEXT NOT NULL,
            source TEXT,
            source_url TEXT,
            confidence REAL,
            occurred_at TEXT,
            detail_json TEXT,
            is_demo INTEGER NOT NULL DEFAULT 0,
            spam_status TEXT NOT NULL DEFAULT 'clean',
            created_at TIMESTAMP
        )
    ''')
    # Append-only attribution touches -> first/latest/conversion + UTM path.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_source_attribution (
            id TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            touch_type TEXT NOT NULL,
            source TEXT,
            utm_source TEXT,
            utm_medium TEXT,
            utm_campaign TEXT,
            utm_term TEXT,
            utm_content TEXT,
            referrer TEXT,
            landing_page TEXT,
            offer_type TEXT,
            page_variant TEXT,
            campaign_id TEXT,
            occurred_at TEXT,
            created_at TIMESTAMP
        )
    ''')
    # Persisted source-run accounting for future automated collectors.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_source_runs (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            run_id TEXT,
            started_at TEXT,
            finished_at TEXT,
            status TEXT,
            records_found INTEGER DEFAULT 0,
            records_created INTEGER DEFAULT 0,
            records_updated INTEGER DEFAULT 0,
            records_merged INTEGER DEFAULT 0,
            records_rejected INTEGER DEFAULT 0,
            errors_json TEXT,
            warnings_json TEXT,
            category TEXT,
            state TEXT,
            query TEXT,
            created_at TIMESTAMP
        )
    ''')
    # SERP url-seen ledger — the authoritative idempotency check for the
    # SERP collector (multifamily/serp/serp_collector.py): a URL already
    # in here is skipped before it ever reaches matching, so a re-run of
    # the same search never re-creates a signal or spams a review
    # candidate for the same article (the matching engine's same_source_url
    # reason is only review-tier, not auto-merge, so without this ledger a
    # repeat run would queue a new review candidate every time).
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_serp_seen (
            url TEXT PRIMARY KEY,
            category TEXT,
            state TEXT,
            first_seen_at TIMESTAMP
        )
    ''')
    # Possible matches needing human review (auto-tier matches never queue here).
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_lead_match_candidates (
            id TEXT PRIMARY KEY,
            incoming_signal_id TEXT,
            candidate_lead_id TEXT NOT NULL,
            match_tier TEXT NOT NULL,
            match_reasons_json TEXT,
            score REAL,
            status TEXT NOT NULL DEFAULT 'pending',
            resolved_by TEXT,
            created_at TIMESTAMP,
            resolved_at TEXT
        )
    ''')

    # Manual follow-up/activity tracking (Part 7). Entirely separate from
    # the BTR crm_* tables — Multifamily and BTR data never mix.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_activities (
            id TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            note TEXT,
            next_follow_up_date TEXT,
            user_email TEXT,
            created_at TIMESTAMP
        )
    ''')

    # Outcome tracking (outcome/snapshot/notification phase). Append-only —
    # multifamily_leads.current_outcome/current_outcome_at cache the latest
    # event for fast filtering. Real leads only.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_lead_outcomes (
            id TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            outcome_type TEXT NOT NULL,
            outcome_date TEXT,
            estimated_premium REAL,
            estimated_revenue REAL,
            quoted_premium REAL,
            bound_premium REAL,
            effective_date TEXT,
            renewal_date TEXT,
            lost_reason TEXT,
            won_reason TEXT,
            notes TEXT,
            created_by TEXT,
            created_at TIMESTAMP
        )
    ''')

    # Score/timing snapshots (outcome/snapshot/notification phase).
    # Append-only, read-only projection — never recomputes scoring math,
    # just records what score_lead()/detect_process_stage() already
    # produced at a given moment (created/signal_added/merged/
    # outcome_changed/manual_rerun). Real leads only.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_lead_snapshots (
            id TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            score_total INTEGER,
            score_category TEXT,
            reason_codes_json TEXT,
            disqualifier_codes_json TEXT,
            process_stage TEXT,
            outreach_window TEXT,
            timing_reason TEXT,
            timing_confidence TEXT,
            urgency_label TEXT,
            signal_count INTEGER,
            attribution_summary_json TEXT,
            created_at TIMESTAMP
        )
    ''')

    # In-app notifications (outcome/snapshot/notification phase). No
    # external email/SMS — an in-app queue only. `dedupe_key` is UNIQUE so
    # emit() is naturally idempotent via INSERT OR IGNORE (db.py translates
    # this to ON CONFLICT DO NOTHING on Postgres).
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_notifications (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            lead_id TEXT,
            severity TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            action_url TEXT,
            metadata_json TEXT,
            dedupe_key TEXT,
            read_at TEXT,
            created_at TIMESTAMP
        )
    ''')

    # Sales Intelligence decision log (NEPQ-based reasoning engine).
    # Append-only, real-leads-only — records WHICH strategy/stage the
    # engine selected at a point in time, for future calibration (which
    # approach actually correlates with meetings/wins). Never stores the
    # generated message text itself (that's cheap to regenerate live from
    # the same lead+variant) — only the decision facets + reasoning.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_sales_intelligence_events (
            id TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            variant INTEGER NOT NULL DEFAULT 0,
            lead_temperature TEXT,
            lead_origin TEXT,
            insurance_scenario TEXT,
            buyer_awareness_level TEXT,
            resistance_risk TEXT,
            nepq_stage TEXT,
            recommended_action TEXT,
            confidence_score REAL,
            reasoning_json TEXT,
            conversation_mode TEXT,
            follow_up_type TEXT,
            guardrail_status TEXT,
            created_at TIMESTAMP
        )
    ''')

    try:
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_created ON multifamily_leads(created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_state ON multifamily_leads(state)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_spam_status ON multifamily_leads(spam_status)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_events_ip_created ON multifamily_intake_events(ip_hash, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_events_email_created ON multifamily_intake_events(email, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_events_type_created ON multifamily_intake_events(event_type, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_activities_lead ON multifamily_activities(lead_id, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_activities_followup ON multifamily_activities(next_follow_up_date)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_signals_lead ON multifamily_signals(lead_id, occurred_at)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_signals_type ON multifamily_signals(signal_type)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_attribution_lead ON multifamily_source_attribution(lead_id, occurred_at)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_source_runs_created ON multifamily_source_runs(created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_match_candidates_status ON multifamily_lead_match_candidates(status, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_merge_status ON multifamily_leads(merge_status)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_outcomes_lead ON multifamily_lead_outcomes(lead_id, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_outcomes_type ON multifamily_lead_outcomes(outcome_type)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_current_outcome ON multifamily_leads(current_outcome)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_snapshots_lead ON multifamily_lead_snapshots(lead_id, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_snapshots_reason ON multifamily_lead_snapshots(reason)')
        execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_multifamily_notifications_dedupe ON multifamily_notifications(dedupe_key)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_notifications_read ON multifamily_notifications(read_at, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_notifications_lead ON multifamily_notifications(lead_id)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_sales_intel_lead ON multifamily_sales_intelligence_events(lead_id, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_serp_seen_category_state ON multifamily_serp_seen(category, state)')
    except Exception:
        pass

    # A match candidate references both the incoming lead and the existing
    # candidate lead (added after the table's initial create).
    _safe_add_column('multifamily_lead_match_candidates', 'incoming_lead_id', 'TEXT')

    # Sales-intelligence decision log: conversation_mode/follow_up_type/
    # guardrail_status added after the table's initial create.
    _safe_add_column('multifamily_sales_intelligence_events', 'conversation_mode', 'TEXT')
    _safe_add_column('multifamily_sales_intelligence_events', 'follow_up_type', 'TEXT')
    _safe_add_column('multifamily_sales_intelligence_events', 'guardrail_status', 'TEXT')

    # SERP collection run metadata — added after the table's initial create.
    _safe_add_column('multifamily_source_runs', 'category', 'TEXT')
    _safe_add_column('multifamily_source_runs', 'state', 'TEXT')
    _safe_add_column('multifamily_source_runs', 'query', 'TEXT')

    # Funnel phase: which offer-page variant/campaign drove each attribution
    # touch — added after the table's initial create.
    _safe_add_column('multifamily_source_attribution', 'page_variant', 'TEXT')
    _safe_add_column('multifamily_source_attribution', 'campaign_id', 'TEXT')

    # Outbound-to-form merge-back tokens (Funnel Phase 3). token is the
    # primary key so the public offer-page URL never has to encode lead_id
    # directly (?mf_ref=<token>).
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_outbound_links (
            token TEXT PRIMARY KEY,
            lead_id TEXT NOT NULL,
            offer_type TEXT,
            page_variant TEXT,
            campaign_id TEXT,
            source TEXT,
            created_by TEXT,
            created_at TIMESTAMP,
            converted_at TEXT,
            converted_lead_id TEXT
        )
    ''')
    try:
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_outbound_links_lead ON multifamily_outbound_links(lead_id, created_at DESC)')
    except Exception:
        pass

    # Pilot Campaign Control Center. campaign_targets.lead_id is nullable
    # (a target may be a cold prospect with no lead yet) — this is why
    # campaigns get their OWN token column rather than reusing
    # multifamily_outbound_links, whose lead_id is NOT NULL.
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_campaigns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            page_variant TEXT NOT NULL,
            offer_type TEXT NOT NULL,
            target_state TEXT,
            target_city TEXT,
            target_segment TEXT,
            campaign_source TEXT,
            utm_source TEXT,
            utm_medium TEXT,
            utm_campaign TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            created_by TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP
        )
    ''')
    execute('''
        CREATE TABLE IF NOT EXISTS multifamily_campaign_targets (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            tracking_token TEXT NOT NULL,
            company TEXT,
            contact_name TEXT,
            email TEXT,
            phone TEXT,
            linkedin_url TEXT,
            city TEXT,
            state TEXT,
            segment TEXT,
            lead_id TEXT,
            status TEXT NOT NULL DEFAULT 'planned',
            notes TEXT,
            created_at TIMESTAMP,
            last_activity_at TEXT,
            converted_at TEXT
        )
    ''')
    try:
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_campaigns_status ON multifamily_campaigns(status, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_campaign_targets_campaign ON multifamily_campaign_targets(campaign_id, created_at DESC)')
        execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_multifamily_campaign_targets_token ON multifamily_campaign_targets(tracking_token)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_campaign_targets_lead ON multifamily_campaign_targets(lead_id)')
    except Exception:
        pass

    _backfill_signals_from_lead_json()
    _SCHEMA_READY = True


def _lead_situation_of(lead: MultifamilyLead) -> str:
    for signal in lead.signals:
        if signal.detail and signal.detail.get('lead_situation'):
            return signal.detail['lead_situation']
    return ''


def lead_situation_of(lead: MultifamilyLead) -> str:
    """Public alias — the self-reported situation (e.g. 'renewal',
    'acquisition') read from the lead's primary signal, used by the
    Outreach Workbench's page-recommendation (Funnel Phase 3)."""
    return _lead_situation_of(lead)


def insert_lead(lead: MultifamilyLead) -> None:
    """Persist a fully-built, already-scored real lead (any spam_status —
    callers decide what to do with 'rejected'/'suspicious' leads; this
    function just stores what it's given for audit purposes)."""
    ensure_schema()
    contact = lead.contacts[0] if lead.contacts else None
    row = {
        'id': lead.id,
        'is_demo': 1 if lead.is_demo else 0,
        'company_name': lead.company.name,
        'property_name': lead.property.name,
        'contact_name': contact.full_name if contact else None,
        'contact_email': contact.email if contact else None,
        'contact_phone': contact.phone if contact else None,
        'contact_role': contact.title if contact else None,
        'state': lead.state,
        'city': lead.city,
        'asset_type': lead.property.asset_type,
        'unit_count': lead.property.unit_count,
        'lead_situation': _lead_situation_of(lead),
        'primary_concern': lead.pain_flags[0] if lead.pain_flags else None,
        'notes': lead.notes,
        'source': lead.primary_source,
        'source_page': lead.source_page,
        'source_url': lead.source_url,
        'confidence': lead.confidence,
        'score_total': lead.score.total if lead.score else None,
        'score_category': lead.score.category if lead.score else None,
        'utm_source': lead.utm_source,
        'utm_medium': lead.utm_medium,
        'utm_campaign': lead.utm_campaign,
        'utm_term': lead.utm_term,
        'utm_content': lead.utm_content,
        'referrer': lead.referrer,
        'landing_page': lead.landing_page,
        'offer_type': lead.offer_type,
        'page_variant': lead.page_variant,
        'campaign_id': lead.campaign_id,
        'spam_status': lead.spam_status,
        'spam_reason_codes': json.dumps(lead.spam_reason_codes),
        'submitted_ip_hash': lead.submitted_ip_hash,
        'user_agent_summary': lead.user_agent_summary,
        'merge_status': 'active',
        'signal_count': len(lead.signals or []),
        'lead_json': json.dumps(dataclasses.asdict(lead)),
    }
    cols = list(row.keys())
    placeholders = ', '.join(['?'] * len(cols))
    execute(
        f"INSERT INTO multifamily_leads ({', '.join(cols)}) VALUES ({placeholders})",
        list(row.values()),
    )


def _dict_to_lead(d: dict) -> MultifamilyLead:
    """Reconstruct a full MultifamilyLead (with nested dataclasses) from
    the JSON shape produced by dataclasses.asdict() — so real leads can
    flow through the exact same scoring/filtering/sorting helpers in
    pipeline.py as in-memory mock leads. Rows written before a given
    field existed simply fall back to that field's dataclass default."""
    company = MultifamilyCompany(**d['company'])
    prop = MultifamilyProperty(**d['property'])
    signals = [MultifamilySignal(**s) for s in d.get('signals', [])]
    contacts = [MultifamilyContact(**c) for c in d.get('contacts', [])]
    score = MultifamilyLeadScore(**d['score']) if d.get('score') else None
    rest = {
        k: v for k, v in d.items()
        if k not in ('company', 'property', 'signals', 'contacts', 'score')
    }
    return MultifamilyLead(company=company, property=prop, signals=signals, contacts=contacts, score=score, **rest)


def get_real_leads(include_rejected: bool = False) -> List[MultifamilyLead]:
    """Return persisted real (non-demo) leads, newest first.

    By default excludes spam_status='rejected' leads — those should
    never appear in normal dashboard views. Pass include_rejected=True
    for the admin/debug view only. 'suspicious' leads are always
    included (they're real leads that just need a closer look)."""
    ensure_schema()
    # Exclude merged-away tombstones from every normal view; they're kept
    # only for reversibility/audit (merged_into_id points at the survivor).
    sql = "SELECT lead_json FROM multifamily_leads WHERE (merge_status IS NULL OR merge_status != 'merged')"
    if not include_rejected:
        sql += " AND spam_status != 'rejected'"
    sql += ' ORDER BY created_at DESC'
    rows = fetch_all(sql)
    leads = []
    for row in rows:
        try:
            leads.append(_dict_to_lead(json.loads(row['lead_json'])))
        except Exception:
            continue
    return leads


def delete_lead(lead_id: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_leads WHERE id = ?', [lead_id])


# ---------------------------------------------------------------------------
# Intake events — the rate-limiting ledger + admin/debug audit trail.
# Logged for EVERY POST attempt, regardless of outcome (including ones
# that never made it to a persisted lead, e.g. rate-limited/oversized).
# ---------------------------------------------------------------------------

def record_intake_event(event_type: str, ip_hash: Optional[str], email: Optional[str], detail: Optional[Dict[str, Any]] = None) -> None:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    # created_at is stamped explicitly (rather than relying on the column's
    # DB-side CURRENT_TIMESTAMP default) so it's in the exact same
    # isoformat() shape as the cutoffs count_recent_events() compares
    # against — SQLite's CURRENT_TIMESTAMP uses a space separator
    # ('YYYY-MM-DD HH:MM:SS'), not isoformat()'s 'T', and string-comparing
    # the two formats silently returns wrong results.
    execute(
        'INSERT INTO multifamily_intake_events (id, event_type, ip_hash, email, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [new_id(), event_type, ip_hash, (email or '').lower() or None, json.dumps(detail or {}), utc_now_iso()],
    )


def count_recent_events(event_types: List[str], since_iso: str, ip_hash: Optional[str] = None, email: Optional[str] = None) -> int:
    """Count intake events of the given type(s) since a timestamp, for a
    given ip_hash and/or email (OR'd together — either match counts)."""
    ensure_schema()
    if not ip_hash and not email:
        return 0
    placeholders = ', '.join(['?'] * len(event_types))
    sql = f'SELECT COUNT(*) AS n FROM multifamily_intake_events WHERE event_type IN ({placeholders}) AND created_at >= ? AND ('
    params: List[Any] = list(event_types) + [since_iso]
    clauses = []
    if ip_hash:
        clauses.append('ip_hash = ?')
        params.append(ip_hash)
    if email:
        clauses.append('email = ?')
        params.append((email or '').lower())
    sql += ' OR '.join(clauses) + ')'
    rows = fetch_all(sql, params)
    return int(rows[0]['n']) if rows else 0


def delete_events_for(ip_hash: Optional[str] = None, email: Optional[str] = None) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    if ip_hash:
        execute('DELETE FROM multifamily_intake_events WHERE ip_hash = ?', [ip_hash])
    if email:
        execute('DELETE FROM multifamily_intake_events WHERE email = ?', [(email or '').lower()])


def get_intake_stats(recent_limit: int = 20) -> Dict[str, Any]:
    """Admin/debug summary: recent submissions, spam-status counts, rate
    limit hits, and source/campaign breakdown."""
    ensure_schema()
    recent_rows = fetch_all(
        'SELECT id, company_name, contact_email, source, utm_source, utm_campaign, '
        'spam_status, score_total, score_category, created_at '
        'FROM multifamily_leads ORDER BY created_at DESC LIMIT ?',
        [recent_limit],
    )
    status_rows = fetch_all('SELECT spam_status, COUNT(*) AS n FROM multifamily_leads GROUP BY spam_status')
    counts_by_spam_status = {row['spam_status'] or 'clean': row['n'] for row in status_rows}

    rate_limit_rows = fetch_all(
        "SELECT COUNT(*) AS n FROM multifamily_intake_events WHERE event_type IN ('rate_limited_ip', 'rate_limited_email')"
    )
    rate_limit_hits = int(rate_limit_rows[0]['n']) if rate_limit_rows else 0

    source_rows = fetch_all(
        "SELECT COALESCE(NULLIF(utm_source, ''), source) AS source, COUNT(*) AS n "
        "FROM multifamily_leads GROUP BY COALESCE(NULLIF(utm_source, ''), source)"
    )
    source_breakdown = {row['source'] or 'unknown': row['n'] for row in source_rows}

    campaign_rows = fetch_all(
        "SELECT utm_campaign, COUNT(*) AS n FROM multifamily_leads WHERE utm_campaign IS NOT NULL AND utm_campaign != '' "
        "GROUP BY utm_campaign"
    )
    campaign_breakdown = {row['utm_campaign']: row['n'] for row in campaign_rows}

    return {
        'recent_submissions': recent_rows,
        'counts_by_spam_status': counts_by_spam_status,
        'rate_limit_hits': rate_limit_hits,
        'source_breakdown': source_breakdown,
        'campaign_breakdown': campaign_breakdown,
    }


# ---------------------------------------------------------------------------
# Source Performance (Part 8) — aggregations over real leads' source/UTM data.
# Demo leads carry no meaningful attribution, so these are real-lead-only;
# the API/UI shows an empty state when there are zero real leads.
# ---------------------------------------------------------------------------

def get_source_performance() -> Dict[str, Any]:
    ensure_schema()
    # Operational breakdowns exclude rejected spam (not real opportunities)
    # and merged-away tombstones (counted once, on the survivor).
    real = "is_demo = 0 AND spam_status != 'rejected' AND (merge_status IS NULL OR merge_status != 'merged')"

    def _counts(expr: str, where: str = real, label_default: str = 'unknown') -> Dict[str, int]:
        rows = fetch_all(
            f"SELECT {expr} AS k, COUNT(*) AS n FROM multifamily_leads WHERE {where} GROUP BY {expr}"
        )
        return {(row['k'] or label_default): row['n'] for row in rows}

    leads_by_source = _counts("COALESCE(NULLIF(utm_source, ''), source)")
    leads_by_source_page = _counts("COALESCE(NULLIF(source_page, ''), 'unknown')")
    leads_by_offer_type = _counts("COALESCE(NULLIF(offer_type, ''), 'unknown')")
    leads_by_campaign = _counts("COALESCE(NULLIF(utm_campaign, ''), 'none')")
    # Funnel Phase 6: which offer page (multifamily/forms/form_variants.py
    # slug) and which outreach campaign_id drove each lead — distinct
    # from offer_type/utm_campaign above (page_variant is the funnel's
    # own page identity; campaign_id is the funnel's own outreach tag).
    leads_by_page_variant = _counts("COALESCE(NULLIF(page_variant, ''), 'none')")
    leads_by_campaign_id = _counts("COALESCE(NULLIF(campaign_id, ''), 'none')")

    # Category × source (Call Today / Hot / Warm / Nurture / Watchlist by source).
    cat_rows = fetch_all(
        "SELECT COALESCE(NULLIF(utm_source, ''), source) AS src, score_category AS cat, COUNT(*) AS n "
        f"FROM multifamily_leads WHERE {real} GROUP BY src, cat"
    )
    by_source_category: Dict[str, Dict[str, int]] = {}
    call_today_by_source: Dict[str, int] = {}
    for row in cat_rows:
        src = row['src'] or 'unknown'
        cat = row['cat'] or 'unscored'
        by_source_category.setdefault(src, {})[cat] = row['n']
        if cat == 'call_today':
            call_today_by_source[src] = call_today_by_source.get(src, 0) + row['n']

    # Spam/suspicious rate by source (over ALL real leads, incl. rejected).
    spam_rows = fetch_all(
        "SELECT COALESCE(NULLIF(utm_source, ''), source) AS src, "
        "SUM(CASE WHEN spam_status IN ('suspicious', 'rejected') THEN 1 ELSE 0 END) AS flagged, "
        "COUNT(*) AS total "
        "FROM multifamily_leads WHERE is_demo = 0 GROUP BY src"
    )
    spam_rate_by_source = {
        (row['src'] or 'unknown'): {
            'flagged': int(row['flagged'] or 0),
            'total': int(row['total'] or 0),
            'rate_pct': round(100.0 * (row['flagged'] or 0) / row['total'], 1) if row['total'] else 0.0,
        }
        for row in spam_rows
    }

    # Best landing page (most leads) and worst source (lowest avg score).
    landing_rows = fetch_all(
        "SELECT landing_page AS lp, COUNT(*) AS n FROM multifamily_leads "
        f"WHERE {real} AND landing_page IS NOT NULL AND landing_page != '' GROUP BY landing_page ORDER BY n DESC LIMIT 1"
    )
    best_landing_page = ({'landing_page': landing_rows[0]['lp'], 'leads': landing_rows[0]['n']}
                         if landing_rows else None)

    avg_rows = fetch_all(
        "SELECT COALESCE(NULLIF(utm_source, ''), source) AS src, ROUND(AVG(score_total), 1) AS avg_score, COUNT(*) AS n "
        f"FROM multifamily_leads WHERE {real} AND score_total IS NOT NULL GROUP BY src HAVING COUNT(*) >= 1 ORDER BY avg_score ASC LIMIT 1"
    )
    worst_source = ({'source': avg_rows[0]['src'], 'avg_score': avg_rows[0]['avg_score'], 'leads': avg_rows[0]['n']}
                    if avg_rows else None)

    missing_rows = fetch_all(
        "SELECT COUNT(*) AS n FROM multifamily_leads "
        f"WHERE {real} AND (utm_source IS NULL OR utm_source = '') AND (utm_campaign IS NULL OR utm_campaign = '') "
        "AND (referrer IS NULL OR referrer = '')"
    )
    leads_missing_attribution = int(missing_rows[0]['n']) if missing_rows else 0

    total_rows = fetch_all(f"SELECT COUNT(*) AS n FROM multifamily_leads WHERE {real}")
    total_real_leads = int(total_rows[0]['n']) if total_rows else 0

    # Signal-based view (Phase C): per-source / per-type signal counts over
    # real, non-rejected signals — additive to the lead-source aggregates.
    sig_where = "is_demo = 0 AND spam_status != 'rejected'"
    signals_by_source = {
        (r['k'] or 'unknown'): r['n'] for r in fetch_all(
            f"SELECT COALESCE(NULLIF(source, ''), 'unknown') AS k, COUNT(*) AS n FROM multifamily_signals WHERE {sig_where} GROUP BY source")
    }
    signals_by_type = {
        (r['k'] or 'unknown'): r['n'] for r in fetch_all(
            f"SELECT COALESCE(NULLIF(signal_type, ''), 'unknown') AS k, COUNT(*) AS n FROM multifamily_signals WHERE {sig_where} GROUP BY signal_type")
    }
    total_signal_rows = sum(signals_by_source.values())

    # Funnel Phase 6: outbound-to-form conversion path — how many links
    # were generated vs. actually converted, overall and per offer page.
    outbound_rows = fetch_all(
        "SELECT COALESCE(NULLIF(page_variant, ''), 'none') AS pv, "
        "COUNT(*) AS sent, SUM(CASE WHEN converted_at IS NOT NULL THEN 1 ELSE 0 END) AS converted "
        "FROM multifamily_outbound_links GROUP BY pv"
    )
    outbound_by_page_variant = {}
    total_links_sent = 0
    total_links_converted = 0
    for row in outbound_rows:
        sent = int(row['sent'] or 0)
        converted = int(row['converted'] or 0)
        total_links_sent += sent
        total_links_converted += converted
        outbound_by_page_variant[row['pv'] or 'none'] = {
            'sent': sent, 'converted': converted,
            'conversion_rate_pct': round(100.0 * converted / sent, 1) if sent else 0.0,
        }
    outbound_conversion_stats = {
        'total_links_sent': total_links_sent,
        'total_links_converted': total_links_converted,
        'conversion_rate_pct': round(100.0 * total_links_converted / total_links_sent, 1) if total_links_sent else 0.0,
        'by_page_variant': outbound_by_page_variant,
    }

    return {
        'total_real_leads': total_real_leads,
        'leads_by_source': leads_by_source,
        'leads_by_source_page': leads_by_source_page,
        'leads_by_offer_type': leads_by_offer_type,
        'leads_by_campaign': leads_by_campaign,
        'leads_by_page_variant': leads_by_page_variant,
        'leads_by_campaign_id': leads_by_campaign_id,
        'by_source_category': by_source_category,
        'call_today_by_source': call_today_by_source,
        'spam_rate_by_source': spam_rate_by_source,
        'best_landing_page': best_landing_page,
        'worst_source': worst_source,
        'leads_missing_attribution': leads_missing_attribution,
        # Funnel Phase 6: outbound-to-form conversion path.
        'outbound_conversion_stats': outbound_conversion_stats,
        # Phase C signal-history view.
        'total_signals': total_signal_rows,
        'signals_by_source': signals_by_source,
        'signals_by_type': signals_by_type,
        # SERP source performance (Multifamily SERP Phase C).
        'serp': _serp_source_performance(leads_by_source, by_source_category, call_today_by_source, signals_by_source),
    }


def _serp_source_performance(
    leads_by_source: Dict[str, int], by_source_category: Dict[str, Dict[str, int]],
    call_today_by_source: Dict[str, int], signals_by_source: Dict[str, int],
) -> Dict[str, Any]:
    """SERP-specific rollup, additive to the generic per-source breakdown
    already computed above: leads merged away (tombstoned into an
    existing lead — not visible in the active-lead counts above), pending
    review candidates raised by SERP-sourced signals, and aggregate
    source-run totals (found/created/merged/rejected) from every logged
    'serp' collection run."""
    merged_rows = fetch_all(
        "SELECT COUNT(*) AS n FROM multifamily_leads WHERE is_demo = 0 AND source = 'serp' AND merge_status = 'merged'"
    )
    leads_merged_away = int(merged_rows[0]['n']) if merged_rows else 0

    review_rows = fetch_all(
        "SELECT COUNT(*) AS n FROM multifamily_lead_match_candidates mc "
        "JOIN multifamily_leads l ON mc.incoming_lead_id = l.id "
        "WHERE l.source = 'serp' AND mc.status = 'pending'"
    )
    review_candidates_pending = int(review_rows[0]['n']) if review_rows else 0

    run_rows = fetch_all(
        "SELECT COUNT(*) AS runs, COALESCE(SUM(records_found), 0) AS found, "
        "COALESCE(SUM(records_created), 0) AS created, COALESCE(SUM(records_merged), 0) AS merged, "
        "COALESCE(SUM(records_rejected), 0) AS rejected "
        "FROM multifamily_source_runs WHERE source = 'serp'"
    )
    run_totals = run_rows[0] if run_rows else {}

    return {
        'signals_received': signals_by_source.get('serp', 0),
        'leads_created': leads_by_source.get('serp', 0),
        'leads_merged_away': leads_merged_away,
        'review_candidates_pending': review_candidates_pending,
        'hot_leads': by_source_category.get('serp', {}).get('hot', 0),
        'call_today_leads': call_today_by_source.get('serp', 0),
        'collection_runs': int(run_totals.get('runs') or 0),
        'total_found_across_runs': int(run_totals.get('found') or 0),
        'total_created_across_runs': int(run_totals.get('created') or 0),
        'total_merged_across_runs': int(run_totals.get('merged') or 0),
        'total_rejected_across_runs': int(run_totals.get('rejected') or 0),
    }


# ---------------------------------------------------------------------------
# Manual activity tracking (Part 7). Multifamily-only — never touches the
# BTR crm_* tables. Activities meaningfully attach to REAL leads (demo lead
# ids regenerate each pipeline run).
# ---------------------------------------------------------------------------

def insert_activity(lead_id: str, activity_type: str, note: Optional[str] = None,
                    next_follow_up_date: Optional[str] = None, user_email: Optional[str] = None) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    row = {
        'id': new_id(),
        'lead_id': lead_id,
        'activity_type': activity_type,
        'note': note,
        'next_follow_up_date': next_follow_up_date or None,
        'user_email': (user_email or '').lower() or None,
        'created_at': utc_now_iso(),
    }
    execute(
        'INSERT INTO multifamily_activities (id, lead_id, activity_type, note, next_follow_up_date, user_email, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    return row


def get_activities_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    return fetch_all(
        'SELECT id, lead_id, activity_type, note, next_follow_up_date, user_email, created_at '
        'FROM multifamily_activities WHERE lead_id = ? ORDER BY created_at DESC',
        [lead_id],
    )


def _activities_with_lead(where: str, params: List[Any]) -> List[Dict[str, Any]]:
    """Activity rows LEFT JOINed to their lead for display fields (company/
    state/category). Lead fields are NULL for activities on demo leads."""
    return fetch_all(
        'SELECT a.id, a.lead_id, a.activity_type, a.note, a.next_follow_up_date, a.user_email, a.created_at, '
        'l.company_name, l.state, l.city, l.score_category '
        'FROM multifamily_activities a LEFT JOIN multifamily_leads l ON a.lead_id = l.id '
        f'WHERE {where}',
        params,
    )


def get_followups_due(today_date: str) -> List[Dict[str, Any]]:
    """Activities whose next_follow_up_date is on or before `today_date`
    (YYYY-MM-DD), newest follow-up first."""
    ensure_schema()
    return _activities_with_lead(
        "a.next_follow_up_date IS NOT NULL AND a.next_follow_up_date != '' AND a.next_follow_up_date <= ? "
        "ORDER BY a.next_follow_up_date ASC",
        [today_date],
    )


def get_activities_by_type(activity_types: List[str]) -> List[Dict[str, Any]]:
    ensure_schema()
    if not activity_types:
        return []
    placeholders = ', '.join(['?'] * len(activity_types))
    return _activities_with_lead(
        f"a.activity_type IN ({placeholders}) ORDER BY a.created_at DESC",
        list(activity_types),
    )


def last_activity_at_by_lead() -> Dict[str, str]:
    ensure_schema()
    rows = fetch_all('SELECT lead_id, MAX(created_at) AS last_at FROM multifamily_activities GROUP BY lead_id')
    return {row['lead_id']: row['last_at'] for row in rows}


def delete_activities_for_lead(lead_id: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_activities WHERE lead_id = ?', [lead_id])


# ===========================================================================
# Signal architecture (signal-architecture phase)
# Persisted, queryable signals + source-attribution touches + source-run
# accounting + match candidates. `lead_json` on multifamily_leads remains
# the dataclass source of truth; multifamily_signals is a consistent
# queryable projection of it.
# ===========================================================================

def _insert_signal_row(lead_id: str, signal: Dict[str, Any], is_demo: int = 0, spam_status: str = 'clean') -> None:
    """Insert one signal row from a plain dict (no ensure_schema — safe to
    call from the backfill, which runs *inside* ensure_schema)."""
    from multifamily.types import utc_now_iso
    detail = signal.get('detail')
    execute(
        'INSERT INTO multifamily_signals (id, lead_id, signal_type, source, source_url, confidence, '
        'occurred_at, detail_json, is_demo, spam_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
            signal.get('id'), lead_id, signal.get('signal_type'), signal.get('source'), signal.get('source_url'),
            signal.get('confidence'), signal.get('occurred_at'),
            json.dumps(detail) if detail is not None else None,
            1 if is_demo else 0, spam_status or 'clean', utc_now_iso(),
        ],
    )


def _backfill_signals_from_lead_json() -> None:
    """One-time, idempotent backfill: project signals embedded in each
    lead's lead_json into the multifamily_signals table. Inserts only
    signals whose id isn't already present, so it's safe to run on every
    process start (it's called from ensure_schema, once per process)."""
    try:
        existing = {r['id'] for r in fetch_all('SELECT id FROM multifamily_signals')}
        lead_rows = fetch_all('SELECT id, is_demo, spam_status, lead_json FROM multifamily_leads')
    except Exception:
        return
    for row in lead_rows:
        try:
            d = json.loads(row['lead_json'])
        except Exception:
            continue
        for s in (d.get('signals') or []):
            sid = s.get('id')
            if not sid or sid in existing:
                continue
            try:
                _insert_signal_row(row['id'], s, is_demo=row.get('is_demo') or 0, spam_status=row.get('spam_status') or 'clean')
                existing.add(sid)
            except Exception:
                continue


def insert_signal(lead_id: str, signal, is_demo: bool = False, spam_status: str = 'clean') -> None:
    """Persist one signal (a MultifamilySignal dataclass or a dict) as a
    queryable row, keyed to its lead."""
    ensure_schema()
    s = dataclasses.asdict(signal) if dataclasses.is_dataclass(signal) else dict(signal)
    _insert_signal_row(lead_id, s, is_demo=1 if is_demo else 0, spam_status=spam_status)


def persist_lead_signals(lead) -> None:
    """Persist every signal of a freshly-built lead (used by intake/merge)."""
    ensure_schema()
    for s in (lead.signals or []):
        insert_signal(lead.id, s, is_demo=lead.is_demo, spam_status=getattr(lead, 'spam_status', 'clean'))


def get_signals_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(
        'SELECT id, lead_id, signal_type, source, source_url, confidence, occurred_at, detail_json, '
        'is_demo, spam_status, created_at FROM multifamily_signals WHERE lead_id = ? ORDER BY occurred_at ASC, created_at ASC',
        [lead_id],
    )
    for r in rows:
        try:
            r['detail'] = json.loads(r['detail_json']) if r.get('detail_json') else {}
        except Exception:
            r['detail'] = {}
    return rows


def delete_signals_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_signals WHERE lead_id = ?', [lead_id])


def reassign_signals(from_lead_id: str, to_lead_id: str) -> None:
    """Move a merged-away lead's signal rows onto the survivor (Phase B)."""
    ensure_schema()
    execute('UPDATE multifamily_signals SET lead_id = ? WHERE lead_id = ?', [to_lead_id, from_lead_id])


# ---- Source attribution touches -------------------------------------------

def record_attribution(lead_id: str, touch_type: str, source: Optional[str] = None,
                       utm_source: Optional[str] = None, utm_medium: Optional[str] = None,
                       utm_campaign: Optional[str] = None, utm_term: Optional[str] = None,
                       utm_content: Optional[str] = None, referrer: Optional[str] = None,
                       landing_page: Optional[str] = None, offer_type: Optional[str] = None,
                       page_variant: Optional[str] = None, campaign_id: Optional[str] = None,
                       occurred_at: Optional[str] = None) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    now = utc_now_iso()
    row = {
        'id': new_id(), 'lead_id': lead_id, 'touch_type': touch_type, 'source': source,
        'utm_source': utm_source, 'utm_medium': utm_medium, 'utm_campaign': utm_campaign,
        'utm_term': utm_term, 'utm_content': utm_content, 'referrer': referrer,
        'landing_page': landing_page, 'offer_type': offer_type,
        'page_variant': page_variant, 'campaign_id': campaign_id,
        'occurred_at': occurred_at or now, 'created_at': now,
    }
    execute(
        'INSERT INTO multifamily_source_attribution (id, lead_id, touch_type, source, utm_source, utm_medium, '
        'utm_campaign, utm_term, utm_content, referrer, landing_page, offer_type, page_variant, campaign_id, '
        'occurred_at, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    return row


def record_lead_attribution_touch(lead, touch_type: str = 'touch') -> None:
    """Record one attribution touch from a lead's current source/UTM fields."""
    record_attribution(
        lead.id, touch_type, source=lead.primary_source,
        utm_source=lead.utm_source, utm_medium=lead.utm_medium, utm_campaign=lead.utm_campaign,
        utm_term=lead.utm_term, utm_content=lead.utm_content, referrer=lead.referrer,
        landing_page=lead.landing_page, offer_type=lead.offer_type,
        page_variant=getattr(lead, 'page_variant', None), campaign_id=getattr(lead, 'campaign_id', None),
        occurred_at=lead.last_verified_at,
    )


# ---- Outbound-to-form merge-back links (Funnel Phase 3) --------------------

def create_outbound_link(lead_id: str, offer_type: Optional[str] = None,
                          page_variant: Optional[str] = None, campaign_id: Optional[str] = None,
                          source: Optional[str] = None, created_by: Optional[str] = None) -> Dict[str, Any]:
    """Mint a token mapping back to `lead_id` — an operator sends the
    prospect a link like /mf-review/<page_variant>?mf_ref=<token>; when
    they submit it, create_lead() looks the token up and merges the
    submission straight into this lead (see api/routes/multifamily.py)."""
    ensure_schema()
    import secrets
    from multifamily.types import utc_now_iso
    token = secrets.token_urlsafe(16)
    now = utc_now_iso()
    row = {
        'token': token, 'lead_id': lead_id, 'offer_type': offer_type, 'page_variant': page_variant,
        'campaign_id': campaign_id, 'source': source, 'created_by': created_by,
        'created_at': now, 'converted_at': None, 'converted_lead_id': None,
    }
    execute(
        'INSERT INTO multifamily_outbound_links (token, lead_id, offer_type, page_variant, campaign_id, '
        'source, created_by, created_at, converted_at, converted_lead_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    return row


def get_outbound_link(token: str) -> Optional[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(
        'SELECT token, lead_id, offer_type, page_variant, campaign_id, source, created_by, created_at, '
        'converted_at, converted_lead_id FROM multifamily_outbound_links WHERE token = ?',
        [token],
    )
    return rows[0] if rows else None


def get_outbound_links_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    return fetch_all(
        'SELECT token, lead_id, offer_type, page_variant, campaign_id, source, created_by, created_at, '
        'converted_at, converted_lead_id FROM multifamily_outbound_links WHERE lead_id = ? ORDER BY created_at DESC',
        [lead_id],
    )


def mark_outbound_link_converted(token: str, converted_lead_id: str) -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute(
        'UPDATE multifamily_outbound_links SET converted_at = ?, converted_lead_id = ? WHERE token = ?',
        [utc_now_iso(), converted_lead_id, token],
    )


def delete_outbound_links_for_lead(lead_id: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_outbound_links WHERE lead_id = ?', [lead_id])


# ---- Pilot Campaign Control Center -----------------------------------------

_CAMPAIGN_COLUMNS = (
    'id, name, description, page_variant, offer_type, target_state, target_city, '
    'target_segment, campaign_source, utm_source, utm_medium, utm_campaign, status, '
    'created_by, created_at, updated_at'
)

_CAMPAIGN_TARGET_COLUMNS = (
    'id, campaign_id, tracking_token, company, contact_name, email, phone, linkedin_url, '
    'city, state, segment, lead_id, status, notes, created_at, last_activity_at, converted_at'
)


def create_campaign(
    name: str, page_variant: str, offer_type: str, *, description: Optional[str] = None,
    target_state: Optional[str] = None, target_city: Optional[str] = None,
    target_segment: Optional[str] = None, campaign_source: Optional[str] = None,
    utm_source: Optional[str] = None, utm_medium: Optional[str] = None, utm_campaign: Optional[str] = None,
    status: str = 'draft', created_by: Optional[str] = None,
) -> Dict[str, Any]:
    """`offer_type` is derived from `page_variant` by the caller (see
    api/routes/multifamily.py, same pattern as the outbound-link mint
    endpoint) — this function just persists what it's given."""
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    now = utc_now_iso()
    row = {
        'id': new_id(), 'name': name, 'description': description, 'page_variant': page_variant,
        'offer_type': offer_type, 'target_state': target_state, 'target_city': target_city,
        'target_segment': target_segment, 'campaign_source': campaign_source,
        'utm_source': utm_source, 'utm_medium': utm_medium, 'utm_campaign': utm_campaign,
        'status': status, 'created_by': created_by, 'created_at': now, 'updated_at': now,
    }
    execute(
        f'INSERT INTO multifamily_campaigns ({_CAMPAIGN_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    return row


def get_campaign(campaign_id: str) -> Optional[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(f'SELECT {_CAMPAIGN_COLUMNS} FROM multifamily_campaigns WHERE id = ?', [campaign_id])
    return rows[0] if rows else None


def list_campaigns(status: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_schema()
    if status:
        return fetch_all(
            f'SELECT {_CAMPAIGN_COLUMNS} FROM multifamily_campaigns WHERE status = ? ORDER BY created_at DESC',
            [status],
        )
    return fetch_all(f'SELECT {_CAMPAIGN_COLUMNS} FROM multifamily_campaigns ORDER BY created_at DESC')


def update_campaign_status(campaign_id: str, status: str) -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute(
        'UPDATE multifamily_campaigns SET status = ?, updated_at = ? WHERE id = ?',
        [status, utc_now_iso(), campaign_id],
    )


def delete_campaign(campaign_id: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_campaign_targets WHERE campaign_id = ?', [campaign_id])
    execute('DELETE FROM multifamily_campaigns WHERE id = ?', [campaign_id])


def create_campaign_target(
    campaign_id: str, *, company: Optional[str] = None, contact_name: Optional[str] = None,
    email: Optional[str] = None, phone: Optional[str] = None, linkedin_url: Optional[str] = None,
    city: Optional[str] = None, state: Optional[str] = None, segment: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Mints this target's own tracking_token (distinct from
    multifamily_outbound_links' token — that table's lead_id is NOT
    NULL, so it can't represent a cold prospect with no lead yet)."""
    ensure_schema()
    import secrets
    from multifamily.types import new_id, utc_now_iso
    now = utc_now_iso()
    row = {
        'id': new_id(), 'campaign_id': campaign_id, 'tracking_token': secrets.token_urlsafe(16),
        'company': company, 'contact_name': contact_name, 'email': email, 'phone': phone,
        'linkedin_url': linkedin_url, 'city': city, 'state': state, 'segment': segment,
        'lead_id': None, 'status': 'planned', 'notes': notes,
        'created_at': now, 'last_activity_at': None, 'converted_at': None,
    }
    execute(
        f'INSERT INTO multifamily_campaign_targets ({_CAMPAIGN_TARGET_COLUMNS}) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    return row


def get_campaign_target(target_id: str) -> Optional[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(f'SELECT {_CAMPAIGN_TARGET_COLUMNS} FROM multifamily_campaign_targets WHERE id = ?', [target_id])
    return rows[0] if rows else None


def get_campaign_target_by_token(token: str) -> Optional[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(f'SELECT {_CAMPAIGN_TARGET_COLUMNS} FROM multifamily_campaign_targets WHERE tracking_token = ?', [token])
    return rows[0] if rows else None


def list_campaign_targets(campaign_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    return fetch_all(
        f'SELECT {_CAMPAIGN_TARGET_COLUMNS} FROM multifamily_campaign_targets '
        'WHERE campaign_id = ? ORDER BY created_at DESC',
        [campaign_id],
    )


def update_campaign_target_status(target_id: str, status: str, notes: Optional[str] = None) -> None:
    """Any status transition bumps last_activity_at — this is the only
    'freshness' clock a campaign target has (mirrors how lead activities
    drive multifamily_leads' implicit staleness checks)."""
    ensure_schema()
    from multifamily.types import utc_now_iso
    now = utc_now_iso()
    if notes is not None:
        execute(
            'UPDATE multifamily_campaign_targets SET status = ?, notes = ?, last_activity_at = ? WHERE id = ?',
            [status, notes, now, target_id],
        )
    else:
        execute(
            'UPDATE multifamily_campaign_targets SET status = ?, last_activity_at = ? WHERE id = ?',
            [status, now, target_id],
        )


def set_campaign_target_lead(target_id: str, lead_id: str) -> None:
    """Backfill a target's lead_id once its identity resolves to a real
    lead (via the matching engine) — separate from marking it converted,
    since a target can be linked to a lead before it actually converts
    (e.g. an operator manually attaches an existing lead to a target)."""
    ensure_schema()
    execute('UPDATE multifamily_campaign_targets SET lead_id = ? WHERE id = ?', [lead_id, target_id])


def mark_campaign_target_converted(target_id: str, lead_id: str) -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    now = utc_now_iso()
    execute(
        "UPDATE multifamily_campaign_targets SET status = 'converted', lead_id = ?, "
        'converted_at = ?, last_activity_at = ? WHERE id = ?',
        [lead_id, now, now, target_id],
    )


def delete_campaign_targets_for_campaign(campaign_id: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_campaign_targets WHERE campaign_id = ?', [campaign_id])


def get_attribution_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    return fetch_all(
        'SELECT id, lead_id, touch_type, source, utm_source, utm_medium, utm_campaign, utm_term, utm_content, '
        'referrer, landing_page, offer_type, page_variant, campaign_id, occurred_at, created_at '
        'FROM multifamily_source_attribution '
        'WHERE lead_id = ? ORDER BY occurred_at ASC, created_at ASC',
        [lead_id],
    )


# Sources that represent a real "conversion" (a form/manual submission),
# used to pick the conversion touch from the attribution history.
_CONVERSION_SOURCES = {'benchmark_form', 'form', 'manual', 'linkedin_lead_form'}


def get_attribution_summary(lead_id: str) -> Dict[str, Any]:
    """Derive first-touch / latest-touch / conversion source plus the
    UTM / landing-page / referrer path from a lead's append-only
    attribution touches (Phase C)."""
    touches = get_attribution_for_lead(lead_id)
    if not touches:
        return {
            'first_touch': None, 'latest_touch': None, 'conversion_source': None,
            'touches': [], 'utm_history': [], 'landing_page_history': [], 'referrer_history': [],
        }
    first, latest = touches[0], touches[-1]
    conversion = next((t for t in touches if t.get('source') in _CONVERSION_SOURCES), first)
    utm_history = [
        {'utm_source': t.get('utm_source'), 'utm_medium': t.get('utm_medium'),
         'utm_campaign': t.get('utm_campaign'), 'occurred_at': t.get('occurred_at')}
        for t in touches if any(t.get(k) for k in ('utm_source', 'utm_medium', 'utm_campaign'))
    ]
    landing_history = [t.get('landing_page') for t in touches if t.get('landing_page')]
    referrer_history = [t.get('referrer') for t in touches if t.get('referrer')]
    return {
        'first_touch': {'source': first.get('source'), 'utm_source': first.get('utm_source'),
                        'utm_campaign': first.get('utm_campaign'), 'occurred_at': first.get('occurred_at')},
        'latest_touch': {'source': latest.get('source'), 'utm_source': latest.get('utm_source'),
                         'utm_campaign': latest.get('utm_campaign'), 'occurred_at': latest.get('occurred_at')},
        'conversion_source': conversion.get('source'),
        'touches': touches,
        'utm_history': utm_history,
        'landing_page_history': landing_history,
        'referrer_history': referrer_history,
    }


def delete_attribution_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_source_attribution WHERE lead_id = ?', [lead_id])


def reassign_attribution(from_lead_id: str, to_lead_id: str) -> None:
    ensure_schema()
    execute('UPDATE multifamily_source_attribution SET lead_id = ? WHERE lead_id = ?', [to_lead_id, from_lead_id])


# ---- Source-run accounting -------------------------------------------------

def start_source_run(source: str, run_id: Optional[str] = None) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    now = utc_now_iso()
    rid = run_id or new_id()
    row = {'id': new_id(), 'source': source, 'run_id': rid, 'started_at': now, 'status': 'running', 'created_at': now}
    execute(
        'INSERT INTO multifamily_source_runs (id, source, run_id, started_at, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [row['id'], source, rid, now, 'running', now],
    )
    return row


def finish_source_run(run_db_id: str, status: str = 'success', records_found: int = 0, records_created: int = 0,
                      records_updated: int = 0, records_merged: int = 0, records_rejected: int = 0,
                      errors: Optional[List[str]] = None, warnings: Optional[List[str]] = None) -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute(
        'UPDATE multifamily_source_runs SET finished_at = ?, status = ?, records_found = ?, records_created = ?, '
        'records_updated = ?, records_merged = ?, records_rejected = ?, errors_json = ?, warnings_json = ? WHERE id = ?',
        [utc_now_iso(), status, records_found, records_created, records_updated, records_merged, records_rejected,
         json.dumps(errors or []), json.dumps(warnings or []), run_db_id],
    )


def get_source_runs(limit: int = 50, source: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_schema()
    where = 'WHERE source = ?' if source else ''
    params = ([source] if source else []) + [limit]
    rows = fetch_all(
        'SELECT id, source, run_id, started_at, finished_at, status, records_found, records_created, '
        'records_updated, records_merged, records_rejected, errors_json, warnings_json, '
        'category, state, query, created_at '
        f'FROM multifamily_source_runs {where} ORDER BY created_at DESC LIMIT ?',
        params,
    )
    for r in rows:
        for k in ('errors_json', 'warnings_json'):
            try:
                r[k.replace('_json', '')] = json.loads(r[k]) if r.get(k) else []
            except Exception:
                r[k.replace('_json', '')] = []
    return rows


def set_source_run_query_metadata(
    run_db_id: str, *, category: Optional[str] = None, state: Optional[str] = None,
    query: Optional[str] = None, records_found: Optional[int] = None,
) -> None:
    """Attach SERP-specific run metadata after ingest_batch/ingest_trigger_batch
    already logged the run (those generic functions don't know about
    category/state/query). Also lets the SERP collector correct
    records_found to the TOTAL raw search-result count — ingest_batch only
    sees the already-filtered accepted-for-ingest count, which would
    otherwise undercount once low-relevance results are filtered out
    upstream of ingest."""
    ensure_schema()
    sets, params = [], []
    if category is not None:
        sets.append('category = ?'); params.append(category)
    if state is not None:
        sets.append('state = ?'); params.append(state)
    if query is not None:
        sets.append('query = ?'); params.append(query)
    if records_found is not None:
        sets.append('records_found = ?'); params.append(records_found)
    if not sets:
        return
    params.append(run_db_id)
    execute(f'UPDATE multifamily_source_runs SET {", ".join(sets)} WHERE id = ?', params)


def delete_source_run(run_db_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_source_runs WHERE id = ?', [run_db_id])


# ---- SERP url-seen ledger ---------------------------------------------------

def is_serp_url_seen(url: str) -> bool:
    ensure_schema()
    rows = fetch_all('SELECT 1 FROM multifamily_serp_seen WHERE url = ?', [url])
    return bool(rows)


def mark_serp_url_seen(url: str, category: Optional[str] = None, state: Optional[str] = None) -> None:
    """Idempotent — INSERT OR IGNORE so re-marking an already-seen URL
    (e.g. a race between two concurrent runs) never raises."""
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute(
        'INSERT OR IGNORE INTO multifamily_serp_seen (url, category, state, first_seen_at) VALUES (?, ?, ?, ?)',
        [url, category, state, utc_now_iso()],
    )


def delete_serp_seen_url(url: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_serp_seen WHERE url = ?', [url])


# ---- Match candidates (review queue) --------------------------------------

def insert_match_candidate(incoming_signal_id: Optional[str], candidate_lead_id: str, match_tier: str,
                           match_reasons: Optional[List[str]] = None, score: float = 0.0,
                           incoming_lead_id: Optional[str] = None) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    row = {
        'id': new_id(), 'incoming_signal_id': incoming_signal_id, 'candidate_lead_id': candidate_lead_id,
        'incoming_lead_id': incoming_lead_id, 'match_tier': match_tier, 'match_reasons': match_reasons or [],
        'score': score, 'status': 'pending', 'created_at': utc_now_iso(),
    }
    execute(
        'INSERT INTO multifamily_lead_match_candidates (id, incoming_signal_id, candidate_lead_id, incoming_lead_id, '
        'match_tier, match_reasons_json, score, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [row['id'], incoming_signal_id, candidate_lead_id, incoming_lead_id, match_tier,
         json.dumps(row['match_reasons']), score, 'pending', row['created_at']],
    )
    return row


def get_match_candidates(status: str = 'pending') -> List[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(
        'SELECT c.id, c.incoming_signal_id, c.incoming_lead_id, c.candidate_lead_id, c.match_tier, c.match_reasons_json, '
        'c.score, c.status, c.resolved_by, c.created_at, c.resolved_at, l.company_name, l.state, l.city, '
        'il.company_name AS incoming_company_name, il.state AS incoming_state, il.city AS incoming_city '
        'FROM multifamily_lead_match_candidates c '
        'LEFT JOIN multifamily_leads l ON c.candidate_lead_id = l.id '
        'LEFT JOIN multifamily_leads il ON c.incoming_lead_id = il.id '
        'WHERE c.status = ? ORDER BY c.created_at DESC',
        [status],
    )
    for r in rows:
        try:
            r['match_reasons'] = json.loads(r['match_reasons_json']) if r.get('match_reasons_json') else []
        except Exception:
            r['match_reasons'] = []
    return rows


def get_match_candidate(candidate_id: str) -> Optional[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all('SELECT * FROM multifamily_lead_match_candidates WHERE id = ?', [candidate_id])
    return rows[0] if rows else None


def resolve_match_candidate(candidate_id: str, status: str, resolved_by: Optional[str] = None) -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute(
        'UPDATE multifamily_lead_match_candidates SET status = ?, resolved_by = ?, resolved_at = ? WHERE id = ?',
        [status, resolved_by, utc_now_iso(), candidate_id],
    )


def delete_match_candidates_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_lead_match_candidates WHERE candidate_lead_id = ?', [lead_id])


# ---- Lead update / tombstone (used by the merge engine, Phase B) ----------

def get_lead_row(lead_id: str) -> Optional[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all('SELECT * FROM multifamily_leads WHERE id = ?', [lead_id])
    return rows[0] if rows else None


def get_lead_by_id(lead_id: str) -> Optional[MultifamilyLead]:
    """Reconstruct a single lead dataclass from its persisted lead_json."""
    row = get_lead_row(lead_id)
    if not row or not row.get('lead_json'):
        return None
    try:
        return _dict_to_lead(json.loads(row['lead_json']))
    except Exception:
        return None


def get_active_lead_by_id(lead_id: str, _hops: int = 0) -> Optional[MultifamilyLead]:
    """Like get_lead_by_id, but follows merged_into_id if the given lead
    was itself merged away since — used by the outbound-link merge-back
    path (Funnel Phase 3), where the token's original lead_id may have
    been folded into a survivor by an unrelated fuzzy/auto match in the
    meantime. Bounded hop count as a defensive guard against a corrupt
    merge cycle."""
    if _hops > 5:
        return None
    row = get_lead_row(lead_id)
    if not row:
        return None
    if row.get('merge_status') == 'merged' and row.get('merged_into_id'):
        return get_active_lead_by_id(row['merged_into_id'], _hops + 1)
    if not row.get('lead_json'):
        return None
    try:
        return _dict_to_lead(json.loads(row['lead_json']))
    except Exception:
        return None


def update_lead(lead) -> None:
    """Rewrite an existing lead's projection columns + lead_json in place
    (used after a merge re-scores/re-times the survivor)."""
    ensure_schema()
    contact = lead.contacts[0] if lead.contacts else None
    execute(
        'UPDATE multifamily_leads SET company_name=?, property_name=?, contact_name=?, contact_email=?, '
        'contact_phone=?, contact_role=?, state=?, city=?, asset_type=?, unit_count=?, lead_situation=?, '
        'primary_concern=?, notes=?, source=?, source_page=?, source_url=?, confidence=?, score_total=?, '
        'score_category=?, signal_count=?, lead_json=? WHERE id=?',
        [
            lead.company.name, lead.property.name,
            contact.full_name if contact else None, contact.email if contact else None,
            contact.phone if contact else None, contact.title if contact else None,
            lead.state, lead.city, lead.property.asset_type, lead.property.unit_count,
            _lead_situation_of(lead), lead.pain_flags[0] if lead.pain_flags else None, lead.notes,
            lead.primary_source, lead.source_page, lead.source_url, lead.confidence,
            lead.score.total if lead.score else None, lead.score.category if lead.score else None,
            len(lead.signals or []), json.dumps(dataclasses.asdict(lead)), lead.id,
        ],
    )


def mark_lead_merged(loser_id: str, survivor_id: str) -> None:
    """Tombstone a merged-away lead (reversible: merged_into_id points at
    the survivor). It stops appearing in every normal view."""
    ensure_schema()
    execute(
        "UPDATE multifamily_leads SET merge_status = 'merged', merged_into_id = ? WHERE id = ?",
        [survivor_id, loser_id],
    )


# ===========================================================================
# Outcome tracking (outcome/snapshot/notification phase)
# Append-only business-outcome events on real leads. current_outcome/
# current_outcome_at on multifamily_leads always mirror the LATEST event
# (by outcome_date, tie-broken by created_at) for cheap filtering/reporting.
# ===========================================================================

def record_outcome(
    lead_id: str, outcome_type: str, *, outcome_date: Optional[str] = None,
    estimated_premium: Optional[float] = None, estimated_revenue: Optional[float] = None,
    quoted_premium: Optional[float] = None, bound_premium: Optional[float] = None,
    effective_date: Optional[str] = None, renewal_date: Optional[str] = None,
    lost_reason: Optional[str] = None, won_reason: Optional[str] = None,
    notes: Optional[str] = None, created_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist one outcome event and refresh the lead's current_outcome
    cache to the most recent event (by outcome_date). Real leads only —
    callers must resolve a real lead id before calling this."""
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    now = utc_now_iso()
    row = {
        'id': new_id(), 'lead_id': lead_id, 'outcome_type': outcome_type,
        'outcome_date': outcome_date or now, 'estimated_premium': estimated_premium,
        'estimated_revenue': estimated_revenue, 'quoted_premium': quoted_premium,
        'bound_premium': bound_premium, 'effective_date': effective_date,
        'renewal_date': renewal_date, 'lost_reason': lost_reason, 'won_reason': won_reason,
        'notes': notes, 'created_by': (created_by or '').lower() or None, 'created_at': now,
    }
    execute(
        'INSERT INTO multifamily_lead_outcomes (id, lead_id, outcome_type, outcome_date, estimated_premium, '
        'estimated_revenue, quoted_premium, bound_premium, effective_date, renewal_date, lost_reason, won_reason, '
        'notes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    latest = get_current_outcome(lead_id)
    if latest:
        execute(
            'UPDATE multifamily_leads SET current_outcome = ?, current_outcome_at = ? WHERE id = ?',
            [latest['outcome_type'], latest['outcome_date'], lead_id],
        )
    return row


def get_outcomes_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    """All outcome events for a lead, most recent first (by outcome_date,
    then created_at, so backdated entries still sort correctly)."""
    ensure_schema()
    return fetch_all(
        'SELECT id, lead_id, outcome_type, outcome_date, estimated_premium, estimated_revenue, quoted_premium, '
        'bound_premium, effective_date, renewal_date, lost_reason, won_reason, notes, created_by, created_at '
        'FROM multifamily_lead_outcomes WHERE lead_id = ? ORDER BY outcome_date DESC, created_at DESC',
        [lead_id],
    )


def get_current_outcome(lead_id: str) -> Optional[Dict[str, Any]]:
    """The single most-recent outcome event for a lead, or None."""
    rows = get_outcomes_for_lead(lead_id)
    return rows[0] if rows else None


def get_current_outcomes_for_leads(lead_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Bulk current-outcome lookup for a batch of REAL lead ids — lets list
    views show a lead-card outcome pill without one query per lead. Returns
    only ids that actually have a current_outcome set."""
    ensure_schema()
    if not lead_ids:
        return {}
    placeholders = ', '.join(['?'] * len(lead_ids))
    rows = fetch_all(
        f'SELECT id, current_outcome, current_outcome_at FROM multifamily_leads '
        f'WHERE id IN ({placeholders}) AND current_outcome IS NOT NULL',
        lead_ids,
    )
    return {r['id']: {'outcome_type': r['current_outcome'], 'outcome_date': r['current_outcome_at']} for r in rows}


def delete_outcomes_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_lead_outcomes WHERE lead_id = ?', [lead_id])
    execute('UPDATE multifamily_leads SET current_outcome = NULL, current_outcome_at = NULL WHERE id = ?', [lead_id])


# ===========================================================================
# Score/timing snapshots (outcome/snapshot/notification phase)
# Append-only, read-only projections of already-computed score/timing/
# attribution state — never recomputes scoring math. See
# multifamily/snapshots.py for the capture logic; this module is pure CRUD.
# ===========================================================================

def insert_snapshot(
    lead_id: str, reason: str, *, score_total: Optional[int] = None, score_category: Optional[str] = None,
    reason_codes: Optional[List[str]] = None, disqualifier_codes: Optional[List[str]] = None,
    process_stage: Optional[str] = None, outreach_window: Optional[str] = None,
    timing_reason: Optional[str] = None, timing_confidence: Optional[str] = None,
    urgency_label: Optional[str] = None, signal_count: int = 0,
    attribution_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    row = {
        'id': new_id(), 'lead_id': lead_id, 'reason': reason,
        'score_total': score_total, 'score_category': score_category,
        'reason_codes': reason_codes or [], 'disqualifier_codes': disqualifier_codes or [],
        'process_stage': process_stage, 'outreach_window': outreach_window,
        'timing_reason': timing_reason, 'timing_confidence': timing_confidence,
        'urgency_label': urgency_label, 'signal_count': signal_count,
        'attribution_summary': attribution_summary or {}, 'created_at': utc_now_iso(),
    }
    execute(
        'INSERT INTO multifamily_lead_snapshots (id, lead_id, reason, score_total, score_category, '
        'reason_codes_json, disqualifier_codes_json, process_stage, outreach_window, timing_reason, '
        'timing_confidence, urgency_label, signal_count, attribution_summary_json, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
            row['id'], lead_id, reason, score_total, score_category,
            json.dumps(row['reason_codes']), json.dumps(row['disqualifier_codes']),
            process_stage, outreach_window, timing_reason, timing_confidence, urgency_label,
            signal_count, json.dumps(row['attribution_summary']), row['created_at'],
        ],
    )
    return row


def _snapshot_row_with_json(r: Dict[str, Any]) -> Dict[str, Any]:
    try:
        r['reason_codes'] = json.loads(r['reason_codes_json']) if r.get('reason_codes_json') else []
    except Exception:
        r['reason_codes'] = []
    try:
        r['disqualifier_codes'] = json.loads(r['disqualifier_codes_json']) if r.get('disqualifier_codes_json') else []
    except Exception:
        r['disqualifier_codes'] = []
    try:
        r['attribution_summary'] = json.loads(r['attribution_summary_json']) if r.get('attribution_summary_json') else {}
    except Exception:
        r['attribution_summary'] = {}
    return r


def get_snapshots_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    """Full snapshot history for a lead, newest first."""
    ensure_schema()
    rows = fetch_all(
        'SELECT id, lead_id, reason, score_total, score_category, reason_codes_json, disqualifier_codes_json, '
        'process_stage, outreach_window, timing_reason, timing_confidence, urgency_label, signal_count, '
        'attribution_summary_json, created_at FROM multifamily_lead_snapshots '
        'WHERE lead_id = ? ORDER BY created_at DESC',
        [lead_id],
    )
    return [_snapshot_row_with_json(r) for r in rows]


def get_creation_snapshot(lead_id: str) -> Optional[Dict[str, Any]]:
    """The lead's very first ('created') snapshot — the baseline used for
    calibration reporting (e.g. avg score/timing-confidence at intake)."""
    ensure_schema()
    rows = fetch_all(
        "SELECT id, lead_id, reason, score_total, score_category, reason_codes_json, disqualifier_codes_json, "
        "process_stage, outreach_window, timing_reason, timing_confidence, urgency_label, signal_count, "
        "attribution_summary_json, created_at FROM multifamily_lead_snapshots "
        "WHERE lead_id = ? AND reason = 'created' ORDER BY created_at ASC LIMIT 1",
        [lead_id],
    )
    return _snapshot_row_with_json(rows[0]) if rows else None


def get_creation_snapshots_for_leads(lead_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Bulk creation-snapshot ('created' reason) lookup for a batch of lead
    ids — one query instead of one per lead, for the source-ROI report's
    avg-score/avg-timing-confidence-at-creation metrics."""
    ensure_schema()
    if not lead_ids:
        return {}
    placeholders = ', '.join(['?'] * len(lead_ids))
    rows = fetch_all(
        f"SELECT id, lead_id, reason, score_total, score_category, reason_codes_json, disqualifier_codes_json, "
        f"process_stage, outreach_window, timing_reason, timing_confidence, urgency_label, signal_count, "
        f"attribution_summary_json, created_at FROM multifamily_lead_snapshots "
        f"WHERE lead_id IN ({placeholders}) AND reason = 'created' ORDER BY created_at ASC",
        lead_ids,
    )
    result: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if r['lead_id'] not in result:  # ascending order -> first write wins
            result[r['lead_id']] = _snapshot_row_with_json(r)
    return result


def delete_snapshots_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_lead_snapshots WHERE lead_id = ?', [lead_id])


# ===========================================================================
# In-app notifications (outcome/snapshot/notification phase)
# No external email/SMS — an in-app queue only. See multifamily/
# notifications.py for emit()/sweep() (the business logic); this module is
# pure CRUD. `dedupe_key` is UNIQUE, so insert_notification() is naturally
# idempotent via INSERT OR IGNORE.
# ===========================================================================

def _notification_row_with_json(r: Dict[str, Any]) -> Dict[str, Any]:
    try:
        r['metadata'] = json.loads(r['metadata_json']) if r.get('metadata_json') else {}
    except Exception:
        r['metadata'] = {}
    r['is_read'] = bool(r.get('read_at'))
    return r


def insert_notification(
    type_: str, *, title: str, message: str, lead_id: Optional[str] = None, severity: str = 'info',
    action_url: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None, dedupe_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Insert one notification. If `dedupe_key` already exists, this is a
    no-op (INSERT OR IGNORE) and returns None so callers can tell a fresh
    notification was NOT created."""
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    row_id = new_id()
    now = utc_now_iso()
    execute(
        'INSERT OR IGNORE INTO multifamily_notifications '
        '(id, type, lead_id, severity, title, message, action_url, metadata_json, dedupe_key, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [row_id, type_, lead_id, severity, title, message, action_url, json.dumps(metadata or {}), dedupe_key, now],
    )
    if dedupe_key:
        rows = fetch_all('SELECT * FROM multifamily_notifications WHERE dedupe_key = ?', [dedupe_key])
        if not rows or rows[0]['id'] != row_id:
            return None  # a notification with this dedupe_key already existed
        return _notification_row_with_json(rows[0])
    rows = fetch_all('SELECT * FROM multifamily_notifications WHERE id = ?', [row_id])
    return _notification_row_with_json(rows[0]) if rows else None


def get_notifications(unread_only: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = 'SELECT * FROM multifamily_notifications'
    if unread_only:
        sql += ' WHERE read_at IS NULL'
    sql += ' ORDER BY created_at DESC LIMIT ?'
    rows = fetch_all(sql, [limit])
    return [_notification_row_with_json(r) for r in rows]


def count_unread_notifications() -> int:
    ensure_schema()
    rows = fetch_all('SELECT COUNT(*) AS n FROM multifamily_notifications WHERE read_at IS NULL')
    return int(rows[0]['n']) if rows else 0


def mark_notification_read(notification_id: str) -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute(
        'UPDATE multifamily_notifications SET read_at = ? WHERE id = ? AND read_at IS NULL',
        [utc_now_iso(), notification_id],
    )


def mark_all_notifications_read() -> None:
    ensure_schema()
    from multifamily.types import utc_now_iso
    execute('UPDATE multifamily_notifications SET read_at = ? WHERE read_at IS NULL', [utc_now_iso()])


def count_recent_events_global(event_types: List[str], since_iso: str) -> int:
    """System-wide count of intake events of the given type(s) since a
    timestamp (unlike count_recent_events, not scoped to one ip/email) —
    used for the spam/rate-limit-spike notification."""
    ensure_schema()
    placeholders = ', '.join(['?'] * len(event_types))
    rows = fetch_all(
        f'SELECT COUNT(*) AS n FROM multifamily_intake_events WHERE event_type IN ({placeholders}) AND created_at >= ?',
        list(event_types) + [since_iso],
    )
    return int(rows[0]['n']) if rows else 0


def delete_notifications_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_notifications WHERE lead_id = ?', [lead_id])


def delete_notification(notification_id: str) -> None:
    """Used by tests to clean up after themselves."""
    ensure_schema()
    execute('DELETE FROM multifamily_notifications WHERE id = ?', [notification_id])


# ===========================================================================
# Source ROI + calibration readiness (outcome/snapshot/notification phase)
# Additive to get_source_performance() (lead-count/signal-count view) —
# this reports outcomes/revenue/quality by source, and a descriptive
# (no-ML) dataset for future calibration once real lead history exists.
# ===========================================================================

_ROI_DIMENSIONS = [
    'source', 'source_page', 'offer_type', 'utm_source', 'utm_campaign',
    'first_touch_source', 'conversion_source', 'latest_signal_source',
    # Funnel Phase 6: which offer page + outreach campaign drove the lead
    # (distinct from utm_campaign, which is UTM-parameter-based and
    # applies to any source, not just the funnel's own offer pages).
    'page_variant', 'campaign_id',
]

# high=1.0/medium=0.5/low=0.0 — timing_confidence is a label
# (multifamily/timing/process_stage_detector.py's _confidence()), so
# "average timing confidence" needs a numeric mapping to average.
_TIMING_CONFIDENCE_SCORE = {'high': 1.0, 'medium': 0.5, 'low': 0.0}

_SCORE_BANDS = [('90-100', 90, 100), ('75-89', 75, 89), ('60-74', 60, 74), ('40-59', 40, 59), ('0-39', 0, 39)]


def _attribution_touch_sources_by_lead() -> Dict[str, Dict[str, Optional[str]]]:
    """For every lead_id, derive first_touch_source/conversion_source from
    the append-only attribution history — the same rule
    get_attribution_summary() applies per-lead, batched here so the ROI
    report isn't N queries for N leads."""
    ensure_schema()
    rows = fetch_all(
        'SELECT lead_id, source, occurred_at FROM multifamily_source_attribution ORDER BY lead_id, occurred_at ASC'
    )
    by_lead: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_lead.setdefault(r['lead_id'], []).append(r)
    result: Dict[str, Dict[str, Optional[str]]] = {}
    for lead_id, touches in by_lead.items():
        first = touches[0]
        conversion = next((t for t in touches if t.get('source') in _CONVERSION_SOURCES), first)
        result[lead_id] = {'first_touch_source': first.get('source'), 'conversion_source': conversion.get('source')}
    return result


def _latest_signal_source_by_lead() -> Dict[str, str]:
    """Most recent real, non-rejected signal's source, per lead."""
    ensure_schema()
    rows = fetch_all(
        "SELECT lead_id, source, occurred_at FROM multifamily_signals "
        "WHERE is_demo = 0 AND spam_status != 'rejected' ORDER BY lead_id, occurred_at ASC"
    )
    result: Dict[str, str] = {}
    for r in rows:
        if r.get('source'):
            result[r['lead_id']] = r['source']  # ascending order -> last write wins
    return result


def _outcome_rollup_by_lead() -> Dict[str, Dict[str, Any]]:
    """Per lead: the set of outcome types EVER reached (for funnel
    milestone counts — "did this lead ever hit quote_sent", not "how many
    times") plus the max estimated_revenue/bound_premium ever recorded on
    it (the most defensible single number without double-counting a
    history that may set the same field more than once)."""
    ensure_schema()
    rows = fetch_all('SELECT lead_id, outcome_type, estimated_revenue, bound_premium FROM multifamily_lead_outcomes')
    result: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        entry = result.setdefault(r['lead_id'], {'types': set(), 'estimated_revenue': None, 'bound_premium': None})
        entry['types'].add(r['outcome_type'])
        if r.get('estimated_revenue') is not None:
            entry['estimated_revenue'] = max(entry['estimated_revenue'] or 0, r['estimated_revenue'])
        if r.get('bound_premium') is not None:
            entry['bound_premium'] = max(entry['bound_premium'] or 0, r['bound_premium'])
    return result


def _new_roi_bucket() -> Dict[str, Any]:
    return {
        'leads_created': 0, 'signals_received': 0, 'hot_or_call_today_leads': 0,
        'meetings_booked': 0, 'submissions_received': 0, 'quotes_started': 0, 'quotes_sent': 0,
        'wins': 0, 'losses': 0, 'estimated_revenue': 0.0, 'bound_premium': 0.0,
        'duplicate_or_merged_leads': 0,
        '_total_incl_rejected': 0, '_rejected': 0, '_score_sum': 0.0, '_score_n': 0,
        '_timing_sum': 0.0, '_timing_n': 0,
    }


def _finalize_roi_bucket(b: Dict[str, Any]) -> Dict[str, Any]:
    total_incl_rejected = b.pop('_total_incl_rejected')
    rejected = b.pop('_rejected')
    score_sum, score_n = b.pop('_score_sum'), b.pop('_score_n')
    timing_sum, timing_n = b.pop('_timing_sum'), b.pop('_timing_n')
    leads = b['leads_created']
    b['spam_rate_pct'] = round(100.0 * rejected / total_incl_rejected, 1) if total_incl_rejected else 0.0
    b['duplicate_or_merge_rate_pct'] = round(100.0 * b['duplicate_or_merged_leads'] / leads, 1) if leads else 0.0
    b['avg_score_at_creation'] = round(score_sum / score_n, 1) if score_n else None
    b['avg_timing_confidence'] = round(timing_sum / timing_n, 2) if timing_n else None
    b['estimated_revenue'] = round(b['estimated_revenue'], 2)
    b['bound_premium'] = round(b['bound_premium'], 2)
    return b


def get_source_roi() -> Dict[str, Any]:
    """Outcome-aware ROI report, grouped by 10 dimensions (source,
    source_page, offer_type, utm_source, utm_campaign, first_touch_source,
    conversion_source, latest_signal_source, page_variant, campaign_id).
    Real leads only
    (non-merged-away); rejected leads count toward spam_rate_pct's
    denominator only — never toward any funnel/revenue/quality metric.
    `duplicate_or_merge_rate_pct` = share of leads in the bucket that
    absorbed >1 signal (signal_count > 1), i.e. survived at least one
    merge — covers both the on-intake auto-merge path and the
    admin-confirmed match-candidate merge uniformly, since both raise a
    survivor's signal_count."""
    ensure_schema()
    rows = fetch_all(
        "SELECT id, source, source_page, offer_type, utm_source, utm_campaign, score_category, "
        "signal_count, spam_status, page_variant, campaign_id FROM multifamily_leads WHERE is_demo = 0 "
        "AND (merge_status IS NULL OR merge_status != 'merged')"
    )
    touch_sources = _attribution_touch_sources_by_lead()
    latest_signal_source = _latest_signal_source_by_lead()
    outcomes = _outcome_rollup_by_lead()
    creation = get_creation_snapshots_for_leads([r['id'] for r in rows])

    def _dim_value(row: Dict[str, Any], dim: str) -> str:
        if dim == 'first_touch_source':
            v = touch_sources.get(row['id'], {}).get('first_touch_source')
        elif dim == 'conversion_source':
            v = touch_sources.get(row['id'], {}).get('conversion_source')
        elif dim == 'latest_signal_source':
            v = latest_signal_source.get(row['id'])
        else:
            v = row.get(dim)
        return v or 'unknown'

    _OUTCOME_FIELD_MAP = (
        ('meeting_booked', 'meetings_booked'), ('submission_received', 'submissions_received'),
        ('quote_started', 'quotes_started'), ('quote_sent', 'quotes_sent'), ('won', 'wins'), ('lost', 'losses'),
    )

    report: Dict[str, Any] = {}
    for dim in _ROI_DIMENSIONS:
        buckets: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            b = buckets.setdefault(_dim_value(row, dim), _new_roi_bucket())
            b['_total_incl_rejected'] += 1
            if row.get('spam_status') == 'rejected':
                b['_rejected'] += 1
                continue  # rejected leads never count as a valid lead beyond the spam-rate denominator
            b['leads_created'] += 1
            b['signals_received'] += row.get('signal_count') or 0
            if row.get('score_category') in ('hot', 'call_today'):
                b['hot_or_call_today_leads'] += 1
            if (row.get('signal_count') or 0) > 1:
                b['duplicate_or_merged_leads'] += 1
            o = outcomes.get(row['id'])
            if o:
                for outcome_type, field in _OUTCOME_FIELD_MAP:
                    if outcome_type in o['types']:
                        b[field] += 1
                if o.get('estimated_revenue'):
                    b['estimated_revenue'] += o['estimated_revenue']
                if o.get('bound_premium'):
                    b['bound_premium'] += o['bound_premium']
            snap = creation.get(row['id'])
            if snap:
                if snap.get('score_total') is not None:
                    b['_score_sum'] += snap['score_total']
                    b['_score_n'] += 1
                tc = _TIMING_CONFIDENCE_SCORE.get(snap.get('timing_confidence'))
                if tc is not None:
                    b['_timing_sum'] += tc
                    b['_timing_n'] += 1
        report[dim] = {key: _finalize_roi_bucket(b) for key, b in buckets.items()}
    return report


def _score_band(total: Optional[int]) -> str:
    if total is None:
        return 'unknown'
    for label, lo, hi in _SCORE_BANDS:
        if lo <= total <= hi:
            return label
    return 'unknown'


def get_calibration_dataset() -> Dict[str, Any]:
    """Descriptive-only foundation for future calibration (NO machine
    learning — counts and rates only). Joins each real lead's creation
    snapshot (score/timing baseline, frozen at intake) with its outcome
    history and activity log to surface:
      - score_band_meeting_or_win_rate: which score bands actually
        produce a meeting or a win
      - timing_stage_reply_rate: which process stages produce replies
      - process_stage_win_rate: which process stages actually close
      - revenue_by_source: which source creates the most estimated
        revenue / bound premium
      - disqualifier_code_outcome_mix: how leads carrying each
        disqualifier code eventually resolve — a disqualifier code with a
        high won-rate is a candidate for being "too strict"
    """
    ensure_schema()
    rows = fetch_all(
        "SELECT id, source FROM multifamily_leads WHERE is_demo = 0 AND spam_status != 'rejected' "
        "AND (merge_status IS NULL OR merge_status != 'merged')"
    )
    lead_ids = [r['id'] for r in rows]
    source_by_lead = {r['id']: (r['source'] or 'unknown') for r in rows}
    creation = get_creation_snapshots_for_leads(lead_ids)
    outcomes = _outcome_rollup_by_lead()
    replied_leads = {
        r['lead_id'] for r in fetch_all("SELECT DISTINCT lead_id FROM multifamily_activities WHERE activity_type = 'replied'")
    }

    score_band_stats: Dict[str, Dict[str, int]] = {}
    timing_stage_stats: Dict[str, Dict[str, int]] = {}
    process_stage_stats: Dict[str, Dict[str, int]] = {}
    source_revenue: Dict[str, float] = {}
    disqualifier_outcome_mix: Dict[str, Dict[str, int]] = {}

    for lead_id in lead_ids:
        snap = creation.get(lead_id)
        o = outcomes.get(lead_id, {'types': set(), 'estimated_revenue': None, 'bound_premium': None})
        types = o['types']
        won_or_meeting = bool(types & {'meeting_booked', 'won'})
        replied = lead_id in replied_leads
        stage = (snap or {}).get('process_stage') or 'unknown'

        bs = score_band_stats.setdefault(_score_band((snap or {}).get('score_total')), {'leads': 0, 'meetings_or_wins': 0})
        bs['leads'] += 1
        bs['meetings_or_wins'] += int(won_or_meeting)

        ts = timing_stage_stats.setdefault(stage, {'leads': 0, 'replies': 0})
        ts['leads'] += 1
        ts['replies'] += int(replied)

        pc = process_stage_stats.setdefault(stage, {'leads': 0, 'wins': 0})
        pc['leads'] += 1
        pc['wins'] += int('won' in types)

        src = source_by_lead.get(lead_id, 'unknown')
        revenue = (o.get('estimated_revenue') or 0) + (o.get('bound_premium') or 0)
        if revenue:
            source_revenue[src] = source_revenue.get(src, 0.0) + revenue

        for code in ((snap or {}).get('disqualifier_codes') or []):
            outcome_label = 'no_outcome_yet'
            if 'won' in types:
                outcome_label = 'won'
            elif 'lost' in types:
                outcome_label = 'lost'
            elif 'not_a_fit' in types:
                outcome_label = 'not_a_fit'
            elif 'dead' in types:
                outcome_label = 'dead'
            elif types:
                outcome_label = 'in_progress'
            dm = disqualifier_outcome_mix.setdefault(code, {})
            dm[outcome_label] = dm.get(outcome_label, 0) + 1

    def _with_rate(stats: Dict[str, Dict[str, int]], numerator_key: str, denom_key: str) -> Dict[str, Dict[str, Any]]:
        return {
            key: {**v, 'rate_pct': round(100.0 * v[numerator_key] / v[denom_key], 1) if v[denom_key] else 0.0}
            for key, v in stats.items()
        }

    return {
        'score_band_meeting_or_win_rate': _with_rate(score_band_stats, 'meetings_or_wins', 'leads'),
        'timing_stage_reply_rate': _with_rate(timing_stage_stats, 'replies', 'leads'),
        'process_stage_win_rate': _with_rate(process_stage_stats, 'wins', 'leads'),
        'revenue_by_source': {k: round(v, 2) for k, v in source_revenue.items()},
        'disqualifier_code_outcome_mix': disqualifier_outcome_mix,
        'sample_size': len(lead_ids),
    }


# ===========================================================================
# Sales Intelligence decision log (NEPQ-based reasoning engine)
# Append-only, real-leads-only. See multifamily/sales_intelligence/engine.py
# for the reasoning logic; this module is pure CRUD, matching the
# snapshot/outcome/notification tables' pattern.
# ===========================================================================

def log_sales_intelligence_event(
    lead_id: str, *, variant: int = 0, lead_temperature: Optional[str] = None, lead_origin: Optional[str] = None,
    insurance_scenario: Optional[str] = None, buyer_awareness_level: Optional[str] = None,
    resistance_risk: Optional[str] = None, nepq_stage: Optional[str] = None,
    recommended_action: Optional[str] = None, confidence_score: Optional[float] = None,
    reasoning: Optional[Dict[str, Any]] = None, conversation_mode: Optional[str] = None,
    follow_up_type: Optional[str] = None, guardrail_status: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    row_id = new_id()
    now = utc_now_iso()
    execute(
        'INSERT INTO multifamily_sales_intelligence_events '
        '(id, lead_id, variant, lead_temperature, lead_origin, insurance_scenario, buyer_awareness_level, '
        'resistance_risk, nepq_stage, recommended_action, confidence_score, reasoning_json, '
        'conversation_mode, follow_up_type, guardrail_status, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
            row_id, lead_id, variant, lead_temperature, lead_origin, insurance_scenario, buyer_awareness_level,
            resistance_risk, nepq_stage, recommended_action, confidence_score, json.dumps(reasoning or {}),
            conversation_mode, follow_up_type, guardrail_status, now,
        ],
    )
    return {
        'id': row_id, 'lead_id': lead_id, 'variant': variant, 'lead_temperature': lead_temperature,
        'lead_origin': lead_origin, 'insurance_scenario': insurance_scenario,
        'buyer_awareness_level': buyer_awareness_level, 'resistance_risk': resistance_risk,
        'nepq_stage': nepq_stage, 'recommended_action': recommended_action, 'confidence_score': confidence_score,
        'reasoning': reasoning or {}, 'conversation_mode': conversation_mode, 'follow_up_type': follow_up_type,
        'guardrail_status': guardrail_status, 'created_at': now,
    }


def _sales_intelligence_row_with_json(r: Dict[str, Any]) -> Dict[str, Any]:
    try:
        r['reasoning'] = json.loads(r['reasoning_json']) if r.get('reasoning_json') else {}
    except Exception:
        r['reasoning'] = {}
    return r


def get_sales_intelligence_history(lead_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(
        'SELECT id, lead_id, variant, lead_temperature, lead_origin, insurance_scenario, buyer_awareness_level, '
        'resistance_risk, nepq_stage, recommended_action, confidence_score, reasoning_json, '
        'conversation_mode, follow_up_type, guardrail_status, created_at '
        'FROM multifamily_sales_intelligence_events WHERE lead_id = ? ORDER BY created_at DESC',
        [lead_id],
    )
    return [_sales_intelligence_row_with_json(r) for r in rows]


def get_latest_sales_intelligence_event(lead_id: str) -> Optional[Dict[str, Any]]:
    rows = get_sales_intelligence_history(lead_id)
    return rows[0] if rows else None


def delete_sales_intelligence_events_for_lead(lead_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_sales_intelligence_events WHERE lead_id = ?', [lead_id])
