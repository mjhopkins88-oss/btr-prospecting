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
            created_at TIMESTAMP
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
    except Exception:
        pass

    # A match candidate references both the incoming lead and the existing
    # candidate lead (added after the table's initial create).
    _safe_add_column('multifamily_lead_match_candidates', 'incoming_lead_id', 'TEXT')

    _backfill_signals_from_lead_json()
    _SCHEMA_READY = True


def _lead_situation_of(lead: MultifamilyLead) -> str:
    for signal in lead.signals:
        if signal.detail and signal.detail.get('lead_situation'):
            return signal.detail['lead_situation']
    return ''


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

    return {
        'total_real_leads': total_real_leads,
        'leads_by_source': leads_by_source,
        'leads_by_source_page': leads_by_source_page,
        'leads_by_offer_type': leads_by_offer_type,
        'leads_by_campaign': leads_by_campaign,
        'by_source_category': by_source_category,
        'call_today_by_source': call_today_by_source,
        'spam_rate_by_source': spam_rate_by_source,
        'best_landing_page': best_landing_page,
        'worst_source': worst_source,
        'leads_missing_attribution': leads_missing_attribution,
        # Phase C signal-history view.
        'total_signals': total_signal_rows,
        'signals_by_source': signals_by_source,
        'signals_by_type': signals_by_type,
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
                       occurred_at: Optional[str] = None) -> Dict[str, Any]:
    ensure_schema()
    from multifamily.types import new_id, utc_now_iso
    now = utc_now_iso()
    row = {
        'id': new_id(), 'lead_id': lead_id, 'touch_type': touch_type, 'source': source,
        'utm_source': utm_source, 'utm_medium': utm_medium, 'utm_campaign': utm_campaign,
        'utm_term': utm_term, 'utm_content': utm_content, 'referrer': referrer,
        'landing_page': landing_page, 'offer_type': offer_type,
        'occurred_at': occurred_at or now, 'created_at': now,
    }
    execute(
        'INSERT INTO multifamily_source_attribution (id, lead_id, touch_type, source, utm_source, utm_medium, '
        'utm_campaign, utm_term, utm_content, referrer, landing_page, offer_type, occurred_at, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        list(row.values()),
    )
    return row


def record_lead_attribution_touch(lead, touch_type: str = 'touch') -> None:
    """Record one attribution touch from a lead's current source/UTM fields."""
    record_attribution(
        lead.id, touch_type, source=lead.primary_source,
        utm_source=lead.utm_source, utm_medium=lead.utm_medium, utm_campaign=lead.utm_campaign,
        utm_term=lead.utm_term, utm_content=lead.utm_content, referrer=lead.referrer,
        landing_page=lead.landing_page, offer_type=lead.offer_type, occurred_at=lead.last_verified_at,
    )


def get_attribution_for_lead(lead_id: str) -> List[Dict[str, Any]]:
    ensure_schema()
    return fetch_all(
        'SELECT id, lead_id, touch_type, source, utm_source, utm_medium, utm_campaign, utm_term, utm_content, '
        'referrer, landing_page, offer_type, occurred_at, created_at FROM multifamily_source_attribution '
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


def get_source_runs(limit: int = 50) -> List[Dict[str, Any]]:
    ensure_schema()
    rows = fetch_all(
        'SELECT id, source, run_id, started_at, finished_at, status, records_found, records_created, '
        'records_updated, records_merged, records_rejected, errors_json, warnings_json, created_at '
        'FROM multifamily_source_runs ORDER BY created_at DESC LIMIT ?',
        [limit],
    )
    for r in rows:
        for k in ('errors_json', 'warnings_json'):
            try:
                r[k.replace('_json', '')] = json.loads(r[k]) if r.get(k) else []
            except Exception:
                r[k.replace('_json', '')] = []
    return rows


def delete_source_run(run_db_id: str) -> None:
    ensure_schema()
    execute('DELETE FROM multifamily_source_runs WHERE id = ?', [run_db_id])


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
