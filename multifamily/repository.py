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

    try:
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_created ON multifamily_leads(created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_state ON multifamily_leads(state)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_spam_status ON multifamily_leads(spam_status)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_events_ip_created ON multifamily_intake_events(ip_hash, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_events_email_created ON multifamily_intake_events(email, created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_events_type_created ON multifamily_intake_events(event_type, created_at DESC)')
    except Exception:
        pass
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
    sql = 'SELECT lead_json FROM multifamily_leads'
    if not include_rejected:
        sql += " WHERE spam_status != 'rejected'"
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
