"""
Persistence layer for REAL (non-demo) multifamily leads.

Mock/demo leads stay exactly where they were (multifamily/signal_collectors/),
generated fresh in-memory on every pipeline run. Real leads — captured
through POST /api/multifamily/leads — are durable: this module owns the
`multifamily_leads` table and is the only place that reads/writes it.

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
from typing import List

from shared.database import fetch_all, execute

from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty,
    MultifamilyContact, MultifamilySignal, MultifamilyLeadScore,
)

_SCHEMA_READY = False


def ensure_schema() -> None:
    """Idempotent CREATE TABLE — safe to call on every import/request."""
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
    try:
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_created ON multifamily_leads(created_at DESC)')
        execute('CREATE INDEX IF NOT EXISTS idx_multifamily_leads_state ON multifamily_leads(state)')
    except Exception:
        pass
    _SCHEMA_READY = True


def _lead_situation_of(lead: MultifamilyLead) -> str:
    for signal in lead.signals:
        if signal.detail and signal.detail.get('lead_situation'):
            return signal.detail['lead_situation']
    return ''


def insert_lead(lead: MultifamilyLead) -> None:
    """Persist a fully-built, already-scored real lead."""
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
    pipeline.py as in-memory mock leads."""
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


def get_real_leads() -> List[MultifamilyLead]:
    """Return every persisted real (non-demo) lead, newest first."""
    ensure_schema()
    rows = fetch_all('SELECT lead_json FROM multifamily_leads ORDER BY created_at DESC')
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
