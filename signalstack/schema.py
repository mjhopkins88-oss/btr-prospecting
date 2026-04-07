"""
SignalStack database schema.

Designed to be SQLite- and Postgres-compatible via the project's db.py
translation layer. We use TEXT for IDs (uuid strings) for portability,
TEXT for timestamps (ISO8601), and INTEGER for booleans/counts.

Tables:
    ss_companies          — company intelligence
    ss_prospects          — people / contacts (linked to optional company)
    ss_signals            — structured, source-attributed facts
    ss_notes              — free-form notes attached to prospect or company
    ss_tags               — tag dictionary
    ss_prospect_tags      — many-to-many
    ss_messages           — generated / saved / sent messages
    ss_message_signals    — which signals each message used (grounding trail)
    ss_message_outcomes   — outcome events (one prospect can have many)
    ss_prompt_templates   — versioned prompt templates
"""
from db import get_db, is_postgres


# Use TEXT everywhere; portable across SQLite + Postgres.
SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS ss_companies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        website TEXT,
        industry TEXT,
        location TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_prospects (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        linkedin_url TEXT,
        company_id TEXT,
        company_name TEXT,
        title TEXT,
        industry TEXT,
        location TEXT,
        status TEXT NOT NULL DEFAULT 'new',
        warmth INTEGER NOT NULL DEFAULT 0,
        last_contacted_at TEXT,
        notes TEXT,
        owner_user_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_signals (
        id TEXT PRIMARY KEY,
        prospect_id TEXT,
        company_id TEXT,
        type TEXT NOT NULL,
        source TEXT NOT NULL,
        text TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 0.7,
        safe_to_reference INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_notes (
        id TEXT PRIMARY KEY,
        prospect_id TEXT,
        company_id TEXT,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_tags (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_prospect_tags (
        prospect_id TEXT NOT NULL,
        tag_id TEXT NOT NULL,
        PRIMARY KEY (prospect_id, tag_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_messages (
        id TEXT PRIMARY KEY,
        prospect_id TEXT NOT NULL,
        body TEXT NOT NULL,
        rationale TEXT,
        message_type TEXT,
        primary_trigger TEXT,
        communication_style TEXT,
        outreach_goal TEXT,
        channel TEXT,
        status TEXT NOT NULL DEFAULT 'draft',
        sent_at TEXT,
        grounding_score REAL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_message_signals (
        message_id TEXT NOT NULL,
        signal_id TEXT NOT NULL,
        PRIMARY KEY (message_id, signal_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_message_outcomes (
        id TEXT PRIMARY KEY,
        message_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        notes TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_prompt_templates (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        body TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """,
]

INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS ix_ss_prospects_status ON ss_prospects(status)",
    "CREATE INDEX IF NOT EXISTS ix_ss_prospects_company ON ss_prospects(company_id)",
    "CREATE INDEX IF NOT EXISTS ix_ss_signals_prospect ON ss_signals(prospect_id)",
    "CREATE INDEX IF NOT EXISTS ix_ss_signals_company ON ss_signals(company_id)",
    "CREATE INDEX IF NOT EXISTS ix_ss_messages_prospect ON ss_messages(prospect_id)",
    "CREATE INDEX IF NOT EXISTS ix_ss_messages_status ON ss_messages(status)",
]


def init_schema() -> None:
    """Create all SignalStack tables if they don't exist. Idempotent."""
    conn = get_db()
    try:
        cur = conn.cursor()
        for stmt in SCHEMA_SQL:
            cur.execute(stmt)
        for stmt in INDEXES_SQL:
            cur.execute(stmt)
        conn.commit()
        print(f"[SignalStack] Schema initialized ({'postgres' if is_postgres() else 'sqlite'})")
    finally:
        conn.close()
