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
    ss_profile_context    — manually imported LinkedIn profile context
    ss_social_principles  — social-selling knowledge layer
    ss_message_metadata   — grounding/strategy metadata for messages
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
    CREATE TABLE IF NOT EXISTS ss_profile_context (
        id TEXT PRIMARY KEY,
        prospect_id TEXT NOT NULL,
        linkedin_url TEXT,
        headline TEXT,
        about_text TEXT,
        current_role TEXT,
        current_company TEXT,
        prior_roles_summary TEXT,
        featured_topics TEXT,
        recent_posts_summary TEXT,
        notable_language_patterns TEXT,
        shared_context TEXT,
        manual_observations TEXT,
        safe_flags TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_social_principles (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        principle_name TEXT NOT NULL,
        description TEXT NOT NULL,
        practical_use_case TEXT,
        allowed_contexts TEXT,
        disallowed_contexts TEXT,
        example_pattern TEXT,
        anti_pattern TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ss_message_metadata (
        message_id TEXT PRIMARY KEY,
        facts_used_json TEXT,
        signals_used_json TEXT,
        notes_used_json TEXT,
        profile_fields_used_json TEXT,
        grounding_score REAL,
        unsafe_claims_json TEXT,
        validator_notes TEXT,
        strategy_json TEXT,
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
    "CREATE INDEX IF NOT EXISTS ix_ss_profile_prospect ON ss_profile_context(prospect_id)",
    "CREATE INDEX IF NOT EXISTS ix_ss_principles_active ON ss_social_principles(active)",
]


def init_schema() -> None:
    """Create all SignalStack tables if they don't exist. Idempotent.

    Each statement is committed independently so a single failure (e.g.
    a pre-existing table with a slightly different shape on Postgres)
    cannot abort the whole transaction and leave later tables missing.
    """
    created = 0
    failed = 0
    for stmt in SCHEMA_SQL + INDEXES_SQL:
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(stmt)
            conn.commit()
            created += 1
        except Exception as e:
            failed += 1
            try:
                conn.rollback()
            except Exception:
                pass
            print(f"[SignalStack] schema stmt failed: {e}\n  SQL: {stmt[:120]}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
    print(f"[SignalStack] Schema initialized ({'postgres' if is_postgres() else 'sqlite'}) — {created} ok, {failed} failed")
    # Idempotent seeding of the social-selling knowledge layer.
    try:
        from .seed import seed_principles_if_empty
        seed_principles_if_empty()
    except Exception as e:
        print(f"[SignalStack] principle seed skipped: {e}")
