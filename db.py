"""
Centralized database connection module.

If DATABASE_URL is set (Railway Postgres), uses psycopg2.
Otherwise falls back to local SQLite for development.

Usage:
    from db import get_db, is_postgres

Every caller gets a connection object that supports:
    conn.cursor(), conn.commit(), conn.close()
    cursor.execute(sql, params), cursor.fetchone(), cursor.fetchall()

The module automatically translates SQLite-style '?' placeholders to
PostgreSQL-style '%s' when running against Postgres.
"""
import os
import re
import sqlite3

DATABASE_URL = os.getenv('DATABASE_URL', '')
_use_postgres = bool(DATABASE_URL and DATABASE_URL.startswith('postgres'))


def is_postgres():
    """Return True if connected to PostgreSQL via DATABASE_URL."""
    return _use_postgres


def _log_db_info():
    """Print DB connection info at startup (no secrets)."""
    if _use_postgres:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(DATABASE_URL)
            host = parsed.hostname or 'unknown'
            port = parsed.port or 5432
            dbname = (parsed.path or '').lstrip('/')
            print(f"[DB] Connected: postgres @ {host}:{port}/{dbname}")
        except Exception:
            print("[DB] Connected: postgres (URL parse failed)")
    else:
        print("[DB] Connected: sqlite (prospects.db) — local/dev mode")


# --- SQL translation ---

_INSERT_OR_IGNORE_RE = re.compile(r'INSERT\s+OR\s+IGNORE\s+INTO', re.IGNORECASE)


def _translate_sql(sql):
    """
    Translate SQLite SQL to PostgreSQL SQL:
    - '?' placeholders -> '%s'
    - INSERT OR IGNORE INTO -> INSERT INTO ... ON CONFLICT DO NOTHING
    - Skip PRAGMA statements
    """
    if not _use_postgres:
        return sql

    # Handle INSERT OR IGNORE -> INSERT ... ON CONFLICT DO NOTHING
    had_or_ignore = bool(_INSERT_OR_IGNORE_RE.search(sql))
    if had_or_ignore:
        sql = _INSERT_OR_IGNORE_RE.sub('INSERT INTO', sql)

    # Replace ? with %s, but not inside quoted strings
    result = []
    in_single_quote = False
    in_double_quote = False
    for ch in sql:
        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            result.append(ch)
        elif ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            result.append(ch)
        elif ch == '?' and not in_single_quote and not in_double_quote:
            result.append('%s')
        else:
            result.append(ch)

    translated = ''.join(result)

    # Append ON CONFLICT DO NOTHING for former INSERT OR IGNORE
    if had_or_ignore and 'ON CONFLICT' not in translated.upper():
        translated = translated.rstrip().rstrip(';') + ' ON CONFLICT DO NOTHING'

    return translated


# --- Cursor / Connection wrappers ---

class _PgCursorWrapper:
    """Wraps a psycopg2 cursor to accept SQLite-style '?' placeholders."""

    def __init__(self, real_cursor):
        self._cur = real_cursor

    def execute(self, sql, params=None):
        sql = _translate_sql(sql)
        if params:
            self._cur.execute(sql, params)
        else:
            self._cur.execute(sql)

    def executemany(self, sql, seq_of_params):
        sql = _translate_sql(sql)
        self._cur.executemany(sql, seq_of_params)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    @property
    def lastrowid(self):
        return getattr(self._cur, 'lastrowid', None)

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description


class _PgConnectionWrapper:
    """Wraps a psycopg2 connection to provide SQLite-compatible interface."""

    def __init__(self, real_conn):
        self._conn = real_conn

    def cursor(self):
        return _PgCursorWrapper(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def execute(self, sql, params=None):
        """Direct execute (used for PRAGMAs which are no-ops on PG)."""
        sql_lower = sql.strip().lower()
        # Skip SQLite-specific PRAGMAs
        if sql_lower.startswith('pragma'):
            return
        cur = self.cursor()
        cur.execute(sql, params)
        return cur


# --- Public API ---

def get_db():
    """
    Get a database connection.
    - If DATABASE_URL is set: returns a psycopg2 connection (wrapped)
    - Otherwise: returns a sqlite3 connection with WAL mode
    """
    if _use_postgres:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        return _PgConnectionWrapper(conn)
    else:
        conn = sqlite3.connect('prospects.db')
        conn.execute("PRAGMA journal_mode=WAL")
        return conn


# Print DB info once at import time
_log_db_info()
