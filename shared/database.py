"""
Database helpers for the Lead Intelligence Platform.
Re-exports the core connection from db.py and adds entity-graph helpers.
"""
import uuid
from datetime import datetime
from db import get_db, is_postgres, IntegrityError


def new_id():
    """Generate a new UUID string for entity-graph primary keys."""
    return str(uuid.uuid4())


def now_ts():
    """UTC timestamp for created_at / updated_at fields."""
    return datetime.utcnow().isoformat()


def upsert_entity(table, conflict_cols, data):
    """
    Insert a row into an entity-graph table.  On conflict (by conflict_cols),
    update the non-conflict columns.

    Args:
        table: table name (e.g. 'li_companies')
        conflict_cols: list of column names forming the unique constraint
        data: dict of column->value pairs
    Returns:
        The id of the inserted/updated row, or None.
    """
    conn = get_db()
    cur = conn.cursor()
    cols = list(data.keys())
    vals = list(data.values())
    placeholders = ', '.join(['?'] * len(vals))
    col_str = ', '.join(cols)

    update_cols = [c for c in cols if c not in conflict_cols and c != 'id']
    if is_postgres():
        conflict_str = ', '.join(conflict_cols)
        if update_cols:
            set_clause = ', '.join(f'{c} = EXCLUDED.{c}' for c in update_cols)
            sql = (f"INSERT INTO {table} ({col_str}) VALUES ({placeholders}) "
                   f"ON CONFLICT ({conflict_str}) DO UPDATE SET {set_clause} "
                   f"RETURNING id")
        else:
            sql = (f"INSERT INTO {table} ({col_str}) VALUES ({placeholders}) "
                   f"ON CONFLICT ({conflict_str}) DO NOTHING RETURNING id")
    else:
        sql = f"INSERT OR REPLACE INTO {table} ({col_str}) VALUES ({placeholders})"

    try:
        cur.execute(sql, vals)
        if is_postgres():
            row = cur.fetchone()
            conn.commit()
            conn.close()
            return row[0] if row else data.get('id')
        else:
            conn.commit()
            rid = data.get('id')
            conn.close()
            return rid
    except Exception:
        conn.rollback()
        conn.close()
        raise


def fetch_one(sql, params=None):
    """Execute SQL, return one row as dict (or None)."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params or [])
    row = cur.fetchone()
    if row and cur.description:
        cols = [d[0] for d in cur.description]
        conn.close()
        return dict(zip(cols, row))
    conn.close()
    return None


def fetch_all(sql, params=None):
    """Execute SQL, return list of dicts."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params or [])
    rows = cur.fetchall()
    if rows and cur.description:
        cols = [d[0] for d in cur.description]
        conn.close()
        return [dict(zip(cols, r)) for r in rows]
    conn.close()
    return []


def execute(sql, params=None):
    """Execute a write statement, commit, return rowcount."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params or [])
    rc = cur.rowcount
    conn.commit()
    conn.close()
    return rc
