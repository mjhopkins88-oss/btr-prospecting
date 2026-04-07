"""
SignalStack repository layer.

Thin data-access functions over the existing db.get_db() helper.
All functions return plain dicts so the route layer can json.dumps()
without extra serialization. Caller is responsible for input validation
via signalstack.types.validate().
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from db import get_db
from .types import (
    PROSPECT_STATUS, SIGNAL_TYPES, SIGNAL_SOURCES,
    MESSAGE_STATUS, MESSAGE_OUTCOMES, validate,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _uid() -> str:
    return uuid.uuid4().hex


def _row_to_dict(cursor, row) -> Optional[dict]:
    if row is None:
        return None
    cols = [d[0] for d in cursor.description]
    return dict(zip(cols, row))


def _rows_to_dicts(cursor, rows) -> list:
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, r)) for r in rows]


# ----------------------- Companies -----------------------

def create_company(data: dict) -> dict:
    cid = _uid()
    now = _now()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_companies
               (id, name, website, industry, location, notes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (cid, data["name"], data.get("website"), data.get("industry"),
             data.get("location"), data.get("notes"), now, now),
        )
        conn.commit()
    finally:
        conn.close()
    return get_company(cid)


def get_company(cid: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ss_companies WHERE id = ?", (cid,))
        return _row_to_dict(cur, cur.fetchone())
    finally:
        conn.close()


def list_companies(q: str = "") -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        if q:
            like = f"%{q}%"
            cur.execute(
                "SELECT * FROM ss_companies WHERE name LIKE ? OR industry LIKE ? ORDER BY name",
                (like, like),
            )
        else:
            cur.execute("SELECT * FROM ss_companies ORDER BY name")
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


def update_company(cid: str, data: dict) -> Optional[dict]:
    fields = ["name", "website", "industry", "location", "notes"]
    sets, vals = [], []
    for f in fields:
        if f in data:
            sets.append(f"{f} = ?")
            vals.append(data[f])
    if not sets:
        return get_company(cid)
    sets.append("updated_at = ?")
    vals.append(_now())
    vals.append(cid)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE ss_companies SET {', '.join(sets)} WHERE id = ?", tuple(vals))
        conn.commit()
    finally:
        conn.close()
    return get_company(cid)


# ----------------------- Prospects -----------------------

def create_prospect(data: dict) -> dict:
    pid = _uid()
    now = _now()
    status = validate(data.get("status", "new"), PROSPECT_STATUS, "status")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_prospects
               (id, full_name, linkedin_url, company_id, company_name, title,
                industry, location, status, warmth, last_contacted_at, notes,
                owner_user_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pid, data["full_name"], data.get("linkedin_url"),
             data.get("company_id"), data.get("company_name"),
             data.get("title"), data.get("industry"), data.get("location"),
             status, int(data.get("warmth", 0)),
             data.get("last_contacted_at"), data.get("notes"),
             data.get("owner_user_id"), now, now),
        )
        conn.commit()
    finally:
        conn.close()
    return get_prospect(pid)


def get_prospect(pid: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ss_prospects WHERE id = ?", (pid,))
        return _row_to_dict(cur, cur.fetchone())
    finally:
        conn.close()


def list_prospects(q: str = "", status: str = "") -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        clauses, params = [], []
        if q:
            like = f"%{q}%"
            clauses.append("(full_name LIKE ? OR company_name LIKE ? OR title LIKE ?)")
            params.extend([like, like, like])
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(
            f"SELECT * FROM ss_prospects {where} ORDER BY updated_at DESC",
            tuple(params),
        )
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


def update_prospect(pid: str, data: dict) -> Optional[dict]:
    fields = ["full_name", "linkedin_url", "company_id", "company_name",
              "title", "industry", "location", "status", "warmth",
              "last_contacted_at", "notes"]
    if "status" in data:
        validate(data["status"], PROSPECT_STATUS, "status")
    sets, vals = [], []
    for f in fields:
        if f in data:
            sets.append(f"{f} = ?")
            vals.append(data[f])
    if not sets:
        return get_prospect(pid)
    sets.append("updated_at = ?")
    vals.append(_now())
    vals.append(pid)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE ss_prospects SET {', '.join(sets)} WHERE id = ?", tuple(vals))
        conn.commit()
    finally:
        conn.close()
    return get_prospect(pid)


def list_prospects_for_company(company_id: str) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ss_prospects WHERE company_id = ? ORDER BY updated_at DESC", (company_id,))
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


# ----------------------- Signals -----------------------

def create_signal(data: dict) -> dict:
    sid = _uid()
    validate(data["type"], SIGNAL_TYPES, "signal type")
    validate(data["source"], SIGNAL_SOURCES, "signal source")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_signals
               (id, prospect_id, company_id, type, source, text, confidence,
                safe_to_reference, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sid, data.get("prospect_id"), data.get("company_id"),
             data["type"], data["source"], data["text"],
             float(data.get("confidence", 0.7)),
             1 if data.get("safe_to_reference", True) else 0, _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return get_signal(sid)


def get_signal(sid: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ss_signals WHERE id = ?", (sid,))
        return _row_to_dict(cur, cur.fetchone())
    finally:
        conn.close()


def list_signals_for_prospect(pid: str, only_safe: bool = False) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        if only_safe:
            cur.execute(
                "SELECT * FROM ss_signals WHERE prospect_id = ? AND safe_to_reference = 1 ORDER BY created_at DESC",
                (pid,),
            )
        else:
            cur.execute(
                "SELECT * FROM ss_signals WHERE prospect_id = ? ORDER BY created_at DESC",
                (pid,),
            )
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


def list_signals_for_company(cid: str, only_safe: bool = False) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        if only_safe:
            cur.execute(
                "SELECT * FROM ss_signals WHERE company_id = ? AND safe_to_reference = 1 ORDER BY created_at DESC",
                (cid,),
            )
        else:
            cur.execute(
                "SELECT * FROM ss_signals WHERE company_id = ? ORDER BY created_at DESC",
                (cid,),
            )
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


# ----------------------- Messages -----------------------

def create_message(data: dict, signal_ids: list) -> dict:
    mid = _uid()
    validate(data.get("status", "draft"), MESSAGE_STATUS, "message status")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_messages
               (id, prospect_id, body, rationale, message_type, primary_trigger,
                communication_style, outreach_goal, channel, status, sent_at,
                grounding_score, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (mid, data["prospect_id"], data["body"], data.get("rationale"),
             data.get("message_type"), data.get("primary_trigger"),
             data.get("communication_style"), data.get("outreach_goal"),
             data.get("channel"), data.get("status", "draft"),
             data.get("sent_at"), data.get("grounding_score"), _now()),
        )
        for sid in signal_ids or []:
            cur.execute(
                "INSERT INTO ss_message_signals (message_id, signal_id) VALUES (?, ?)",
                (mid, sid),
            )
        conn.commit()
    finally:
        conn.close()
    return get_message(mid)


def get_message(mid: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ss_messages WHERE id = ?", (mid,))
        msg = _row_to_dict(cur, cur.fetchone())
        if not msg:
            return None
        cur.execute("SELECT signal_id FROM ss_message_signals WHERE message_id = ?", (mid,))
        msg["signal_ids"] = [r[0] for r in cur.fetchall()]
        return msg
    finally:
        conn.close()


def update_message(mid: str, data: dict) -> Optional[dict]:
    fields = ["body", "status", "channel", "sent_at"]
    if "status" in data:
        validate(data["status"], MESSAGE_STATUS, "message status")
    sets, vals = [], []
    for f in fields:
        if f in data:
            sets.append(f"{f} = ?")
            vals.append(data[f])
    if not sets:
        return get_message(mid)
    vals.append(mid)
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE ss_messages SET {', '.join(sets)} WHERE id = ?", tuple(vals))
        conn.commit()
    finally:
        conn.close()
    return get_message(mid)


def list_messages(prospect_id: str = "", status: str = "") -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        clauses, params = [], []
        if prospect_id:
            clauses.append("prospect_id = ?")
            params.append(prospect_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cur.execute(
            f"SELECT * FROM ss_messages {where} ORDER BY created_at DESC",
            tuple(params),
        )
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


def record_outcome(message_id: str, outcome: str, notes: str = "") -> dict:
    validate(outcome, MESSAGE_OUTCOMES, "outcome")
    oid = _uid()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_message_outcomes (id, message_id, outcome, notes, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (oid, message_id, outcome, notes, _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"id": oid, "message_id": message_id, "outcome": outcome, "notes": notes}


_PROFILE_FIELDS = (
    "linkedin_url", "headline", "about_text", "current_role", "current_company",
    "prior_roles_summary", "featured_topics", "recent_posts_summary",
    "notable_language_patterns", "shared_context", "manual_observations",
    "safe_flags",
)


def upsert_profile_context(prospect_id: str, data: dict) -> dict:
    """Insert or update the manual LinkedIn profile context for a prospect."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM ss_profile_context WHERE prospect_id = ?", (prospect_id,))
        row = cur.fetchone()
        now = _now()
        if row:
            sets, vals = [], []
            for f in _PROFILE_FIELDS:
                if f in data:
                    sets.append(f"{f} = ?")
                    vals.append(data[f])
            if sets:
                sets.append("updated_at = ?")
                vals.append(now)
                vals.append(row[0])
                cur.execute(
                    f"UPDATE ss_profile_context SET {', '.join(sets)} WHERE id = ?",
                    tuple(vals),
                )
        else:
            pid = _uid()
            cur.execute(
                """INSERT INTO ss_profile_context
                   (id, prospect_id, linkedin_url, headline, about_text,
                    current_role, current_company, prior_roles_summary,
                    featured_topics, recent_posts_summary,
                    notable_language_patterns, shared_context,
                    manual_observations, safe_flags, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (pid, prospect_id, data.get("linkedin_url"),
                 data.get("headline"), data.get("about_text"),
                 data.get("current_role"), data.get("current_company"),
                 data.get("prior_roles_summary"), data.get("featured_topics"),
                 data.get("recent_posts_summary"),
                 data.get("notable_language_patterns"),
                 data.get("shared_context"), data.get("manual_observations"),
                 data.get("safe_flags"), now, now),
            )
        conn.commit()
    finally:
        conn.close()
    return get_profile_context(prospect_id) or {}


def get_profile_context(prospect_id: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM ss_profile_context WHERE prospect_id = ?", (prospect_id,))
            return _row_to_dict(cur, cur.fetchone())
        except Exception as e:
            # Table may not exist on older deploys — fail soft so the
            # generator can still run from inline profile_override.
            print(f"[SignalStack] get_profile_context skipped: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return None
    finally:
        conn.close()


# ----------------------- Notes -----------------------

def create_note(data: dict) -> dict:
    nid = _uid()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_notes (id, prospect_id, company_id, body, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (nid, data.get("prospect_id"), data.get("company_id"),
             data["body"], _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"id": nid, **data}


def list_notes_for_prospect(prospect_id: str) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM ss_notes WHERE prospect_id = ? ORDER BY created_at DESC",
            (prospect_id,),
        )
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()


# ----------------------- Social-selling principles -----------------------

def list_principles(active_only: bool = True) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            if active_only:
                cur.execute("SELECT * FROM ss_social_principles WHERE active = 1 ORDER BY category, principle_name")
            else:
                cur.execute("SELECT * FROM ss_social_principles ORDER BY category, principle_name")
            return _rows_to_dicts(cur, cur.fetchall())
        except Exception as e:
            print(f"[SignalStack] list_principles skipped: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return []
    finally:
        conn.close()


def create_principle(data: dict) -> dict:
    pid = _uid()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_social_principles
               (id, category, principle_name, description, practical_use_case,
                allowed_contexts, disallowed_contexts, example_pattern,
                anti_pattern, active, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pid, data["category"], data["principle_name"],
             data["description"], data.get("practical_use_case"),
             data.get("allowed_contexts"), data.get("disallowed_contexts"),
             data.get("example_pattern"), data.get("anti_pattern"),
             1 if data.get("active", True) else 0, _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"id": pid, **data}


# ----------------------- Message metadata (grounding trail) -----------------------

def save_message_metadata(message_id: str, meta: dict) -> None:
    import json as _json
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM ss_message_metadata WHERE message_id = ?", (message_id,))
        cur.execute(
            """INSERT INTO ss_message_metadata
               (message_id, facts_used_json, signals_used_json, notes_used_json,
                profile_fields_used_json, grounding_score, unsafe_claims_json,
                validator_notes, strategy_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (message_id,
             _json.dumps(meta.get("facts_used") or []),
             _json.dumps(meta.get("signals_used") or []),
             _json.dumps(meta.get("notes_used") or []),
             _json.dumps(meta.get("profile_fields_used") or []),
             meta.get("grounding_score"),
             _json.dumps(meta.get("unsafe_claims") or []),
             meta.get("validator_notes"),
             _json.dumps(meta.get("strategy") or {}),
             _now()),
        )
        conn.commit()
    finally:
        conn.close()


def list_outcomes_for_message(message_id: str) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM ss_message_outcomes WHERE message_id = ? ORDER BY created_at DESC",
            (message_id,),
        )
        return _rows_to_dicts(cur, cur.fetchall())
    finally:
        conn.close()
