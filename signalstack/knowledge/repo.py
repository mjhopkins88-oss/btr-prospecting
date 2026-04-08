"""
Knowledge dataset repository.

Thin data-access layer over db.get_db() for the knowledge tables:
    ss_knowledge_sources
    ss_knowledge_entries
    ss_knowledge_tags
    ss_knowledge_source_tags
    ss_knowledge_entry_tags

Returns plain dicts so the route layer can json.dumps() them with no
extra serialization. All input validation belongs to the caller (the
routes layer uses signalstack.types.validate()).
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from db import get_db
from ..types import (
    KNOWLEDGE_SOURCE_TYPES,
    KNOWLEDGE_EXTRACTION_STATUS,
    validate,
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


# ----------------------- Tags -----------------------

def _normalize_tag(label: str) -> str:
    return (label or "").strip().lower()


def get_or_create_tag(label: str) -> Optional[dict]:
    label = _normalize_tag(label)
    if not label:
        return None
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ss_knowledge_tags WHERE label = ?", (label,))
        row = _row_to_dict(cur, cur.fetchone())
        if row:
            return row
        tid = _uid()
        cur.execute(
            "INSERT INTO ss_knowledge_tags (id, label) VALUES (?, ?)",
            (tid, label),
        )
        conn.commit()
        return {"id": tid, "label": label}
    finally:
        conn.close()


def list_tags() -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM ss_knowledge_tags ORDER BY label")
            return _rows_to_dicts(cur, cur.fetchall())
        except Exception:
            try: conn.rollback()
            except Exception: pass
            return []
    finally:
        conn.close()


def _replace_source_tags(source_id: str, labels: Iterable[str]) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM ss_knowledge_source_tags WHERE source_id = ?", (source_id,))
        conn.commit()
    finally:
        conn.close()
    out = []
    for lbl in labels or []:
        tag = get_or_create_tag(lbl)
        if not tag:
            continue
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO ss_knowledge_source_tags (source_id, tag_id) VALUES (?, ?)",
                (source_id, tag["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        out.append(tag)
    return out


def _replace_entry_tags(entry_id: str, labels: Iterable[str]) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM ss_knowledge_entry_tags WHERE entry_id = ?", (entry_id,))
        conn.commit()
    finally:
        conn.close()
    out = []
    for lbl in labels or []:
        tag = get_or_create_tag(lbl)
        if not tag:
            continue
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO ss_knowledge_entry_tags (entry_id, tag_id) VALUES (?, ?)",
                (entry_id, tag["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        out.append(tag)
    return out


def list_tags_for_source(source_id: str) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT t.* FROM ss_knowledge_tags t "
                "JOIN ss_knowledge_source_tags st ON st.tag_id = t.id "
                "WHERE st.source_id = ? ORDER BY t.label",
                (source_id,),
            )
            return _rows_to_dicts(cur, cur.fetchall())
        except Exception:
            try: conn.rollback()
            except Exception: pass
            return []
    finally:
        conn.close()


def list_tags_for_entry(entry_id: str) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT t.* FROM ss_knowledge_tags t "
                "JOIN ss_knowledge_entry_tags et ON et.tag_id = t.id "
                "WHERE et.entry_id = ? ORDER BY t.label",
                (entry_id,),
            )
            return _rows_to_dicts(cur, cur.fetchall())
        except Exception:
            try: conn.rollback()
            except Exception: pass
            return []
    finally:
        conn.close()


# ----------------------- Sources -----------------------

_SOURCE_FIELDS = (
    "title", "source_type", "source_url", "raw_text",
    "summary", "notes", "active", "extraction_status",
)


def create_source(data: dict) -> dict:
    sid = _uid()
    now = _now()
    source_type = validate(data.get("source_type", "manual_entry"),
                           KNOWLEDGE_SOURCE_TYPES, "source_type")
    extraction_status = validate(data.get("extraction_status", "RAW"),
                                 KNOWLEDGE_EXTRACTION_STATUS, "extraction_status")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_knowledge_sources
               (id, user_id, title, source_type, source_url, raw_text,
                summary, notes, active, extraction_status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sid, data.get("user_id"), data["title"], source_type,
             data.get("source_url"), data.get("raw_text"),
             data.get("summary"), data.get("notes"),
             1 if data.get("active", True) else 0,
             extraction_status, now, now),
        )
        conn.commit()
    finally:
        conn.close()
    if data.get("tags"):
        _replace_source_tags(sid, data["tags"])
    return get_source(sid) or {}


def update_source(source_id: str, data: dict) -> Optional[dict]:
    if "source_type" in data:
        validate(data["source_type"], KNOWLEDGE_SOURCE_TYPES, "source_type")
    if "extraction_status" in data:
        validate(data["extraction_status"], KNOWLEDGE_EXTRACTION_STATUS, "extraction_status")
    sets, vals = [], []
    for f in _SOURCE_FIELDS:
        if f in data:
            v = data[f]
            if f == "active":
                v = 1 if v else 0
            sets.append(f"{f} = ?")
            vals.append(v)
    if sets:
        sets.append("updated_at = ?")
        vals.append(_now())
        vals.append(source_id)
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE ss_knowledge_sources SET {', '.join(sets)} WHERE id = ?",
                tuple(vals),
            )
            conn.commit()
        finally:
            conn.close()
    if "tags" in data:
        _replace_source_tags(source_id, data["tags"] or [])
    return get_source(source_id)


def get_source(source_id: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM ss_knowledge_sources WHERE id = ?", (source_id,))
            row = _row_to_dict(cur, cur.fetchone())
        except Exception as e:
            print(f"[SignalStack] knowledge.get_source skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return None
    finally:
        conn.close()
    if not row:
        return None
    row["active"] = bool(row.get("active"))
    row["tags"] = [t["label"] for t in list_tags_for_source(source_id)]
    row["entry_count"] = _count_entries_for_source(source_id)
    return row


def list_sources(
    q: str = "",
    source_type: str = "",
    active: Optional[bool] = None,
    extraction_status: str = "",
    tag: str = "",
) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            clauses, params = [], []
            if q:
                like = f"%{q}%"
                clauses.append("(title LIKE ? OR summary LIKE ? OR notes LIKE ?)")
                params.extend([like, like, like])
            if source_type:
                clauses.append("source_type = ?")
                params.append(source_type)
            if active is not None:
                clauses.append("active = ?")
                params.append(1 if active else 0)
            if extraction_status:
                clauses.append("extraction_status = ?")
                params.append(extraction_status)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            cur.execute(
                f"SELECT * FROM ss_knowledge_sources {where} ORDER BY created_at DESC",
                tuple(params),
            )
            rows = _rows_to_dicts(cur, cur.fetchall())
        except Exception as e:
            print(f"[SignalStack] knowledge.list_sources skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return []
    finally:
        conn.close()
    # Hydrate tags + entry counts. Filter by tag in Python so we don't
    # hit cross-engine UPPER/LOWER issues for case-insensitive matching.
    tag_norm = _normalize_tag(tag) if tag else ""
    out = []
    for r in rows:
        r["active"] = bool(r.get("active"))
        r["tags"] = [t["label"] for t in list_tags_for_source(r["id"])]
        r["entry_count"] = _count_entries_for_source(r["id"])
        if tag_norm and tag_norm not in r["tags"]:
            continue
        out.append(r)
    return out


def archive_source(source_id: str) -> Optional[dict]:
    return update_source(source_id, {
        "active": False,
        "extraction_status": "ARCHIVED",
    })


# ----------------------- Entries -----------------------

_ENTRY_FIELDS = (
    "category", "principle_name", "description", "practical_use_case",
    "allowed_contexts", "disallowed_contexts", "example_pattern",
    "anti_pattern", "confidence", "active",
)


def create_entry(data: dict) -> dict:
    eid = _uid()
    now = _now()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ss_knowledge_entries
               (id, source_id, category, principle_name, description,
                practical_use_case, allowed_contexts, disallowed_contexts,
                example_pattern, anti_pattern, confidence, active,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (eid, data["source_id"], data["category"], data["principle_name"],
             data["description"], data.get("practical_use_case"),
             data.get("allowed_contexts"), data.get("disallowed_contexts"),
             data.get("example_pattern"), data.get("anti_pattern"),
             float(data.get("confidence") or 0.7),
             1 if data.get("active", True) else 0,
             now, now),
        )
        conn.commit()
    finally:
        conn.close()
    if data.get("tags"):
        _replace_entry_tags(eid, data["tags"])
    return get_entry(eid) or {}


def update_entry(entry_id: str, data: dict) -> Optional[dict]:
    sets, vals = [], []
    for f in _ENTRY_FIELDS:
        if f in data:
            v = data[f]
            if f == "active":
                v = 1 if v else 0
            if f == "confidence":
                v = float(v or 0.7)
            sets.append(f"{f} = ?")
            vals.append(v)
    if sets:
        sets.append("updated_at = ?")
        vals.append(_now())
        vals.append(entry_id)
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE ss_knowledge_entries SET {', '.join(sets)} WHERE id = ?",
                tuple(vals),
            )
            conn.commit()
        finally:
            conn.close()
    if "tags" in data:
        _replace_entry_tags(entry_id, data["tags"] or [])
    return get_entry(entry_id)


def get_entry(entry_id: str) -> Optional[dict]:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM ss_knowledge_entries WHERE id = ?", (entry_id,))
            row = _row_to_dict(cur, cur.fetchone())
        except Exception as e:
            print(f"[SignalStack] knowledge.get_entry skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return None
    finally:
        conn.close()
    if not row:
        return None
    row["active"] = bool(row.get("active"))
    row["tags"] = [t["label"] for t in list_tags_for_entry(entry_id)]
    return row


def list_entries(
    source_id: str = "",
    active: Optional[bool] = None,
    category: str = "",
) -> list:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            clauses, params = [], []
            if source_id:
                clauses.append("source_id = ?")
                params.append(source_id)
            if active is not None:
                clauses.append("active = ?")
                params.append(1 if active else 0)
            if category:
                clauses.append("category = ?")
                params.append(category)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            cur.execute(
                f"SELECT * FROM ss_knowledge_entries {where} "
                f"ORDER BY created_at DESC",
                tuple(params),
            )
            rows = _rows_to_dicts(cur, cur.fetchall())
        except Exception as e:
            print(f"[SignalStack] knowledge.list_entries skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return []
    finally:
        conn.close()
    for r in rows:
        r["active"] = bool(r.get("active"))
        r["tags"] = [t["label"] for t in list_tags_for_entry(r["id"])]
    return rows


def delete_entry(entry_id: str) -> bool:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM ss_knowledge_entry_tags WHERE entry_id = ?", (entry_id,))
            cur.execute("DELETE FROM ss_knowledge_entries WHERE id = ?", (entry_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f"[SignalStack] knowledge.delete_entry skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return False
    finally:
        conn.close()


def replace_entries_for_source(source_id: str, entries: list) -> list:
    """Wipe and re-insert all entries for a given source. Used by
    extraction. Returns the freshly created entries."""
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            # Wipe entry tag joins for this source's entries first.
            cur.execute(
                "SELECT id FROM ss_knowledge_entries WHERE source_id = ?",
                (source_id,),
            )
            old_ids = [r[0] for r in cur.fetchall()]
            for oid in old_ids:
                cur.execute(
                    "DELETE FROM ss_knowledge_entry_tags WHERE entry_id = ?",
                    (oid,),
                )
            cur.execute(
                "DELETE FROM ss_knowledge_entries WHERE source_id = ?",
                (source_id,),
            )
            conn.commit()
        except Exception as e:
            print(f"[SignalStack] knowledge.replace_entries wipe skipped: {e}")
            try: conn.rollback()
            except Exception: pass
    finally:
        conn.close()
    out = []
    for e in entries or []:
        e = {**e, "source_id": source_id}
        out.append(create_entry(e))
    return out


def _count_entries_for_source(source_id: str) -> int:
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT COUNT(*) FROM ss_knowledge_entries WHERE source_id = ?",
                (source_id,),
            )
            return int(cur.fetchone()[0])
        except Exception:
            try: conn.rollback()
            except Exception: pass
            return 0
    finally:
        conn.close()


# ----------------------- Stats / generator hook -----------------------

def overview_stats() -> dict:
    """Header stats for the knowledge index page."""
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM ss_knowledge_sources")
            total_sources = int(cur.fetchone()[0])
            cur.execute(
                "SELECT COUNT(*) FROM ss_knowledge_sources WHERE active = 1"
            )
            active_sources = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM ss_knowledge_entries")
            total_entries = int(cur.fetchone()[0])
            cur.execute(
                "SELECT COUNT(*) FROM ss_knowledge_entries WHERE active = 1"
            )
            active_entries = int(cur.fetchone()[0])
            cur.execute(
                "SELECT source_type, COUNT(*) FROM ss_knowledge_sources GROUP BY source_type"
            )
            by_type = {row[0]: int(row[1]) for row in cur.fetchall()}
            cur.execute(
                "SELECT extraction_status, COUNT(*) FROM ss_knowledge_sources GROUP BY extraction_status"
            )
            by_status = {row[0]: int(row[1]) for row in cur.fetchall()}
            return {
                "total_sources": total_sources,
                "active_sources": active_sources,
                "total_entries": total_entries,
                "active_entries": active_entries,
                "videos": by_type.get("youtube_video", 0),
                "articles": by_type.get("article", 0),
                "notes": by_type.get("note", 0),
                "podcasts": by_type.get("podcast", 0),
                "playbooks": by_type.get("playbook", 0),
                "transcripts": by_type.get("transcript", 0),
                "frameworks": by_type.get("framework", 0),
                "manual_entries": by_type.get("manual_entry", 0),
                "by_source_type": by_type,
                "by_extraction_status": by_status,
            }
        except Exception as e:
            print(f"[SignalStack] knowledge.overview_stats skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return {
                "total_sources": 0, "active_sources": 0,
                "total_entries": 0, "active_entries": 0,
                "videos": 0, "articles": 0, "notes": 0,
                "podcasts": 0, "playbooks": 0, "transcripts": 0,
                "frameworks": 0, "manual_entries": 0,
                "by_source_type": {}, "by_extraction_status": {},
            }
    finally:
        conn.close()


def list_active_entries_for_generator(limit: int = 25) -> list:
    """Return active knowledge entries for the generator to consult.

    These are NEVER treated as personalization — they shape tone,
    framing, anti-generic filtering and angle preference. The caller
    is responsible for handling them as a strategy/style layer.
    """
    conn = get_db()
    try:
        cur = conn.cursor()
        try:
            # Only entries whose source is also active. Highest-confidence first.
            cur.execute(
                """SELECT e.* FROM ss_knowledge_entries e
                   JOIN ss_knowledge_sources s ON s.id = e.source_id
                   WHERE e.active = 1 AND s.active = 1
                   ORDER BY e.confidence DESC, e.created_at DESC
                   LIMIT ?""",
                (int(limit),),
            )
            rows = _rows_to_dicts(cur, cur.fetchall())
        except Exception as e:
            print(f"[SignalStack] knowledge.list_active_entries_for_generator skipped: {e}")
            try: conn.rollback()
            except Exception: pass
            return []
    finally:
        conn.close()
    for r in rows:
        r["active"] = bool(r.get("active"))
    return rows
