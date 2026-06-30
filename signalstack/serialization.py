"""
JSON serialization safety layer.

The SignalStack generation pipeline attaches data sourced from both
SQLite and Postgres rows (playbook entries, knowledge entries, signals,
observations, grounding metadata, etc.) to its response payload. On
Postgres in particular, rows can contain values that Flask's default
``jsonify`` cannot encode:

    * ``datetime`` / ``date`` — e.g. ``created_at`` as TIMESTAMP
    * ``decimal.Decimal`` — e.g. ``confidence`` as NUMERIC
    * ``memoryview`` / ``bytes`` — e.g. bytea columns or driver buffers
    * ``uuid.UUID`` — when psycopg2 returns UUID objects
    * set / tuple / frozenset — occasionally produced by helpers

A single non-serializable value anywhere in a deeply nested response
used to crash the entire generation route with a 500 — and the fallback
response carried the same poisoned candidates, so the fallback crashed
too.

``to_json_safe`` is a recursive sanitizer that walks the payload and
converts everything it cannot trust into a JSON-safe primitive. It
preserves ``None``, ``bool``, ``int``, ``float``, and ``str`` as-is so
well-formed payloads are unchanged.
"""
from __future__ import annotations

import datetime as _dt
import decimal
import uuid
from typing import Any


_JSON_PRIMITIVES = (str, int, float, bool)


def _decode_bytes(value: Any) -> str:
    try:
        if isinstance(value, memoryview):
            value = value.tobytes()
        return value.decode("utf-8", errors="replace")
    except Exception:
        return repr(value)


def to_json_safe(value: Any, _depth: int = 0, _max_depth: int = 25) -> Any:
    """Recursively convert ``value`` into a JSON-serializable structure.

    The function never raises on unknown types: the final fallback is
    ``str(value)``. Cycles are guarded by a max-depth limit so this is
    safe to call on arbitrary generator output.
    """
    if _depth > _max_depth:
        return f"<max-depth {type(value).__name__}>"

    # Cheap fast-path for the common case.
    if value is None or isinstance(value, _JSON_PRIMITIVES):
        # NaN / inf are technically float but not valid JSON — coerce to
        # None to avoid downstream parser errors in the browser.
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                return None
        return value

    if isinstance(value, dict):
        out: dict = {}
        for k, v in value.items():
            # JSON requires string keys.
            key = k if isinstance(k, str) else str(k)
            out[key] = to_json_safe(v, _depth + 1, _max_depth)
        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_json_safe(v, _depth + 1, _max_depth) for v in value]

    if isinstance(value, (_dt.datetime, _dt.date)):
        try:
            return value.isoformat()
        except Exception:
            return str(value)

    if isinstance(value, _dt.time):
        try:
            return value.isoformat()
        except Exception:
            return str(value)

    if isinstance(value, _dt.timedelta):
        return value.total_seconds()

    if isinstance(value, decimal.Decimal):
        try:
            return float(value)
        except Exception:
            return str(value)

    if isinstance(value, uuid.UUID):
        return str(value)

    if isinstance(value, (bytes, bytearray, memoryview)):
        return _decode_bytes(value)

    # SQLAlchemy / psycopg row objects expose ``_asdict`` or ``keys``.
    as_dict = getattr(value, "_asdict", None)
    if callable(as_dict):
        try:
            return to_json_safe(as_dict(), _depth + 1, _max_depth)
        except Exception:
            pass

    if hasattr(value, "keys") and hasattr(value, "__getitem__"):
        try:
            return {
                (k if isinstance(k, str) else str(k)):
                    to_json_safe(value[k], _depth + 1, _max_depth)
                for k in value.keys()
            }
        except Exception:
            pass

    # Last resort: stringify. Never raise.
    try:
        return str(value)
    except Exception:
        return f"<unserializable {type(value).__name__}>"


def describe_unsafe(value: Any, _path: str = "$", _depth: int = 0,
                    _max_depth: int = 25) -> list[str]:
    """Return a list of ``path: type`` strings for values that would need
    sanitization. Useful for one-shot debug logging when we discover a
    serialization failure in production.
    """
    if _depth > _max_depth:
        return [f"{_path}: <max-depth>"]

    if value is None or isinstance(value, _JSON_PRIMITIVES):
        if isinstance(value, float) and (
            value != value or value in (float("inf"), float("-inf"))
        ):
            return [f"{_path}: non-finite-float"]
        return []

    if isinstance(value, dict):
        problems: list[str] = []
        for k, v in value.items():
            problems.extend(
                describe_unsafe(v, f"{_path}.{k}", _depth + 1, _max_depth)
            )
        return problems

    if isinstance(value, (list, tuple)):
        problems = []
        for i, v in enumerate(value):
            problems.extend(
                describe_unsafe(v, f"{_path}[{i}]", _depth + 1, _max_depth)
            )
        return problems

    return [f"{_path}: {type(value).__name__}"]
