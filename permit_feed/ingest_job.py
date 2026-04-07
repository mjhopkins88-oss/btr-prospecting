"""
Permit feed ingestion job.

Reads from ArcGIS + Socrata sources, deduplicates, and writes
normalized signals to new_signals.json for downstream consumption.

Run:
    python -m permit_feed.ingest_job

Environment variables:
    PERMIT_FEED_STATE_DIR   — directory for state + output files
                              (default: ./permit_feed)
    SOCRATA_APP_TOKEN       — optional Socrata API token

Caps:
    max_total_signals = 500 per run
    max_per_source    = 200 per source
    throttle          = 0.6 s between sources
"""
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone

# Allow running as `python -m permit_feed.ingest_job` from repo root
_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from permit_feed.config_sources import SOURCES
from permit_feed.connectors import fetch_arcgis, fetch_socrata, normalize_permit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_TOTAL_SIGNALS = int(os.environ.get("PERMIT_FEED_MAX_TOTAL", "500"))
MAX_PER_SOURCE    = int(os.environ.get("PERMIT_FEED_MAX_PER_SOURCE", "200"))
THROTTLE_SECS     = 0.6
SEEN_IDS_CAP      = 200_000

STATE_DIR  = os.environ.get("PERMIT_FEED_STATE_DIR") or os.path.join(_parent, "permit_feed")
STATE_FILE = os.path.join(STATE_DIR, "permit_state.json")
OUTPUT_FILE = os.path.join(STATE_DIR, "new_signals.json")


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def _load_state():
    """Load persisted state (cursors + seen IDs)."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[permit_feed] WARN: could not read state file, starting fresh: {e}")
    return {}


def _save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _trim_seen(state):
    """Cap the _seen_ids set to SEEN_IDS_CAP (keep newest)."""
    seen = state.get("_seen_ids", [])
    if len(seen) > SEEN_IDS_CAP:
        state["_seen_ids"] = seen[-SEEN_IDS_CAP:]


# ---------------------------------------------------------------------------
# Main job
# ---------------------------------------------------------------------------

def run_ingest():
    """
    Execute one permit-feed ingestion run.

    Returns
    -------
    list[dict]  Newly ingested (deduplicated) normalized signals.
    """
    state = _load_state()
    seen_ids = set(state.get("_seen_ids", []))
    new_items = []
    source_stats = {}
    total_collected = 0

    for src in SOURCES:
        name = src["name"]
        src_type = src["type"]
        src_state = src["state"]
        per_source_cap = min(src.get("max_per_run", MAX_PER_SOURCE), MAX_PER_SOURCE)
        remaining = MAX_TOTAL_SIGNALS - total_collected
        if remaining <= 0:
            print(f"[permit_feed] Global cap reached, skipping {name}")
            break
        limit = min(per_source_cap, remaining)

        cursor_key = f"cursor_{name}"
        raw_records = []

        print(f"[permit_feed] Fetching {name} ({src_type}, {src_state}) limit={limit} …")

        try:
            if src_type == "arcgis":
                since_ms = state.get(cursor_key, 0)
                raw_records = fetch_arcgis(
                    layer_url=src["feature_layer_url"],
                    date_field=src["date_field"],
                    where=src.get("where", "1=1"),
                    since_ms=since_ms,
                    limit=limit,
                )
                # Advance cursor to max date in results
                if raw_records:
                    max_ts = max(
                        int(r.get(src["date_field"], 0) or 0) for r in raw_records
                    )
                    if max_ts > since_ms:
                        state[cursor_key] = max_ts

            elif src_type == "socrata":
                since_iso = state.get(cursor_key, "")
                raw_records = fetch_socrata(
                    domain=src["domain"],
                    dataset_id=src["dataset_id"],
                    date_field=src["date_field"],
                    since_iso=since_iso,
                    where=src.get("where", ""),
                    limit=limit,
                )
                # Advance cursor
                if raw_records:
                    dates = [r.get(src["date_field"], "") for r in raw_records]
                    max_date = max(d for d in dates if d) if any(dates) else ""
                    if max_date and max_date > since_iso:
                        state[cursor_key] = max_date

            else:
                print(f"[permit_feed] WARN: unknown type '{src_type}' for {name}, skipping")
                source_stats[name] = {"fetched": 0, "new": 0, "error": f"unknown type {src_type}"}
                continue

        except Exception as e:
            print(f"[permit_feed] WARN: {name} failed — {e}")
            traceback.print_exc()
            source_stats[name] = {"fetched": 0, "new": 0, "error": str(e)}
            # Throttle even on failure
            time.sleep(THROTTLE_SECS)
            continue

        # Normalize + dedupe
        new_count = 0
        for raw in raw_records:
            normalized = normalize_permit(raw, name, src_state)
            sig_id = normalized["id"]
            if sig_id not in seen_ids:
                seen_ids.add(sig_id)
                new_items.append(normalized)
                new_count += 1
                total_collected += 1

        source_stats[name] = {"fetched": len(raw_records), "new": new_count}
        print(f"[permit_feed]   → fetched={len(raw_records)}, new={new_count}")

        # Log new permits to intelligence feed
        if new_count > 0:
            try:
                from app import log_intelligence_event
                log_intelligence_event(
                    event_type='PERMIT',
                    title=f"NEW PERMIT \u2014 {name}",
                    description=f"{new_count} new permit(s) detected from {name}",
                    state=src_state,
                )
            except Exception:
                pass

        # Throttle between sources
        time.sleep(THROTTLE_SECS)

    # Persist state
    state["_seen_ids"] = list(seen_ids)
    _trim_seen(state)
    state["_last_run"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    # Write output
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_new": len(new_items),
        "source_stats": source_stats,
        "items": new_items,
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[permit_feed] Done. {len(new_items)} new signals → {OUTPUT_FILE}")
    return new_items


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run_ingest()
