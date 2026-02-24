# Permit Feed — ArcGIS + Socrata Ingestion

Lightweight permit-data ingestion module that pulls from ArcGIS Feature
Services and Socrata Open Data portals, deduplicates records, and outputs
normalized signals to `new_signals.json`.

## Quick Start

```bash
# From repo root
python -m permit_feed.ingest_job
```

Output is written to `permit_feed/new_signals.json` (or `$PERMIT_FEED_STATE_DIR/new_signals.json`).

## Adding Endpoints

Edit `permit_feed/config_sources.py`. Each entry needs:

| Key | ArcGIS | Socrata |
|-----|--------|---------|
| `name` | unique identifier | unique identifier |
| `type` | `"arcgis"` | `"socrata"` |
| `state` | 2-letter code | 2-letter code |
| `max_per_run` | ≤ 200 | ≤ 200 |
| `feature_layer_url` | full Feature Layer URL | — |
| `domain` | — | Socrata host |
| `dataset_id` | — | 4×4 ID |
| `date_field` | epoch-ms field | ISO-8601 column |
| `where` | SQL-like filter | SoQL filter |

The module ships with placeholder sources for TX and AZ — replace the
`PLACEHOLDER` URLs with real endpoints.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PERMIT_FEED_STATE_DIR` | `./permit_feed` | Directory for `permit_state.json` and `new_signals.json` |
| `SOCRATA_APP_TOKEN` | *(none)* | Optional Socrata API token for higher rate limits |
| `PERMIT_FEED_MAX_TOTAL` | `500` | Global signal cap per run |
| `PERMIT_FEED_MAX_PER_SOURCE` | `200` | Per-source cap per run |

## Output Contract

`new_signals.json`:

```json
{
  "generated_at": "2025-01-15T12:00:00+00:00",
  "total_new": 42,
  "source_stats": {
    "tx_dallas_permits": { "fetched": 100, "new": 38 },
    "az_phoenix_permits": { "fetched": 50, "new": 4 }
  },
  "items": [
    {
      "id": "a1b2c3d4e5f6g7h8i9j0",
      "source": "tx_dallas_permits",
      "state": "TX",
      "address": "1234 Main St, Dallas, TX 75201",
      "permit_type": "building",
      "description": "New 200-unit multifamily development",
      "raw": { "...original fields..." }
    }
  ]
}
```

## Railway Deployment

The permit feed runs as part of the app's APScheduler jobs — it is
scheduled at **5:15 AM PT daily**, before the existing discovery and
government-signals jobs.

### Persistence Warning

Railway's filesystem is **ephemeral** — it resets on every deploy. For
deduplication state and output to survive deploys:

1. Mount a **Railway Volume** to `/app/permit_feed` (or any path), then
2. Set `PERMIT_FEED_STATE_DIR` to that mount path.

Without a volume, the state file resets on each deploy, which means
duplicate signals may be re-ingested after deploys (harmless but noisy).

Alternatively, to run the feed manually or as a separate Railway Cron
service:

```
python -m permit_feed.ingest_job
```

Railway → New Service → Cron Job → Schedule: `15 12 * * *` (5:15 AM PT = 12:15 UTC).

## Design

- **Caps**: 500 signals/run, 200/source (configurable via env)
- **Throttle**: ≥ 0.6 s between source fetches
- **Fault-tolerant**: if any source fails, warns and continues
- **Dedup**: SHA-256-based ID; seen-IDs capped at 200k entries
- **Dependencies**: Python stdlib + `requests` (already in requirements.txt)
