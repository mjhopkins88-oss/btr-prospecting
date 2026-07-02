"""
Phase F — Multifamily Command data export. Admin-only "Export all data"
tool: a single timestamped zip containing one CSV per multifamily_*
table, for the operator's own ad-hoc backup/analysis needs. This is NOT
a substitute for platform-level database backups (Railway's own backup
job is the operator's actual disaster-recovery mechanism) -- it's a
convenience export of the Multifamily Command tables specifically.

Table names are a fixed, hardcoded whitelist below -- never derived
from request input -- so interpolating them directly into a SELECT * is
safe (there is no injection surface; nothing here is user-controlled).
"""
import csv
import io
import zipfile
from datetime import datetime
from typing import List

from shared.database import fetch_all

# Every multifamily_* table that exists today (multifamily/repository.py's
# ensure_schema()). Keep this list in sync whenever a new table is added --
# there's no way to introspect this generically across both the SQLite and
# Postgres backends this app supports, so it's an explicit list rather than
# a schema query.
MULTIFAMILY_TABLES: List[str] = [
    'multifamily_leads',
    'multifamily_intake_events',
    'multifamily_signals',
    'multifamily_source_attribution',
    'multifamily_source_runs',
    'multifamily_serp_seen',
    'multifamily_lead_match_candidates',
    'multifamily_activities',
    'multifamily_lead_outcomes',
    'multifamily_lead_snapshots',
    'multifamily_notifications',
    'multifamily_sales_intelligence_events',
    'multifamily_outbound_links',
    'multifamily_campaigns',
    'multifamily_campaign_targets',
    'multifamily_deliverables',
]


def _table_to_csv_bytes(table: str) -> bytes:
    rows = fetch_all(f'SELECT * FROM {table}')
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    else:
        # Still a valid, openable CSV for an empty table -- just no rows.
        output.write('')
    return output.getvalue().encode('utf-8')


def build_export_zip() -> bytes:
    """Build the full export as zip bytes -- one CSV per table in
    MULTIFAMILY_TABLES, named '<table>.csv'. Never writes to disk."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for table in MULTIFAMILY_TABLES:
            zf.writestr(f'{table}.csv', _table_to_csv_bytes(table))
    return buffer.getvalue()


def export_filename() -> str:
    return f'multifamily-export-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.zip'
