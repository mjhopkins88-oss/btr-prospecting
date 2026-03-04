"""
Signal Normalization Worker.
Processes raw li_signals entries, standardizes fields, deduplicates,
and marks them as normalized.
"""
import json
import re
from shared.database import get_db, fetch_all, execute, new_id


def _normalize_company_name(name):
    """Standardize company name for matching."""
    if not name:
        return None
    name = name.strip()
    # Remove common suffixes
    for suffix in [' LLC', ' Inc', ' Inc.', ' Corp', ' Corp.', ' Co.', ' LP', ' LLP', ' Ltd', ' Ltd.']:
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name.strip()


def _normalize_signal_type(raw_type):
    """Map raw signal types to canonical types."""
    if not raw_type:
        return 'other'
    t = raw_type.lower().strip()
    mappings = {
        'land_acquisition': 'land_acquisition',
        'land purchase': 'land_acquisition',
        'land sale': 'land_acquisition',
        'permit_filed': 'permit_filed',
        'permit': 'permit_filed',
        'building permit': 'permit_filed',
        'construction_start': 'construction_start',
        'groundbreaking': 'construction_start',
        'broke ground': 'construction_start',
        'project_announced': 'project_announced',
        'announced': 'project_announced',
        'funding': 'funding',
        'financing': 'funding',
        'loan': 'funding',
        'zoning_change': 'zoning_change',
        'rezoning': 'zoning_change',
        'zoning': 'zoning_change',
    }
    return mappings.get(t, 'other')


def _clamp_strength(val):
    """Ensure strength is between 0.0 and 1.0."""
    try:
        v = float(val)
        return max(0.0, min(1.0, v))
    except (TypeError, ValueError):
        return 0.5


def normalize_signals(batch_size=100):
    """
    Process un-normalized signals in li_signals.
    Standardizes signal_type, strength, and extracts company/project refs.
    """
    rows = fetch_all(
        "SELECT id, headline, body, raw_json, signal_type, strength, city, state "
        "FROM li_signals WHERE normalized = 0 ORDER BY created_at ASC LIMIT ?",
        [batch_size]
    )
    if not rows:
        print("[Normalizer] No un-normalized signals found.")
        return 0

    conn = get_db()
    cur = conn.cursor()
    processed = 0

    for row in rows:
        sig_id = row['id']
        raw = {}
        try:
            raw = json.loads(row.get('raw_json') or '{}')
        except Exception:
            pass

        norm_type = _normalize_signal_type(row.get('signal_type') or raw.get('signal_type'))
        norm_strength = _clamp_strength(row.get('strength') or raw.get('strength', 0.5))

        # Extract company/project from raw_json if present
        company_name = _normalize_company_name(raw.get('company_name'))
        project_name = raw.get('project_name')

        # Link to li_companies if company_name found
        company_id = None
        if company_name:
            cur.execute("SELECT id FROM li_companies WHERE name = ?", (company_name,))
            existing = cur.fetchone()
            if existing:
                company_id = existing[0]
            else:
                company_id = new_id()
                try:
                    cur.execute(
                        "INSERT OR IGNORE INTO li_companies (id, name, created_at, updated_at) "
                        "VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                        (company_id, company_name)
                    )
                except Exception:
                    company_id = None

        # Link to li_projects if project_name found
        project_id = None
        if project_name:
            city = row.get('city') or ''
            state = row.get('state') or ''
            cur.execute(
                "SELECT id FROM li_projects WHERE name = ? AND city = ? AND state = ?",
                (project_name, city, state)
            )
            existing = cur.fetchone()
            if existing:
                project_id = existing[0]
            else:
                project_id = new_id()
                unit_count = raw.get('unit_count')
                try:
                    cur.execute(
                        "INSERT OR IGNORE INTO li_projects "
                        "(id, name, city, state, unit_count, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                        (project_id, project_name, city, state, unit_count)
                    )
                except Exception:
                    project_id = None

        # Update the signal row
        try:
            cur.execute('''
                UPDATE li_signals
                SET signal_type = ?, strength = ?, normalized = 1,
                    company_id = COALESCE(?, company_id),
                    project_id = COALESCE(?, project_id)
                WHERE id = ?
            ''', (norm_type, norm_strength, company_id, project_id, sig_id))
            processed += 1
        except Exception as e:
            print(f"[Normalizer] Error updating signal {sig_id}: {e}")

    conn.commit()
    conn.close()
    print(f"[Normalizer] Normalized {processed}/{len(rows)} signals.")
    return processed
