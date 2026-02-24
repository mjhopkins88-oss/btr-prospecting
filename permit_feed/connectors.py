"""
Connectors for ArcGIS Feature Services and Socrata Open Data APIs.

Only uses Python stdlib + requests (already in requirements.txt).
"""
import hashlib
import os
import time

import requests

# ---------------------------------------------------------------------------
# ArcGIS Feature Service
# ---------------------------------------------------------------------------

def fetch_arcgis(layer_url, date_field, where, since_ms, limit):
    """
    Query an ArcGIS Feature Layer.

    Parameters
    ----------
    layer_url : str   Full URL to the Feature Layer (…/FeatureServer/N)
    date_field : str  Field used for incremental cursor (epoch-ms)
    where : str       Base SQL-like filter (e.g. "1=1")
    since_ms : int    Epoch-ms cursor; only records after this timestamp
    limit : int       Max records to return

    Returns
    -------
    list[dict]  Raw attribute dicts from the API.
    """
    full_where = where or "1=1"
    if since_ms:
        full_where = f"({full_where}) AND {date_field} > {since_ms}"

    params = {
        "f": "json",
        "outFields": "*",
        "returnGeometry": "false",
        "orderByFields": f"{date_field} ASC",
        "where": full_where,
        "resultRecordCount": limit,
    }

    url = layer_url.rstrip("/") + "/query"
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if "error" in data:
        raise RuntimeError(f"ArcGIS error: {data['error']}")

    features = data.get("features", [])
    return [f.get("attributes", f) for f in features]


# ---------------------------------------------------------------------------
# Socrata Open Data
# ---------------------------------------------------------------------------

def fetch_socrata(domain, dataset_id, date_field, since_iso, where, limit):
    """
    Query a Socrata dataset.

    Parameters
    ----------
    domain : str      Socrata host (e.g. data.example.gov)
    dataset_id : str  4×4 dataset identifier
    date_field : str  Column for date cursor
    since_iso : str   ISO-8601 cursor string
    where : str       Optional SoQL where clause
    limit : int       Max records

    Returns
    -------
    list[dict]  Row dicts from the dataset.
    """
    url = f"https://{domain}/resource/{dataset_id}.json"

    where_parts = []
    if where:
        where_parts.append(where)
    if since_iso:
        where_parts.append(f"{date_field} > '{since_iso}'")

    params = {
        "$order": f"{date_field} ASC",
        "$limit": limit,
    }
    if where_parts:
        params["$where"] = " AND ".join(where_parts)

    headers = {}
    token = os.environ.get("SOCRATA_APP_TOKEN")
    if token:
        headers["X-App-Token"] = token

    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

_ADDR_KEYS = ("address", "site_address", "full_address", "location",
              "project_address", "street_address")
_TYPE_KEYS = ("permit_type", "workclass", "record_type", "type",
              "permit_class", "work_type")
_DESC_KEYS = ("description", "work_description", "project_description",
              "scope_of_work", "comments")
_ID_KEYS   = ("permit_number", "record_id", "permit_id", "objectid",
              "id", "case_number")


def _first(raw, keys, default=""):
    """Return the first non-empty value from *raw* matching any key (case-insensitive)."""
    lower_map = {k.lower(): v for k, v in raw.items()} if raw else {}
    for k in keys:
        val = lower_map.get(k.lower())
        if val:
            return str(val).strip()
    return default


def normalize_permit(raw, source_name, state):
    """
    Convert a raw permit record into a normalized signal dict.

    Returns
    -------
    dict with keys: id, source, state, address, permit_type,
                    description, raw
    """
    address = _first(raw, _ADDR_KEYS)
    permit_type = _first(raw, _TYPE_KEYS, "unknown")
    description = _first(raw, _DESC_KEYS)
    record_id = _first(raw, _ID_KEYS)
    updated = str(raw.get("EditDate") or raw.get("updated_at") or "")

    # Deterministic ID: sha256(source|record_id|address|updated_ts)[:20]
    hash_input = f"{source_name}|{record_id}|{address}|{updated}"
    sig_id = hashlib.sha256(hash_input.encode()).hexdigest()[:20]

    return {
        "id": sig_id,
        "source": source_name,
        "state": state,
        "address": address,
        "permit_type": permit_type,
        "description": description,
        "raw": raw,
    }
