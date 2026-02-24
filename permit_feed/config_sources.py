"""
Permit feed source definitions.

Each source dict has:
  name          — human-readable label
  type          — "arcgis" or "socrata"
  state         — two-letter state code
  max_per_run   — cap per source (≤200)

ArcGIS sources additionally have:
  feature_layer_url  — URL of the ArcGIS Feature Layer
  where              — base SQL-like where clause
  date_field         — field used for date cursor

Socrata sources additionally have:
  domain       — Socrata host (e.g. data.example.gov)
  dataset_id   — 4x4 dataset identifier
  date_field   — column used for date cursor
  where        — optional SoQL where filter
"""

SOURCES = [
    # ── Texas ──────────────────────────────────────────────────
    {
        "name": "tx_dallas_permits",
        "type": "arcgis",
        "state": "TX",
        "max_per_run": 200,
        # TODO: replace with real ArcGIS Feature Layer endpoint for Dallas permits
        "feature_layer_url": "https://services.arcgis.com/PLACEHOLDER_DALLAS/arcgis/rest/services/Permits/FeatureServer/0",
        "where": "1=1",
        "date_field": "EditDate",
    },
    {
        "name": "tx_houston_permits",
        "type": "socrata",
        "state": "TX",
        "max_per_run": 200,
        # TODO: replace with real Socrata domain and dataset ID for Houston permits
        "domain": "data.houstontx.gov",
        "dataset_id": "PLACEHOLDER",
        "date_field": "updated_at",
        "where": "",
    },
    # ── Arizona ────────────────────────────────────────────────
    {
        "name": "az_phoenix_permits",
        "type": "arcgis",
        "state": "AZ",
        "max_per_run": 200,
        # TODO: replace with real ArcGIS Feature Layer endpoint for Phoenix permits
        "feature_layer_url": "https://services.arcgis.com/PLACEHOLDER_PHOENIX/arcgis/rest/services/Permits/FeatureServer/0",
        "where": "1=1",
        "date_field": "EditDate",
    },
    {
        "name": "az_maricopa_permits",
        "type": "socrata",
        "state": "AZ",
        "max_per_run": 200,
        # TODO: replace with real Socrata domain and dataset ID for Maricopa County
        "domain": "data.maricopacounty.gov",
        "dataset_id": "PLACEHOLDER",
        "date_field": "updated_date",
        "where": "",
    },
]
