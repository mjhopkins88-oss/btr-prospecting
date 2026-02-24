"""
Canonical underwriting column definitions.

Single source of truth for:
  - Spreadsheet grid column order + headers
  - Intake form field mapping
  - XLSX export column order + formatting
  - DB column names

Every header matches the master spreadsheet EXACTLY.
"""

UNDERWRITING_COLUMNS = [
    # ── Location ───────────────────────────────────────────────
    {"header": "Location Name",                "key": "location_name",                "type": "text",     "section": "location",     "required": True},
    {"header": "Location ID",                  "key": "location_id",                  "type": "text",     "section": "location"},
    {"header": "Latitude",                     "key": "latitude",                     "type": "numeric",  "section": "location"},
    {"header": "Longitude",                    "key": "longitude",                    "type": "numeric",  "section": "location"},
    {"header": "Location Street Address",      "key": "location_street_address",      "type": "text",     "section": "location"},
    {"header": "Postal/zip Code",              "key": "postal_zip_code",              "type": "text",     "section": "location"},
    {"header": "City",                         "key": "city",                         "type": "text",     "section": "location",     "required": True},
    {"header": "County",                       "key": "county",                       "type": "text",     "section": "location"},
    {"header": "State / Province / District",  "key": "state_province_district",      "type": "text",     "section": "location",     "required": True},
    {"header": "Country",                      "key": "country",                      "type": "text",     "section": "location"},
    {"header": "Currency",                     "key": "currency",                     "type": "text",     "section": "location"},

    # ── Values ─────────────────────────────────────────────────
    {"header": "Buildings Values",             "key": "buildings_values",             "type": "currency", "section": "values"},
    {"header": "Contents Values",              "key": "contents_values",              "type": "currency", "section": "values"},
    {"header": "12 month BI Values",           "key": "bi_values_12m",               "type": "currency", "section": "values"},
    {"header": "Total BI Values",              "key": "total_bi_values",             "type": "currency", "section": "values"},
    {"header": "BI Period (number of days)",   "key": "bi_period_days",              "type": "integer",  "section": "values"},

    # ── Construction ───────────────────────────────────────────
    {"header": "Client Construction description",   "key": "client_construction_desc",   "type": "text",    "section": "construction"},
    {"header": "RMS Construction Numeric code",     "key": "rms_construction_code",      "type": "text",    "section": "construction"},
    {"header": "RMS Construction Description",      "key": "rms_construction_desc",      "type": "text",    "section": "construction"},
    {"header": "Client Occupancy Description",      "key": "client_occupancy_desc",      "type": "text",    "section": "construction"},
    {"header": "RMS Occupancy Numeric code",        "key": "rms_occupancy_code",         "type": "text",    "section": "construction"},
    {"header": "RMS Occupancy description (what the risk is used for)", "key": "rms_occupancy_desc", "type": "text", "section": "construction"},

    # ── Building Details ───────────────────────────────────────
    {"header": "Year built",                   "key": "year_built",                   "type": "integer",  "section": "building"},
    {"header": "Year structurally upgraded",   "key": "year_structurally_upgraded",   "type": "integer",  "section": "building"},
    {"header": "Number of stories",            "key": "number_of_stories",            "type": "integer",  "section": "building"},
    {"header": "Floor Area Per Unit",          "key": "floor_area_per_unit",          "type": "numeric",  "section": "building"},
    {"header": "Floor Area Per Building",      "key": "floor_area_per_building",      "type": "numeric",  "section": "building"},
    {"header": "Floor Area Unit",              "key": "floor_area_unit",              "type": "text",     "section": "building"},
    {"header": "Roof updated",                 "key": "roof_updated",                 "type": "text",     "section": "building"},
    {"header": "Number of Units",              "key": "number_of_units",              "type": "integer",  "section": "building",     "required": True},
    {"header": "Number of buildings at location", "key": "number_of_buildings",       "type": "integer",  "section": "building"},
    {"header": "Inception Date",               "key": "inception_date",               "type": "date",     "section": "building"},

    # ── Roof & Structure ──────────────────────────────────────
    {"header": "Roof Covering",                "key": "roof_covering",                "type": "text",     "section": "structure"},
    {"header": "Roof Geometry",                "key": "roof_geometry",                "type": "text",     "section": "structure"},
    {"header": "Roof Age / Condition",         "key": "roof_age_condition",           "type": "text",     "section": "structure"},
    {"header": "Roof Anchor",                  "key": "roof_anchor",                  "type": "text",     "section": "structure"},
    {"header": "Construction Quality",         "key": "construction_quality",         "type": "text",     "section": "structure"},
    {"header": "Cladding Type",                "key": "cladding_type",                "type": "text",     "section": "structure"},
    {"header": "First Floor Height",           "key": "first_floor_height",           "type": "text",     "section": "structure"},
    {"header": "Basement",                     "key": "basement",                     "type": "text",     "section": "structure"},
    {"header": "Basement Protection",          "key": "basement_protection",          "type": "text",     "section": "structure"},
    {"header": "Flood Protection",             "key": "flood_protection",             "type": "text",     "section": "structure"},
    {"header": "Flood Zones",                  "key": "flood_zones",                  "type": "text",     "section": "structure"},
    {"header": "Ice Dam Protection",           "key": "ice_dam_protection",           "type": "text",     "section": "structure"},
    {"header": "Plumbing",                     "key": "plumbing",                     "type": "text",     "section": "structure"},
    {"header": "Insulation",                   "key": "insulation",                   "type": "text",     "section": "structure"},
    {"header": "Attic Insulation",             "key": "attic_insulation",             "type": "text",     "section": "structure"},
    {"header": "Roof Ventilation",             "key": "roof_ventilation",             "type": "text",     "section": "structure"},
    {"header": "Snow Guards",                  "key": "snow_guards",                  "type": "text",     "section": "structure"},
    {"header": "Tree Density",                 "key": "tree_density",                 "type": "text",     "section": "structure"},
    {"header": "Sprinkler",                    "key": "sprinkler",                    "type": "text",     "section": "structure"},
    {"header": "Leased %",                     "key": "leased_pct",                   "type": "percent",  "section": "structure"},
    {"header": "Renter's Insurance Required",  "key": "renters_insurance_required",   "type": "text",     "section": "structure"},

    # ── Premium & Tax ─────────────────────────────────────────
    {"header": "12 month Premium + Taxes",     "key": "premium_taxes_12m",            "type": "currency", "section": "premium"},
    {"header": "14 month premium",             "key": "premium_14m",                  "type": "currency", "section": "premium"},
    {"header": "Tax",                          "key": "tax",                          "type": "currency", "section": "premium"},
    {"header": "Ded buy Down Premium",         "key": "ded_buy_down_premium",         "type": "currency", "section": "premium"},
    {"header": "GL Tax",                       "key": "gl_tax",                       "type": "currency", "section": "premium"},
    {"header": "Excess Tax",                   "key": "excess_tax",                   "type": "currency", "section": "premium"},
    {"header": "Terrorism",                    "key": "terrorism",                    "type": "currency", "section": "premium"},
    {"header": "Falling Water",                "key": "falling_water",                "type": "text",     "section": "premium"},
]

# Derived helpers
COLUMN_KEYS = [c["key"] for c in UNDERWRITING_COLUMNS]
HEADER_MAP = {c["key"]: c["header"] for c in UNDERWRITING_COLUMNS}
KEY_MAP = {c["header"]: c["key"] for c in UNDERWRITING_COLUMNS}
COLUMN_TYPES = {c["key"]: c["type"] for c in UNDERWRITING_COLUMNS}
SECTIONS = {}
for c in UNDERWRITING_COLUMNS:
    SECTIONS.setdefault(c.get("section", "other"), []).append(c)
