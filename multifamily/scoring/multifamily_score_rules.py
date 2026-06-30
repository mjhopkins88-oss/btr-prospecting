"""
Point values and quality-gate rule tables for Multifamily Lead Score.

These are plain data tables (not a DB-backed rules engine) so they're easy
to read, tune, and unit test from scripts/test_multifamily_scoring.py.
"""

# ---- Inbound intent (max 40) ----------------------------------------------

INBOUND_INTENT_POINTS = {
    'benchmark_form_submit': 40,
    'quote_request': 40,
    'meeting_request': 40,
    'calculator_submit': 35,
    'linkedin_lead_form_submit': 35,
    'guide_download': 25,
    'repeat_website_visit': 20,
    'paid_search_click': 15,
    'website_visit': 8,
}

# Direct inbound actions required to ever reach "Call Today".
CALL_TODAY_GATE_SIGNAL_TYPES = {
    'benchmark_form_submit', 'quote_request', 'meeting_request', 'calculator_submit',
}

# Any of these counts as "inbound intent" for the Hot gate.
INBOUND_INTENT_SIGNAL_TYPES = set(INBOUND_INTENT_POINTS.keys())

# ---- Insurance timing (max 25) --------------------------------------------

RENEWAL_WINDOW_DAYS = 120

INSURANCE_TIMING_POINTS = {
    'renewal_within_120': 25,
    'renewal_known_beyond_120': 15,
    'acquisition': 18,
    'refinance': 18,
    'financing': 18,
    'groundbreaking': 18,
    'vertical_construction': 18,
    'permit_filed': 12,
    'planning_approval': 12,
}

# "Known renewal timing" — either renewal bucket — is one of the three
# qualifying paths to Hot (Phase 2 quality rule #3).
RENEWAL_TIMING_KEYS = {'renewal_within_120', 'renewal_known_beyond_120'}

# A "very strong" acquisition/construction trigger — the other non-inbound
# qualifying path to Hot. Deliberately narrower than INSURANCE_TIMING_POINTS:
# refinance/financing/permit_filed/planning_approval are real timing signals
# (they still earn points below) but are NOT considered strong enough, on
# their own, to unlock Hot — only an active acquisition or construction
# actually underway is.
VERY_STRONG_TRIGGER_SIGNAL_TYPES = {'acquisition', 'groundbreaking', 'vertical_construction'}

# Sources that, by themselves (no signal from any other source), make a lead
# "permit-only" or "news-only". These leads can never be Call Today, and can
# only be Hot via a very-strong trigger / renewal-timing / inbound signal
# (see VERY_STRONG_TRIGGER_SIGNAL_TYPES / RENEWAL_TIMING_KEYS above).
LOW_TRUST_ONLY_SOURCES = {'permit', 'news'}

# Signal types that are themselves a direct form submission — missing
# source_url shouldn't be penalized for these, since the submission *is*
# the source.
DIRECT_FORM_SIGNAL_TYPES = {
    'benchmark_form_submit', 'quote_request', 'meeting_request',
    'calculator_submit', 'linkedin_lead_form_submit',
}

# ---- Account fit (max 20) --------------------------------------------------

ACCOUNT_FIT_POINTS = {
    'units_100_plus': 8,
    'units_50_99': 5,
    'portfolio_multi_property': 8,
    'owner_operator_developer': 5,
    'state_ca_tx': 4,
    'decision_maker_role': 5,
}

# ---- Pain potential (max 10) -----------------------------------------------

PAIN_POINTS = {
    'premium_increase': 10,
    'deductible_concern': 8,
    'lender_requirement': 8,
    'cat_exposed_geography': 6,
    'builders_risk_need': 6,
    'gl_excess_concern': 5,
}

# ---- Relationship warmth (max 5) ------------------------------------------

RELATIONSHIP_WARMTH_POINTS = {
    'prior_reply': 5,
    'linkedin_connection': 3,
    'existing_client_or_referral': 5,
}

# ---- Penalties --------------------------------------------------------------

PENALTY_MISSING_SOURCE_URL = 5
PENALTY_UNKNOWN_ASSET_TYPE = 3
PENALTY_UNKNOWN_STATE = 5

UNKNOWN_ASSET_TYPE_VALUES = {None, '', 'unknown'}

# ---- Confidence floor ------------------------------------------------------

# Below this, a lead is flagged LOW_CONFIDENCE and capped at Nurture
# regardless of raw point total — thin/low-certainty signals (e.g. a vague
# news mention) shouldn't surface as Hot/Call Today just because other
# components happen to add up.
CONFIDENCE_THRESHOLD = 0.4

# ---- Disqualifier codes -----------------------------------------------------
# Quality flags surfaced on every score (MultifamilyLeadScore.disqualifier_codes)
# so the dashboard and daily brief can explain exactly why a lead needs more
# info, independent of the hard "missing source type" disqualification.

DISQUALIFIER_CODE_DESCRIPTIONS = {
    'MISSING_SOURCE': 'No recognized source type — lead cannot be scored or routed.',
    'LOW_CONFIDENCE': f'Signal confidence is below {CONFIDENCE_THRESHOLD} — capped at Nurture.',
    'MISSING_STATE': 'Property state is missing or outside the CA/TX launch footprint.',
    'UNKNOWN_ASSET_TYPE': 'Asset type is missing or unknown.',
    'MISSING_TIMING': 'No insurance-timing signal (renewal, acquisition, financing, or construction) present.',
    'NO_INBOUND_SIGNAL': 'No inbound-intent signal (form, calculator, guide download, repeat visit, paid click, or LinkedIn form) present.',
}
