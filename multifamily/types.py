"""
Core data types for Multifamily Command.

Plain dataclasses (no ORM/DB dependency) so the mock signal collectors,
scoring engine, and outreach generators can be exercised directly from
scripts without a database. The Flask API layer (api/routes/multifamily.py)
serializes these via dataclasses.asdict().
"""
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Enumerations (plain string constants — no DB enum types involved)
# ---------------------------------------------------------------------------

SIGNAL_SOURCES = [
    'website', 'form', 'benchmark_form', 'search_console', 'google_ads', 'linkedin_lead_form',
    'permit', 'news', 'crm', 'manual', 'serp',
]

# Sources that represent a real prospect taking inbound action (vs. a
# third-party trigger feed). Used to bucket leads into "Inbound Leads"
# regardless of whether the data is real or mock/demo. 'serp' is
# deliberately excluded — a search-engine result is a third-party trigger,
# not the prospect reaching out, same treatment as 'permit'/'news'.
INBOUND_INTENT_SOURCES = {
    'form', 'benchmark_form', 'manual', 'website', 'search_console', 'google_ads', 'linkedin_lead_form',
}

SIGNAL_TYPES = [
    'benchmark_form_submit', 'quote_request', 'meeting_request',
    'guide_download', 'calculator_submit', 'website_visit',
    'repeat_website_visit', 'keyword_intent', 'paid_search_click',
    'linkedin_lead_form_submit', 'renewal_date_known', 'acquisition',
    'refinance', 'financing', 'permit_filed', 'planning_approval',
    'groundbreaking', 'vertical_construction', 'completion',
    'portfolio_growth',
    # SERP-only market-context signals (multifamily/serp/). Deliberately
    # absent from every scoring-weight table in multifamily_score_rules.py
    # (INBOUND_INTENT_POINTS, INSURANCE_TIMING_POINTS, CALL_TODAY_GATE_
    # SIGNAL_TYPES, VERY_STRONG_TRIGGER_SIGNAL_TYPES) — they contribute zero
    # points and fall through to the timing detector's general_watchlist
    # fallback, same as a generic website visit.
    'insurance_market_pressure', 'market_mention',
]

SCORE_CATEGORIES = ['call_today', 'hot', 'warm', 'nurture', 'watchlist']

# v1 launch states only
SUPPORTED_STATES = ['CA', 'TX']

# Spam/abuse triage states for real (non-demo) leads — see multifamily/spam_guard.py.
SPAM_STATUSES = ['clean', 'suspicious', 'rejected']

# Manual activity types for lightweight follow-up tracking (Part 7).
# No automation — these are logged by an operator after a manual action.
ACTIVITY_TYPES = [
    'called', 'emailed', 'linkedin_sent', 'replied', 'meeting_booked',
    'not_a_fit', 'moved_to_nurture', 'needs_info', 'follow_up_due',
]

# ---- Outcome tracking (outcome/snapshot/notification phase) --------------
# Real business outcomes recorded against a lead (multifamily_lead_outcomes).
# Append-only event log — `current_outcome` on multifamily_leads always
# reflects the LATEST recorded event (by outcome_date, tie-broken by
# created_at), so filtering/reporting never has to replay history.
OUTCOME_TYPES = [
    'meeting_booked', 'submission_received', 'sov_received', 'loss_runs_received',
    'application_received', 'quote_started', 'quote_sent',
    'won', 'lost', 'not_a_fit', 'nurture', 'dead',
]

# Rough funnel ordering for reporting (not used to gate transitions — an
# operator can record outcomes in any order/re-record the same type).
OUTCOME_FUNNEL_RANK = {
    'meeting_booked': 1, 'submission_received': 2, 'sov_received': 3,
    'loss_runs_received': 3, 'application_received': 3, 'quote_started': 4,
    'quote_sent': 5, 'won': 6, 'lost': 6, 'not_a_fit': 6, 'nurture': 6, 'dead': 6,
}

# Terminal outcomes — the deal is closed one way or another.
OUTCOME_TERMINAL_TYPES = {'won', 'lost', 'not_a_fit', 'dead'}

# ---- Signal architecture / dedupe-merge (signal-architecture phase) ----
# Source-attribution touch types (multifamily_source_attribution).
ATTRIBUTION_TOUCH_TYPES = ['first', 'latest', 'conversion', 'touch']

# How confidently an incoming signal matched an existing lead.
#   auto    -> exact email OR exact normalized company+property+contact (auto-merge)
#   review  -> a fuzzy/partial match that needs a human to confirm
#   none    -> no candidate found (new lead)
MATCH_TIERS = ['auto', 'review', 'none']

# Lifecycle of a queued match candidate (multifamily_lead_match_candidates).
MATCH_CANDIDATE_STATUSES = ['pending', 'merged', 'dismissed']

# Pilot Campaign Control Center — a controlled outbound/manual
# prospecting effort tied to one specific offer page (multifamily_campaigns).
CAMPAIGN_STATUSES = ['draft', 'active', 'paused', 'completed']

# Lifecycle of one prospect inside a campaign (multifamily_campaign_targets).
# Mirrors ACTIVITY_TYPES' vocabulary where they overlap (contacted/replied/
# meeting_booked/not_fit/nurture) so a target with a lead can log a matching
# lead activity on every status transition.
CAMPAIGN_TARGET_STATUSES = [
    'planned', 'contacted', 'replied', 'converted', 'meeting_booked', 'not_fit', 'nurture',
]

# Whether a lead row is the live survivor or has been merged away.
MERGE_STATUSES = ['active', 'merged']


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    return datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------

@dataclass
class MultifamilyCompany:
    id: str
    name: str
    company_type: Optional[str] = None  # owner | operator | developer | manager
    is_owner_operator_developer: bool = False
    portfolio_property_count: int = 1
    decision_maker_role: Optional[str] = None
    domain: Optional[str] = None


@dataclass
class MultifamilyProperty:
    id: str
    name: str
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    unit_count: Optional[int] = None
    asset_type: Optional[str] = None  # garden | mid_rise | high_rise | mixed_use | unknown
    cat_exposed: bool = False
    company_id: Optional[str] = None


@dataclass
class MultifamilyContact:
    id: str
    full_name: str
    title: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin_url: Optional[str] = None
    is_decision_maker: bool = False
    company_id: Optional[str] = None


@dataclass
class MultifamilySignal:
    id: str
    signal_type: str
    source: str
    source_url: Optional[str] = None
    confidence: float = 0.5
    occurred_at: str = field(default_factory=utc_now_iso)
    detail: Dict[str, Any] = field(default_factory=dict)
    property_id: Optional[str] = None
    company_id: Optional[str] = None


@dataclass
class MultifamilyWebsiteIntentEvent:
    id: str
    event_type: str  # website_visit | repeat_website_visit
    page: str
    visit_count: int = 1
    state: Optional[str] = None
    occurred_at: str = field(default_factory=utc_now_iso)


@dataclass
class MultifamilySearchIntentKeyword:
    id: str
    keyword: str
    source: str  # search_console | google_ads
    clicks: int = 0
    impressions: int = 0
    landing_page: Optional[str] = None
    high_intent: bool = False


@dataclass
class MultifamilyMarketIntelEvent:
    id: str
    event_type: str  # acquisition | refinance | financing | permit_filed | ...
    headline: str
    source_url: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    occurred_at: str = field(default_factory=utc_now_iso)


@dataclass
class MultifamilyLeadScore:
    total: int
    category: str
    inbound_intent: int = 0
    insurance_timing: int = 0
    account_fit: int = 0
    pain_potential: int = 0
    relationship_warmth: int = 0
    penalties: int = 0
    reasons: List[str] = field(default_factory=list)
    # Stable, machine-readable counterparts to `reasons` (e.g.
    # 'INBOUND_BENCHMARK_FORM_SUBMIT', 'GATE_HOT_REQUIRES_QUALIFYING_SIGNAL')
    # so API/UI consumers can branch on codes instead of parsing text.
    reason_codes: List[str] = field(default_factory=list)
    # Quality flags (e.g. 'LOW_CONFIDENCE', 'MISSING_STATE') — independent of
    # the hard `disqualified` flag below, used to drive the Nurture quality
    # cap and the daily brief's "needs more info" bucket.
    disqualifier_codes: List[str] = field(default_factory=list)
    disqualified: bool = False
    disqualified_reason: Optional[str] = None


@dataclass
class MultifamilySourceRun:
    id: str
    source: str
    started_at: str
    completed_at: Optional[str] = None
    records_found: int = 0
    is_mock: bool = True
    notes: Optional[str] = None
    # Persisted source-run accounting (multifamily_source_runs). Future
    # automated collectors open a run, then close it with these counts.
    run_id: Optional[str] = None          # external/batch run id (defaults to `id`)
    status: str = 'running'               # running | success | error
    records_created: int = 0
    records_updated: int = 0
    records_merged: int = 0
    records_rejected: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class MultifamilySourceAttribution:
    """One attribution touch on a lead (multifamily_source_attribution).
    Append-only — first/latest/conversion are derived from the touch
    history, and the UTM/landing/referrer path is the ordered list of
    these rows."""
    id: str
    lead_id: str
    touch_type: str  # one of ATTRIBUTION_TOUCH_TYPES
    source: Optional[str] = None
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    utm_term: Optional[str] = None
    utm_content: Optional[str] = None
    referrer: Optional[str] = None
    landing_page: Optional[str] = None
    offer_type: Optional[str] = None
    page_variant: Optional[str] = None
    campaign_id: Optional[str] = None
    occurred_at: str = field(default_factory=utc_now_iso)
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class MultifamilyLeadMatchCandidate:
    """A possible match between an incoming signal/lead and an existing
    lead that needs human review (multifamily_lead_match_candidates).
    Auto-tier matches are merged immediately and never queued here."""
    id: str
    incoming_signal_id: Optional[str]
    candidate_lead_id: str
    match_tier: str  # one of MATCH_TIERS ('review' for queued candidates)
    match_reasons: List[str] = field(default_factory=list)
    score: float = 0.0
    status: str = 'pending'  # one of MATCH_CANDIDATE_STATUSES
    resolved_by: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    resolved_at: Optional[str] = None


@dataclass
class MultifamilyOutboundLink:
    """A token minted for outbound-to-form conversion (Funnel Phase 3):
    an operator working `lead_id` generates a link to a specific offer
    page for that prospect (e.g. an acquisition-review link to send by
    email); when the prospect fills out that page carrying `?mf_ref=token`,
    intake looks the token up and merges the submission straight into
    `lead_id` deterministically — bypassing fuzzy matching entirely,
    since the identity is already known. `token` is the primary key so
    the URL never needs to encode `lead_id` directly."""
    token: str
    lead_id: str
    offer_type: Optional[str] = None
    page_variant: Optional[str] = None
    campaign_id: Optional[str] = None
    source: Optional[str] = None  # e.g. 'outbound_email' | 'outbound_call' | 'outbound_message'
    created_by: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    converted_at: Optional[str] = None
    converted_lead_id: Optional[str] = None


@dataclass
class MultifamilyCampaign:
    """A controlled outbound/manual prospecting effort tied to ONE
    specific offer page (Pilot Campaign Control Center) — e.g. "Texas
    Renewal Pressure Test" or "Builder's Risk Review — Active
    Development Prospects". `offer_type` is always derived from
    `page_variant` at write time (multifamily/forms/form_variants.py is
    the single source of truth — never store it independently, to avoid
    it drifting out of sync with the variant)."""
    id: str
    name: str
    page_variant: str  # one of multifamily.forms.form_variants.FORM_VARIANT_SLUGS
    offer_type: str  # derived from page_variant, not independently set
    description: Optional[str] = None
    target_state: Optional[str] = None
    target_city: Optional[str] = None
    target_segment: Optional[str] = None
    campaign_source: Optional[str] = None  # e.g. 'manual_outreach' | 'email' | 'linkedin'
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    status: str = 'draft'  # one of CAMPAIGN_STATUSES
    created_by: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass
class MultifamilyCampaignTarget:
    """One prospect inside a campaign (multifamily_campaign_targets).
    May start with NO lead at all (a cold prospect Max is about to
    reach out to) — `lead_id` is backfilled once the target converts
    (either by resolving to an existing lead via the normal matching
    engine, or by becoming a brand-new one). `tracking_token` is this
    target's own unique token (distinct from multifamily_outbound_links'
    token, which is for one-off ad-hoc drawer-generated links) — the
    campaign's tracked URL is derived from campaign.page_variant +
    this token + the campaign's utm_* fields, never stored redundantly."""
    id: str
    campaign_id: str
    tracking_token: str
    company: Optional[str] = None
    contact_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin_url: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    segment: Optional[str] = None
    lead_id: Optional[str] = None
    status: str = 'planned'  # one of CAMPAIGN_TARGET_STATUSES
    notes: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    last_activity_at: Optional[str] = None
    converted_at: Optional[str] = None


@dataclass
class MultifamilyActivity:
    """A manually-logged outreach/follow-up activity on a lead (Part 7).
    Persisted in the multifamily_activities table. Never auto-generated —
    an operator logs it after a real call/email/LinkedIn touch."""
    id: str
    lead_id: str
    activity_type: str  # one of ACTIVITY_TYPES
    note: Optional[str] = None
    next_follow_up_date: Optional[str] = None  # ISO date (YYYY-MM-DD)
    user_email: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class MultifamilyOutcome:
    """One recorded business-outcome event on a lead
    (multifamily_lead_outcomes). Append-only — `current_outcome`/
    `current_outcome_at` on multifamily_leads is a cache of the latest
    event, kept in sync by repository.record_outcome. Real leads only —
    demo lead ids regenerate every pipeline run, so outcomes never
    meaningfully attach to them."""
    id: str
    lead_id: str
    outcome_type: str  # one of OUTCOME_TYPES
    outcome_date: str = field(default_factory=utc_now_iso)
    estimated_premium: Optional[float] = None
    estimated_revenue: Optional[float] = None
    quoted_premium: Optional[float] = None
    bound_premium: Optional[float] = None
    effective_date: Optional[str] = None
    renewal_date: Optional[str] = None
    lost_reason: Optional[str] = None
    won_reason: Optional[str] = None
    notes: Optional[str] = None
    created_by: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class MultifamilyLead:
    id: str
    company: MultifamilyCompany
    property: MultifamilyProperty
    signals: List[MultifamilySignal]
    contacts: List[MultifamilyContact] = field(default_factory=list)
    state: Optional[str] = None
    city: Optional[str] = None
    primary_signal_type: Optional[str] = None
    primary_source: Optional[str] = None
    source_url: Optional[str] = None
    source_page: Optional[str] = None
    confidence: float = 0.5
    last_verified_at: str = field(default_factory=utc_now_iso)
    pain_flags: List[str] = field(default_factory=list)
    relationship_flags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    # True for mock/demo leads from the signal collectors; False for real
    # leads captured through POST /api/multifamily/leads. The dashboard
    # must never show is_demo leads without a clear "Demo Data" label, and
    # real leads always take priority over demo leads in any given view.
    is_demo: bool = False

    # ---- Source/UTM attribution (real intake only — see multifamily/intake.py) ----
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    utm_term: Optional[str] = None
    utm_content: Optional[str] = None
    referrer: Optional[str] = None
    landing_page: Optional[str] = None
    offer_type: Optional[str] = None
    # Which form-variant page produced this lead (multifamily/forms/form_variants.py
    # slug, e.g. 'renewal-pressure') and which outreach campaign drove the
    # visit, if any. Both optional/additive — a lead with neither is exactly
    # today's benchmark-form behavior.
    page_variant: Optional[str] = None
    campaign_id: Optional[str] = None

    # ---- Spam/abuse signal (real intake only — see multifamily/spam_guard.py) ----
    # 'clean' | 'suspicious' | 'rejected'. Only 'rejected' leads are excluded
    # from normal dashboard views (repository.get_real_leads()).
    spam_status: str = 'clean'
    spam_reason_codes: List[str] = field(default_factory=list)
    submitted_ip_hash: Optional[str] = None
    user_agent_summary: Optional[str] = None

    score: Optional[MultifamilyLeadScore] = None
    why_warm: Optional[str] = None
    likely_pain: Optional[str] = None
    next_best_action: Optional[str] = None
    suggested_opener: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
