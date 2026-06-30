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
    'permit', 'news', 'crm', 'manual',
]

# Sources that represent a real prospect taking inbound action (vs. a
# third-party trigger feed). Used to bucket leads into "Inbound Leads"
# regardless of whether the data is real or mock/demo.
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
]

SCORE_CATEGORIES = ['call_today', 'hot', 'warm', 'nurture', 'watchlist']

# v1 launch states only
SUPPORTED_STATES = ['CA', 'TX']

# Spam/abuse triage states for real (non-demo) leads — see multifamily/spam_guard.py.
SPAM_STATUSES = ['clean', 'suspicious', 'rejected']


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


@dataclass
class MultifamilyOutreachTask:
    id: str
    lead_id: str
    channel: str  # call | email | linkedin
    suggested_opener: str
    next_best_action: str
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
