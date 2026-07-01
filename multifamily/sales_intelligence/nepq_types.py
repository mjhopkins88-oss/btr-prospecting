"""
Core types for the Multifamily Sales Intelligence Engine.

This is a REASONING framework inspired by dialogue-based, question-led
selling principles (connection before pitch, situation -> problem
awareness -> solution awareness -> consequence -> qualifying -> transition
-> presentation -> commitment, neutral/calm/detached tone, self-discovery
over pressure). It does not reproduce or store any proprietary source
text — every string generated downstream (questions, messages, objection
responses) is original, multifamily-insurance-specific copy produced by
this codebase's own generators.

Plain string-constant lists + plain dataclasses (no ORM), matching the
rest of multifamily/types.py's convention, so every stage of the engine
can be exercised standalone from scripts and serialized via
dataclasses.asdict() for the API layer.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

LEAD_TEMPERATURES = ['call_today', 'hot', 'warm', 'nurture', 'watchlist']

LEAD_ORIGINS = [
    'inbound_form', 'benchmark_request', 'manual', 'website_intent', 'paid_search',
    'linkedin_lead_form', 'crm', 'permit_trigger', 'news_trigger', 'acquisition_trigger',
    'construction_trigger', 'referral', 'unknown',
]

INSURANCE_SCENARIOS = [
    'renewal_pressure', 'premium_increase', 'deductible_concern', 'lender_requirement',
    'acquisition_due_diligence', 'refinance_or_financing', 'builders_risk', 'construction_start',
    'completion_or_lease_up', 'gl_excess_concern', 'claims_or_service_issue',
    'just_benchmarking', 'unknown',
]

NEPQ_STAGES = [
    'connection', 'situation', 'problem_awareness', 'solution_awareness', 'consequence',
    'qualifying', 'transition', 'presentation', 'commitment', 'nurture',
]

BUYER_AWARENESS_LEVELS = ['unaware', 'problem_aware', 'solution_aware', 'vendor_comparing', 'decision_ready', 'unknown']

RESISTANCE_RISKS = ['low', 'medium', 'high']

RECOMMENDED_ACTIONS = [
    'call_now', 'send_soft_email', 'send_linkedin_note_manual', 'ask_for_context',
    'ask_for_renewal_timing', 'ask_for_current_program_details', 'ask_for_sov', 'ask_for_loss_runs',
    'schedule_benchmark_call', 'nurture', 'do_not_contact_yet',
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SalesLeadContext:
    """A complete, live-computed read of a lead for sales-reasoning
    purposes. Never persisted directly — derived fresh from the lead's
    current score/signals/timing/activity/outcome state (see
    lead_context_builder.py). Assembled facts + inferred facts."""
    lead_id: str
    company_name: str
    is_demo: bool

    # Assembled facts
    score_total: Optional[int] = None
    score_category: Optional[str] = None
    reason_codes: List[str] = field(default_factory=list)
    disqualifier_codes: List[str] = field(default_factory=list)
    pain_flags: List[str] = field(default_factory=list)
    relationship_flags: List[str] = field(default_factory=list)
    primary_source: Optional[str] = None
    signal_count: int = 0
    signal_types: List[str] = field(default_factory=list)
    process_stage: Optional[str] = None
    outreach_window: Optional[str] = None
    timing_reason: Optional[str] = None
    timing_confidence: Optional[str] = None
    lead_situation: Optional[str] = None
    asset_type: Optional[str] = None
    unit_count: Optional[int] = None
    state: Optional[str] = None
    city: Optional[str] = None
    contact_first_name: Optional[str] = None
    contact_title: Optional[str] = None
    renewal_date: Optional[str] = None
    days_until_renewal: Optional[float] = None
    project_start_date: Optional[str] = None
    utm_source: Optional[str] = None
    utm_campaign: Optional[str] = None
    activity_count: int = 0
    last_activity_type: Optional[str] = None
    replied: bool = False
    followup_due: bool = False
    current_outcome_type: Optional[str] = None
    spam_status: Optional[str] = None
    is_suspicious: bool = False

    # Inferred facts (set by lead_context_builder)
    lead_temperature: str = 'watchlist'
    lead_origin: str = 'unknown'
    insurance_scenario: str = 'unknown'
    buyer_awareness_level: str = 'unknown'
    resistance_risk: str = 'low'
    likely_decision_maker_type: Optional[str] = None
    likely_emotional_driver: Optional[str] = None
    missing_information: List[str] = field(default_factory=list)
    conversation_risk_notes: List[str] = field(default_factory=list)


@dataclass
class ConversationStrategy:
    """The engine's decision about HOW to approach this lead — before any
    copy is generated."""
    starting_nepq_stage: str
    primary_objective: str
    recommended_tone: str
    recommended_action: str
    ask_first: str
    do_not: List[str] = field(default_factory=list)
    should_present: bool = False
    call_now: bool = False
    ask_for_information: bool = False
    challenge_assumptions_carefully: bool = False
    move_toward_next_step: bool = False
    rule_applied: Optional[str] = None


@dataclass
class QuestionPath:
    connection_question: Optional[str] = None
    situation_questions: List[str] = field(default_factory=list)
    problem_awareness_questions: List[str] = field(default_factory=list)
    solution_awareness_questions: List[str] = field(default_factory=list)
    consequence_questions: List[str] = field(default_factory=list)
    qualifying_questions: List[str] = field(default_factory=list)
    transition_question: Optional[str] = None
    commitment_question: Optional[str] = None
    fallback_question: Optional[str] = None
    questions_to_avoid: List[str] = field(default_factory=list)


@dataclass
class MessagePackage:
    call_opener: str
    first_email_subject: str
    first_email_body: str
    linkedin_note_manual: str
    follow_up_1: str
    follow_up_2: str
    soft_bump: str
    meeting_confirmation_note: str
    info_request_note: str


@dataclass
class ObjectionResponse:
    objection_key: str
    likely_meaning: str
    disposition: str  # disengage | nurture | clarify | ask_resolving_question
    response: str
    follow_up_strategy: str
    what_not_to_say: List[str] = field(default_factory=list)


@dataclass
class SalesIntelligenceReasoning:
    selected_strategy: str
    selected_nepq_stage: str
    why_this_stage: str
    why_this_message: str
    key_lead_signals_used: List[str] = field(default_factory=list)
    assumed_pain_points: List[str] = field(default_factory=list)
    missing_information: List[str] = field(default_factory=list)
    what_to_avoid: List[str] = field(default_factory=list)
    confidence_score: float = 0.5
    recommended_next_step: str = ''


@dataclass
class SalesIntelligencePackage:
    """The full output for one lead: context + strategy + question path +
    messages + objection playbook + reasoning. This is what the API
    returns and what the UI (Workbench / drawer) renders."""
    lead_id: str
    variant: int
    context: SalesLeadContext
    strategy: ConversationStrategy
    question_path: QuestionPath
    messages: MessagePackage
    objection_playbook: List[ObjectionResponse]
    reasoning: SalesIntelligenceReasoning
