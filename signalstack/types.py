"""
SignalStack typed enums / schema-safe constants.

These are kept as plain Python constants (not Enum) so they serialize
trivially to JSON and work with both SQLite and Postgres TEXT columns.
A single ALLOWED set per category gives us strong validation without
forcing a DB-level enum migration story.
"""

# --- Prospect status ---
PROSPECT_STATUS = (
    "new",
    "researching",
    "queued",
    "contacted",
    "in_conversation",
    "meeting_booked",
    "won",
    "lost",
    "nurture",
)

# --- Signal categories ---
SIGNAL_TYPES = (
    "post_topic",
    "job_change",
    "company_expansion",
    "hiring_activity",
    "location_overlap",
    "shared_connection",
    "company_news",
    "role_change",
    "user_observation",
    "manual_context",
)

SIGNAL_SOURCES = (
    "manual",
    "linkedin_paste",
    "crm_sync",
    "public_web",
    "import",
)

# --- Messaging strategy layer ---
MESSAGE_TYPES = ("curiosity", "insight", "casual", "direct")

PRIMARY_TRIGGERS = (
    "curiosity",
    "self_relevance",
    "social_proof",
    "reciprocity",
    "loss_aversion",
    "authority",
    "liking",
)

COMMUNICATION_STYLES = ("direct", "conversational", "analytical")

OUTREACH_GOALS = (
    "start_conversation",
    "get_routed",
    "offer_insight",
    "build_familiarity",
)

# --- Message lifecycle ---
MESSAGE_STATUS = ("draft", "saved", "sent", "discarded")
MESSAGE_CHANNELS = ("linkedin_dm", "linkedin_inmail", "email", "other")

# --- Strategy modifiers ---
STRATEGY_MODIFIERS = (
    "low_pressure", "concise", "warmer", "sharper",
    "more_observational", "more_executive", "more_peer_like",
)

# --- Social-selling knowledge categories ---
PRINCIPLE_CATEGORIES = (
    "trust_building", "curiosity", "relevance", "specificity",
    "social_proof", "timing", "objection_softening",
    "conversational_tone", "authority_without_chest_beating",
    "anti_template",
)

# --- Outcomes (used for learning) ---
MESSAGE_OUTCOMES = (
    "no_response",
    "replied",
    "positive_reply",
    "meeting_booked",
    "negative",
)

# --- Knowledge dataset layer ---
KNOWLEDGE_SOURCE_TYPES = (
    "youtube_video",
    "article",
    "note",
    "playbook",
    "transcript",
    "framework",
    "manual_entry",
    "podcast",
    "other",
)

KNOWLEDGE_EXTRACTION_STATUS = (
    "RAW",
    "EXTRACTED",
    "REVIEWED",
    "ARCHIVED",
)

KNOWLEDGE_ENTRY_CATEGORIES = (
    "trust_building",
    "curiosity",
    "relevance",
    "specificity",
    "social_proof",
    "timing",
    "objection_softening",
    "conversational_tone",
    "authority_without_chest_beating",
    "anti_template",
    "framing",
    "outreach_angle",
    "industry_pattern",
    "tone",
    "other",
)


def validate(value: str, allowed: tuple, field: str) -> str:
    if value is None:
        return value
    if value not in allowed:
        raise ValueError(f"Invalid {field}: {value!r}. Allowed: {allowed}")
    return value
