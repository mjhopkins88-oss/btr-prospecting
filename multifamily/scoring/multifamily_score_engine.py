"""
Multifamily Lead Score engine — 100-point model.

    Inbound intent:        40
    Insurance timing:      25
    Account fit:           20
    Pain potential:        10
    Relationship warmth:    5

Categories: Call Today (90-100), Hot (75-89), Warm (60-74),
Nurture (40-59), Watchlist (<40) — subject to the quality gates below.

Phase 2 quality gates (in order of application):
  1. Call Today requires a direct inbound action (benchmark form, meeting
     request, calculator submission, or quote request).
  2. Permit-only / news-only leads can never be Call Today.
  3. Hot requires inbound intent, known renewal timing, or a very strong
     acquisition/construction trigger — generic permit/refinance/financing
     triggers alone are not enough.
  4. Low-confidence or out-of-footprint (missing/unsupported state) leads
     are capped at Nurture, regardless of raw point total.

Every contribution and every gate decision is recorded twice: once as a
human-readable string (`reasons`) and once as a stable machine-readable
code (`reason_codes`), so the dashboard can explain *exactly* why a lead
was scored the way it was.
"""
from typing import List, Optional

from multifamily.types import MultifamilyLead, MultifamilyLeadScore, SIGNAL_SOURCES, SUPPORTED_STATES
from multifamily.scoring.multifamily_score_types import MAX_POINTS, category_for_score
from multifamily.scoring.multifamily_score_rules import (
    INBOUND_INTENT_POINTS,
    INSURANCE_TIMING_POINTS,
    ACCOUNT_FIT_POINTS,
    PAIN_POINTS,
    RELATIONSHIP_WARMTH_POINTS,
    CALL_TODAY_GATE_SIGNAL_TYPES,
    INBOUND_INTENT_SIGNAL_TYPES,
    RENEWAL_TIMING_KEYS,
    VERY_STRONG_TRIGGER_SIGNAL_TYPES,
    LOW_TRUST_ONLY_SOURCES,
    DIRECT_FORM_SIGNAL_TYPES,
    RENEWAL_WINDOW_DAYS,
    CONFIDENCE_THRESHOLD,
    PENALTY_MISSING_SOURCE_URL,
    PENALTY_UNKNOWN_ASSET_TYPE,
    PENALTY_UNKNOWN_STATE,
    UNKNOWN_ASSET_TYPE_VALUES,
)


def _timing_key_for_signal(signal) -> Optional[str]:
    """Map a raw signal to an insurance-timing rule key (renewal_date_known
    needs its days-until-renewal detail to pick the 120-day bucket)."""
    if signal.signal_type == 'renewal_date_known':
        days = signal.detail.get('days_until_renewal') if signal.detail else None
        if isinstance(days, (int, float)) and days <= RENEWAL_WINDOW_DAYS:
            return 'renewal_within_120'
        return 'renewal_known_beyond_120'
    if signal.signal_type in INSURANCE_TIMING_POINTS:
        return signal.signal_type
    return None


def _record(reasons: List[str], reason_codes: List[str], code: str, text: str) -> None:
    reason_codes.append(code)
    reasons.append(text)


def score_lead(lead: MultifamilyLead) -> MultifamilyLeadScore:
    reasons: List[str] = []
    reason_codes: List[str] = []

    # ---- Hard disqualification: missing source type ----------------------
    if not lead.primary_source or lead.primary_source not in SIGNAL_SOURCES:
        return MultifamilyLeadScore(
            total=0,
            category='watchlist',
            disqualified=True,
            disqualified_reason='missing_source_type',
            reasons=['Disqualified: lead has no recognized source type.'],
            reason_codes=['DISQUALIFIED_MISSING_SOURCE'],
            disqualifier_codes=['MISSING_SOURCE'],
        )

    signal_types_present = {s.signal_type for s in lead.signals}

    # ---- Inbound intent (max 40): strongest single inbound signal -------
    # Priority tier (highest first): benchmark form / quote / meeting (40)
    # > calculator / LinkedIn lead form (35) > guide download (25) >
    # repeat website visit (20) > paid search click (15) > single visit (8).
    inbound_intent = 0
    inbound_signal_type = None
    for st in signal_types_present:
        pts = INBOUND_INTENT_POINTS.get(st, 0)
        if pts > inbound_intent:
            inbound_intent, inbound_signal_type = pts, st
    if inbound_signal_type:
        _record(reasons, reason_codes, f'INBOUND_{inbound_signal_type.upper()}',
                f'+{inbound_intent} inbound intent ({inbound_signal_type})')

    # ---- Insurance timing (max 25): strongest single timing trigger -----
    insurance_timing = 0
    timing_key_hit = None
    for signal in lead.signals:
        key = _timing_key_for_signal(signal)
        if key is None:
            continue
        pts = INSURANCE_TIMING_POINTS.get(key, 0)
        if pts > insurance_timing:
            insurance_timing, timing_key_hit = pts, key
    if timing_key_hit:
        _record(reasons, reason_codes, f'TIMING_{timing_key_hit.upper()}',
                f'+{insurance_timing} insurance timing ({timing_key_hit})')

    # ---- Account fit (max 20): additive ----------------------------------
    raw_account_fit = 0
    company, prop = lead.company, lead.property
    if prop.unit_count is not None and prop.unit_count >= 100:
        raw_account_fit += ACCOUNT_FIT_POINTS['units_100_plus']
        _record(reasons, reason_codes, 'FIT_UNITS_100_PLUS', '+8 account fit (100+ units)')
    elif prop.unit_count is not None and prop.unit_count >= 50:
        raw_account_fit += ACCOUNT_FIT_POINTS['units_50_99']
        _record(reasons, reason_codes, 'FIT_UNITS_50_99', '+5 account fit (50-99 units)')
    if company.portfolio_property_count and company.portfolio_property_count > 1:
        raw_account_fit += ACCOUNT_FIT_POINTS['portfolio_multi_property']
        _record(reasons, reason_codes, 'FIT_PORTFOLIO_MULTI_PROPERTY', '+8 account fit (multiple properties / portfolio)')
    if company.is_owner_operator_developer:
        raw_account_fit += ACCOUNT_FIT_POINTS['owner_operator_developer']
        _record(reasons, reason_codes, 'FIT_OWNER_OPERATOR_DEVELOPER', '+5 account fit (owner/operator/developer)')
    if prop.state in SUPPORTED_STATES:
        raw_account_fit += ACCOUNT_FIT_POINTS['state_ca_tx']
        _record(reasons, reason_codes, 'FIT_STATE_CA_TX', '+4 account fit (CA/TX)')
    if company.decision_maker_role:
        raw_account_fit += ACCOUNT_FIT_POINTS['decision_maker_role']
        _record(reasons, reason_codes, 'FIT_DECISION_MAKER_ROLE', '+5 account fit (clear decision-maker role)')
    account_fit = min(raw_account_fit, MAX_POINTS['account_fit'])
    if raw_account_fit > account_fit:
        _record(reasons, reason_codes, 'FIT_CAPPED',
                f'Account fit capped at {account_fit} (raw {raw_account_fit}).')

    # ---- Pain potential (max 10): additive over declared pain flags -----
    raw_pain_potential = 0
    for flag in lead.pain_flags:
        pts = PAIN_POINTS.get(flag, 0)
        if pts:
            raw_pain_potential += pts
            _record(reasons, reason_codes, f'PAIN_{flag.upper()}', f'+{pts} pain potential ({flag})')
    pain_potential = min(raw_pain_potential, MAX_POINTS['pain_potential'])
    if raw_pain_potential > pain_potential:
        _record(reasons, reason_codes, 'PAIN_CAPPED',
                f'Pain potential capped at {pain_potential} (raw {raw_pain_potential}).')

    # ---- Relationship warmth (max 5): additive ---------------------------
    raw_relationship_warmth = 0
    for flag in lead.relationship_flags:
        pts = RELATIONSHIP_WARMTH_POINTS.get(flag, 0)
        if pts:
            raw_relationship_warmth += pts
            _record(reasons, reason_codes, f'RELATIONSHIP_{flag.upper()}', f'+{pts} relationship warmth ({flag})')
    relationship_warmth = min(raw_relationship_warmth, MAX_POINTS['relationship_warmth'])
    if raw_relationship_warmth > relationship_warmth:
        _record(reasons, reason_codes, 'RELATIONSHIP_CAPPED',
                f'Relationship warmth capped at {relationship_warmth} (raw {raw_relationship_warmth}).')

    # ---- Penalties --------------------------------------------------------
    penalties = 0
    if not lead.source_url and lead.primary_signal_type not in DIRECT_FORM_SIGNAL_TYPES and lead.primary_source != 'form':
        penalties += PENALTY_MISSING_SOURCE_URL
        _record(reasons, reason_codes, 'PENALTY_MISSING_SOURCE_URL', f'-{PENALTY_MISSING_SOURCE_URL} missing source URL')
    if prop.asset_type in UNKNOWN_ASSET_TYPE_VALUES:
        penalties += PENALTY_UNKNOWN_ASSET_TYPE
        _record(reasons, reason_codes, 'PENALTY_UNKNOWN_ASSET_TYPE', f'-{PENALTY_UNKNOWN_ASSET_TYPE} unknown asset type')
    if prop.state not in SUPPORTED_STATES:
        penalties += PENALTY_UNKNOWN_STATE
        _record(reasons, reason_codes, 'PENALTY_UNKNOWN_STATE', f'-{PENALTY_UNKNOWN_STATE} unknown/unsupported state')

    raw_total = inbound_intent + insurance_timing + account_fit + pain_potential + relationship_warmth - penalties
    total = max(0, min(100, raw_total))
    category = category_for_score(total)

    # ---- Disqualifier codes (quality flags, independent of hard disqualify) --
    disqualifier_codes: List[str] = []
    if lead.confidence is None or lead.confidence < CONFIDENCE_THRESHOLD:
        disqualifier_codes.append('LOW_CONFIDENCE')
    state_value = lead.state or prop.state
    if not state_value or state_value not in SUPPORTED_STATES:
        disqualifier_codes.append('MISSING_STATE')
    if prop.asset_type in UNKNOWN_ASSET_TYPE_VALUES:
        disqualifier_codes.append('UNKNOWN_ASSET_TYPE')
    if insurance_timing == 0:
        disqualifier_codes.append('MISSING_TIMING')
    if inbound_intent == 0:
        disqualifier_codes.append('NO_INBOUND_SIGNAL')

    # ---- Quality gates ------------------------------------------------------
    has_call_today_gate_signal = bool(signal_types_present & CALL_TODAY_GATE_SIGNAL_TYPES)
    has_inbound_intent_signal = bool(signal_types_present & INBOUND_INTENT_SIGNAL_TYPES)
    has_renewal_timing_signal = timing_key_hit in RENEWAL_TIMING_KEYS
    has_very_strong_trigger_signal = bool(signal_types_present & VERY_STRONG_TRIGGER_SIGNAL_TYPES)

    all_sources = {s.source for s in lead.signals}
    if lead.primary_source:
        all_sources.add(lead.primary_source)
    is_permit_or_news_only = bool(all_sources) and all_sources <= LOW_TRUST_ONLY_SOURCES

    # Gate 1: Call Today requires a direct inbound action.
    if category == 'call_today' and not has_call_today_gate_signal:
        category = 'hot'
        _record(reasons, reason_codes, 'GATE_CALL_TODAY_REQUIRES_DIRECT_ACTION',
                'Downgraded from Call Today: no benchmark form, meeting request, '
                'calculator submission, or quote request present.')

    # Gate 2: permit-only / news-only leads can never be Call Today.
    if category == 'call_today' and is_permit_or_news_only:
        category = 'hot'
        _record(reasons, reason_codes, 'GATE_CALL_TODAY_PERMIT_NEWS_ONLY',
                'Downgraded from Call Today: permit-only/news-only leads cannot be Call Today.')

    # Gate 3: Hot requires inbound intent, known renewal timing, or a very
    # strong acquisition/construction trigger.
    if category in ('call_today', 'hot') and not (
        has_inbound_intent_signal or has_renewal_timing_signal or has_very_strong_trigger_signal
    ):
        category = 'warm'
        _record(reasons, reason_codes, 'GATE_HOT_REQUIRES_QUALIFYING_SIGNAL',
                'Downgraded to Warm: no inbound intent, known renewal timing, or very '
                'strong acquisition/construction trigger present.')

    # Gate 4: low-confidence or out-of-footprint leads are capped at Nurture.
    if category in ('call_today', 'hot', 'warm') and (
        'LOW_CONFIDENCE' in disqualifier_codes or 'MISSING_STATE' in disqualifier_codes
    ):
        category = 'nurture'
        _record(reasons, reason_codes, 'GATE_QUALITY_CAP_LOW_CONFIDENCE_OR_MISSING_STATE',
                'Capped at Nurture: low-confidence signal or missing/unsupported state.')

    return MultifamilyLeadScore(
        total=total,
        category=category,
        inbound_intent=inbound_intent,
        insurance_timing=insurance_timing,
        account_fit=account_fit,
        pain_potential=pain_potential,
        relationship_warmth=relationship_warmth,
        penalties=penalties,
        reasons=reasons,
        reason_codes=reason_codes,
        disqualifier_codes=disqualifier_codes,
        disqualified=False,
    )
