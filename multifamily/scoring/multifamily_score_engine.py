"""
Multifamily Lead Score engine — 100-point model.

    Inbound intent:        40
    Insurance timing:      25
    Account fit:           20
    Pain potential:        10
    Relationship warmth:    5

Categories: Call Today (90-100), Hot (75-89), Warm (60-74),
Nurture (40-59), Watchlist (<40) — subject to the quality gates below.
"""
from typing import Optional

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
    STRONG_TIMING_SIGNAL_TYPES,
    LOW_TRUST_ONLY_SOURCES,
    DIRECT_FORM_SIGNAL_TYPES,
    RENEWAL_WINDOW_DAYS,
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


def score_lead(lead: MultifamilyLead) -> MultifamilyLeadScore:
    reasons = []

    # ---- Disqualification: missing source type --------------------------
    if not lead.primary_source or lead.primary_source not in SIGNAL_SOURCES:
        return MultifamilyLeadScore(
            total=0,
            category='watchlist',
            disqualified=True,
            disqualified_reason='missing_source_type',
            reasons=['Disqualified: lead has no recognized source type.'],
        )

    signal_types_present = {s.signal_type for s in lead.signals}

    # ---- Inbound intent (max 40): strongest single inbound signal -------
    inbound_intent = 0
    inbound_signal_type = None
    for st in signal_types_present:
        pts = INBOUND_INTENT_POINTS.get(st, 0)
        if pts > inbound_intent:
            inbound_intent, inbound_signal_type = pts, st
    if inbound_signal_type:
        reasons.append(f'+{inbound_intent} inbound intent ({inbound_signal_type})')

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
        reasons.append(f'+{insurance_timing} insurance timing ({timing_key_hit})')

    # ---- Account fit (max 20): additive ----------------------------------
    account_fit = 0
    company, prop = lead.company, lead.property
    if prop.unit_count is not None and prop.unit_count >= 100:
        account_fit += ACCOUNT_FIT_POINTS['units_100_plus']
        reasons.append('+8 account fit (100+ units)')
    elif prop.unit_count is not None and prop.unit_count >= 50:
        account_fit += ACCOUNT_FIT_POINTS['units_50_99']
        reasons.append('+5 account fit (50-99 units)')
    if company.portfolio_property_count and company.portfolio_property_count > 1:
        account_fit += ACCOUNT_FIT_POINTS['portfolio_multi_property']
        reasons.append('+8 account fit (multiple properties / portfolio)')
    if company.is_owner_operator_developer:
        account_fit += ACCOUNT_FIT_POINTS['owner_operator_developer']
        reasons.append('+5 account fit (owner/operator/developer)')
    if prop.state in SUPPORTED_STATES:
        account_fit += ACCOUNT_FIT_POINTS['state_ca_tx']
        reasons.append('+4 account fit (CA/TX)')
    if company.decision_maker_role:
        account_fit += ACCOUNT_FIT_POINTS['decision_maker_role']
        reasons.append('+5 account fit (clear decision-maker role)')
    account_fit = min(account_fit, MAX_POINTS['account_fit'])

    # ---- Pain potential (max 10): additive over declared pain flags -----
    pain_potential = 0
    for flag in lead.pain_flags:
        pts = PAIN_POINTS.get(flag, 0)
        if pts:
            pain_potential += pts
            reasons.append(f'+{pts} pain potential ({flag})')
    pain_potential = min(pain_potential, MAX_POINTS['pain_potential'])

    # ---- Relationship warmth (max 5): additive ---------------------------
    relationship_warmth = 0
    for flag in lead.relationship_flags:
        pts = RELATIONSHIP_WARMTH_POINTS.get(flag, 0)
        if pts:
            relationship_warmth += pts
            reasons.append(f'+{pts} relationship warmth ({flag})')
    relationship_warmth = min(relationship_warmth, MAX_POINTS['relationship_warmth'])

    # ---- Penalties --------------------------------------------------------
    penalties = 0
    if not lead.source_url and lead.primary_signal_type not in DIRECT_FORM_SIGNAL_TYPES and lead.primary_source != 'form':
        penalties += PENALTY_MISSING_SOURCE_URL
        reasons.append(f'-{PENALTY_MISSING_SOURCE_URL} missing source URL')
    if prop.asset_type in UNKNOWN_ASSET_TYPE_VALUES:
        penalties += PENALTY_UNKNOWN_ASSET_TYPE
        reasons.append(f'-{PENALTY_UNKNOWN_ASSET_TYPE} unknown asset type')
    if prop.state not in SUPPORTED_STATES:
        penalties += PENALTY_UNKNOWN_STATE
        reasons.append(f'-{PENALTY_UNKNOWN_STATE} unknown/unsupported state')

    raw_total = inbound_intent + insurance_timing + account_fit + pain_potential + relationship_warmth - penalties
    total = max(0, min(100, raw_total))
    category = category_for_score(total)

    # ---- Quality gates ------------------------------------------------------
    has_call_today_gate_signal = bool(signal_types_present & CALL_TODAY_GATE_SIGNAL_TYPES)
    has_inbound_intent_signal = bool(signal_types_present & INBOUND_INTENT_SIGNAL_TYPES)
    has_strong_timing_signal = timing_key_hit in STRONG_TIMING_SIGNAL_TYPES
    is_low_trust_only = (
        lead.primary_source in LOW_TRUST_ONLY_SOURCES
        and not has_inbound_intent_signal
    )

    if category == 'call_today' and not has_call_today_gate_signal:
        category = 'hot'
        reasons.append('Downgraded from Call Today: no inbound form, meeting request, '
                        'calculator submission, or quote request present.')

    if category in ('call_today', 'hot') and not (has_inbound_intent_signal or has_strong_timing_signal):
        category = 'warm'
        reasons.append('Downgraded to Warm: no inbound intent and no strong timing trigger.')

    if category in ('call_today', 'hot') and is_low_trust_only:
        category = 'warm'
        reasons.append('Downgraded to Warm: permit/news-only lead with no inbound intent.')

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
        disqualified=False,
    )
