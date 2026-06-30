"""
Human-readable explanations derived from a scored MultifamilyLead —
used for the "why this lead is warm" and "likely insurance pain"
fields on lead cards in the Multifamily Command UI.
"""
from multifamily.types import MultifamilyLead
from multifamily.scoring.multifamily_score_rules import DISQUALIFIER_CODE_DESCRIPTIONS

_GATE_DOWNGRADE_CODES = {
    'GATE_CALL_TODAY_REQUIRES_DIRECT_ACTION',
    'GATE_CALL_TODAY_PERMIT_NEWS_ONLY',
    'GATE_HOT_REQUIRES_QUALIFYING_SIGNAL',
    'GATE_QUALITY_CAP_LOW_CONFIDENCE_OR_MISSING_STATE',
}

_SIGNAL_TYPE_LABELS = {
    'benchmark_form_submit': 'submitted an insurance benchmark request',
    'quote_request': 'requested a quote',
    'meeting_request': 'requested a meeting',
    'guide_download': 'downloaded a renewal/coverage guide',
    'calculator_submit': 'used the premium/coverage calculator',
    'website_visit': 'visited the multifamily insurance page',
    'repeat_website_visit': 'returned to the multifamily insurance page multiple times',
    'keyword_intent': 'searched a high-intent insurance keyword',
    'paid_search_click': 'clicked a paid search ad to a high-intent landing page',
    'linkedin_lead_form_submit': 'submitted a LinkedIn lead form',
    'renewal_date_known': 'has a known upcoming renewal date',
    'acquisition': 'is in the middle of an acquisition',
    'refinance': 'is refinancing a property',
    'financing': 'has a new financing event',
    'permit_filed': 'filed a construction permit',
    'planning_approval': 'received planning approval',
    'groundbreaking': 'is breaking ground on a new project',
    'vertical_construction': 'has construction underway',
    'completion': 'is completing a construction project',
    'portfolio_growth': 'is growing its portfolio',
}

_PAIN_LABELS = {
    'premium_increase': 'a recent premium increase',
    'deductible_concern': 'concern about their deductible structure',
    'lender_requirement': "a lender-driven coverage requirement",
    'cat_exposed_geography': 'CAT-exposed property geography',
    'builders_risk_need': "a builder's risk coverage need",
    'gl_excess_concern': 'a GL/excess liability concern',
}


def explain_why_warm(lead: MultifamilyLead) -> str:
    score = lead.score
    if score is None or score.disqualified:
        return 'Not yet scored.'

    parts = []
    if lead.primary_signal_type in _SIGNAL_TYPE_LABELS:
        parts.append(f'{lead.company.name} {_SIGNAL_TYPE_LABELS[lead.primary_signal_type]}')
    if score.insurance_timing > 0:
        parts.append('insurance timing looks favorable right now')
    if score.account_fit >= 10:
        parts.append('the account fit is strong (size/portfolio/role)')

    if not parts:
        explanation = f'{lead.company.name} matched on {lead.primary_source or "an unverified source"}; limited signal so far.'
    else:
        explanation = '; '.join(parts) + '.'

    gate_notes = [r for r, c in zip(score.reasons, score.reason_codes) if c in _GATE_DOWNGRADE_CODES]
    if gate_notes:
        explanation += ' ' + ' '.join(gate_notes)

    return explanation


def explain_likely_pain(lead: MultifamilyLead) -> str:
    labels = [_PAIN_LABELS[f] for f in lead.pain_flags if f in _PAIN_LABELS]
    if labels:
        return 'Likely pain: ' + ', '.join(labels) + '.'
    if lead.property.cat_exposed:
        return 'Likely pain: CAT-exposed geography may be driving renewal pricing concerns.'
    return 'No specific pain signal captured yet — confirm on first call.'


def explain_disqualifiers(lead: MultifamilyLead) -> str:
    """Human-readable rollup of why a lead needs more info, derived from
    score.disqualifier_codes (LOW_CONFIDENCE, MISSING_STATE, etc.)."""
    score = lead.score
    if score is None:
        return 'Not yet scored.'
    codes = score.disqualifier_codes
    if not codes:
        return 'No data-quality issues flagged.'
    return ' '.join(DISQUALIFIER_CODE_DESCRIPTIONS.get(code, code) for code in codes)
