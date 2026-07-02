"""
Multifamily form/offer-page variants — config-as-code, single source of
truth for every public offer page under /mf-review/<slug>. Adding a new
offer means adding an entry here, not writing a new HTML file or editing
scattered route logic.

The form is a CONVERSION POINT inside a broader lead engine, not the
whole engine (the four-lane funnel strategy: inbound hand-raisers,
SERP/trigger-based, outbound-to-form, content/search credibility).
Every variant maps onto EXISTING leadSituation/scoring/timing/sales-
intelligence handling — no variant changes scoring math. Conditional
fields ride in the situation signal's `detail` (multifamily/intake.py),
which scoring never reads for points.

'benchmark' is the default variant. It was originally shaped to match a
standalone legacy form (static/multifamily-benchmark-form.html); that
form has since been retired (Phase A visual overhaul) — its route now
302s to /mf-review/benchmark, which is the only live 'benchmark' page.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Public URL path for each variant: /mf-review/<slug>
FORM_VARIANT_SLUGS = [
    'benchmark', 'renewal-pressure', 'acquisition', 'lender-requirement',
    'builders-risk', 'completion-leaseup',
]

DEFAULT_FORM_VARIANT_SLUG = 'benchmark'

# Response-time expectation per variant (Part 9 of the funnel plan) — used
# to set notification priority, never to change scoring/timing math.
NOTIFICATION_PRIORITIES = ['immediate', 'same_day', 'queued']

# Section 8 item 5 — fallback turnaround promise for any FUTURE offer
# variant added before its own turnaround is confirmed. Deliberately
# visible/bracketed so it can never be mistaken for a confirmed
# commitment if it ships unchanged (the six variants below all carry
# real, operator-confirmed turnaround values instead of this default).
DEFAULT_TURNAROUND_PROMISE = '[TURNAROUND — default 5 business days pending operator confirmation]'


@dataclass
class FormFieldSpec:
    """One field on an offer page. `name` is the payload key the form
    posts under (camelCase, matching what multifamily/intake.py's
    build_lead_from_intake() already reads via payload.get(...))."""
    name: str
    label: str
    field_type: str = 'text'  # text | email | tel | date | number | select | textarea
    required: bool = False
    options: List[Dict[str, str]] = field(default_factory=list)  # select: [{'value':.., 'label':..}]
    placeholder: Optional[str] = None


@dataclass
class FormVariant:
    slug: str
    offer_type: str
    lead_situation: str  # one of multifamily.intake.LEAD_SITUATIONS
    headline: str
    subheadline: str
    cta: str
    confirmation: str
    conditional_fields: List[FormFieldSpec] = field(default_factory=list)
    notification_priority: str = 'same_day'
    # Section 8 item 5 — deliverable definition as config, rendered on the
    # offer page as "What you get / What we need / How fast" and read by
    # the Outreach Workbench (multifamily/outreach/outreach_bundle_builder.py)
    # so generated copy can name the concrete artifact instead of speaking
    # generically. required_inputs is documentation copy only — it does not
    # drive form validation (see conditional_fields for the actual fields).
    deliverable_name: str = ''
    deliverable_description: str = ''
    required_inputs: List[str] = field(default_factory=list)
    artifact_type: str = ''
    turnaround_promise: str = DEFAULT_TURNAROUND_PROMISE


FORM_VARIANTS: Dict[str, FormVariant] = {
    'benchmark': FormVariant(
        slug='benchmark',
        offer_type='multifamily_benchmark_review',
        lead_situation='benchmark',
        headline='Multifamily Insurance Benchmark Review',
        subheadline="See how your program compares before you're forced to find out at renewal.",
        cta='Get My Free Benchmark',
        confirmation="Thanks — we'll review what you shared and follow up same day with what we're seeing "
                      "in the market for properties like yours.",
        conditional_fields=[
            FormFieldSpec('primaryConcern', 'What prompted this?', 'select', required=False, options=[
                {'value': 'premium_increase', 'label': 'Premium increase'},
                {'value': 'deductible_concern', 'label': 'Deductible concern'},
                {'value': 'lender_requirement', 'label': 'Lender requirement'},
                {'value': 'cat_exposed_geography', 'label': 'CAT-exposed geography'},
                {'value': 'builders_risk_need', 'label': "Builder's risk need"},
                {'value': 'gl_excess_concern', 'label': 'GL/excess concern'},
            ]),
        ],
        notification_priority='same_day',
        deliverable_name='Multifamily Benchmark Snapshot',
        deliverable_description='$/unit and rate-per-$100-TIV range vs. segment, plus 3 observations.',
        required_inputs=['Property address', 'Unit count', 'Year built', 'Construction type', 'Current premium'],
        artifact_type='Benchmark snapshot (range + written observations)',
        turnaround_promise='5 business days',
    ),
    'renewal-pressure': FormVariant(
        slug='renewal-pressure',
        offer_type='renewal_pressure_test',
        lead_situation='renewal',
        headline='Pressure-Test Your Multifamily Renewal',
        subheadline='Before you re-sign, get an independent read on whether your renewal actually got shopped.',
        cta='Pressure-Test My Renewal',
        confirmation="Thanks — renewal timing matters, so we'll follow up same day (sooner if your renewal is close).",
        conditional_fields=[
            FormFieldSpec('renewalDate', 'Renewal date', 'date', required=True),
            FormFieldSpec('currentPremiumRange', 'Current premium range (optional)', 'select', options=[
                {'value': 'under_100k', 'label': 'Under $100k'},
                {'value': '100k_250k', 'label': '$100k–$250k'},
                {'value': '250k_500k', 'label': '$250k–$500k'},
                {'value': '500k_1m', 'label': '$500k–$1M'},
                {'value': 'over_1m', 'label': 'Over $1M'},
            ]),
            FormFieldSpec('primaryConcern', 'Main concern', 'select', options=[
                {'value': 'premium_increase', 'label': 'Pricing'},
                {'value': 'deductible_concern', 'label': 'Deductible'},
                {'value': 'lender_requirement', 'label': 'Lender'},
                {'value': 'gl_excess_concern', 'label': 'Coverage/service'},
            ]),
        ],
        notification_priority='same_day',
        deliverable_name='Renewal Readiness Memo',
        deliverable_description='Timeline read, market-appetite read, and a deductible-structure critique.',
        required_inputs=['Renewal date', 'Current premium range (optional)', 'Main concern', 'Unit count', 'Asset type'],
        artifact_type='Memo (PDF)',
        turnaround_promise='5 business days',
    ),
    'acquisition': FormVariant(
        slug='acquisition',
        offer_type='acquisition_assumption_review',
        lead_situation='acquisition',
        headline='Insurance Assumption Review — Before You Close',
        subheadline="An independent read on the insurance numbers in your deal, not the seller's.",
        cta='Review My Deal',
        confirmation="Thanks — deal timelines move fast, so we'll follow up right away (sooner if you're close to closing).",
        conditional_fields=[
            FormFieldSpec('targetCloseDate', 'Target close date', 'date', required=True),
            FormFieldSpec('propertyName', 'Property name (optional)', 'text'),
            # numberOfUnits is already a universal optional field on every
            # offer page — not repeated here.
            FormFieldSpec('relyingOnSellerNumbers', "Are you relying on the seller's insurance numbers?", 'select', options=[
                {'value': 'yes', 'label': 'Yes, using seller numbers as-is'},
                {'value': 'no', 'label': 'No, independently validating'},
                {'value': 'unsure', 'label': 'Not sure yet'},
            ]),
        ],
        notification_priority='immediate',
        deliverable_name='Insurance Assumption Validation',
        deliverable_description='A range vs. your pro-forma insurance assumption, plus any flagged risks.',
        required_inputs=['Property address', 'Unit count', 'Vintage (year built)', 'Assumed insurance line', 'Target close date'],
        artifact_type='Validation summary (range + flagged risks)',
        turnaround_promise='3 business days',
    ),
    'lender-requirement': FormVariant(
        slug='lender-requirement',
        offer_type='lender_requirement_review',
        lead_situation='refinance',
        headline='Clear Your Lender Insurance Requirements — Fast',
        subheadline='A quick read on what your lender needs and whether your current program already covers it.',
        cta='Review My Lender Requirements',
        confirmation="Thanks — lender deadlines don't wait, so we'll follow up right away.",
        conditional_fields=[
            FormFieldSpec('lenderDeadline', 'Lender deadline', 'date', required=True),
            FormFieldSpec('issueType', 'What kind of lender issue?', 'select', options=[
                {'value': 'evidence', 'label': 'Evidence of insurance needed'},
                {'value': 'deductible', 'label': 'Deductible too high for lender'},
                {'value': 'exclusions', 'label': 'Exclusions/coverage gaps'},
                {'value': 'carrier_rating', 'label': "Carrier rating doesn't meet requirement"},
                {'value': 'escrow', 'label': 'Escrow/impound issue'},
                {'value': 'unknown', 'label': 'Not sure yet'},
            ]),
        ],
        notification_priority='immediate',
        deliverable_name='Requirements Gap Check',
        deliverable_description="A read on your term-sheet insurance clauses against your current or available program.",
        required_inputs=['Lender deadline', 'Type of lender issue', 'Unit count', 'Asset type'],
        artifact_type='Gap-check summary (PDF)',
        turnaround_promise='3 business days',
    ),
    'builders-risk': FormVariant(
        slug='builders-risk',
        offer_type='builders_risk_review',
        lead_situation='construction',
        headline="Lock In Builder's Risk Before You Break Ground",
        subheadline='A fast read on coverage, limits, and who controls the policy — before costs are exposed mid-build.',
        cta="Review My Builder's Risk",
        confirmation="Thanks — construction timing matters, so we'll follow up right away.",
        conditional_fields=[
            FormFieldSpec('projectStartDate', 'Project start date', 'date', required=True),
            FormFieldSpec('hardCosts', 'Hard costs (optional)', 'text', placeholder='e.g. $12,000,000'),
            FormFieldSpec('softCosts', 'Soft costs (optional)', 'text', placeholder='e.g. $2,000,000'),
            FormFieldSpec('controlType', 'Who controls the policy?', 'select', options=[
                {'value': 'gc_controlled', 'label': 'GC-controlled'},
                {'value': 'owner_controlled', 'label': 'Owner-controlled'},
                {'value': 'unknown', 'label': 'Not sure yet'},
            ]),
            FormFieldSpec('constructionStage', 'Construction stage', 'select', options=[
                {'value': 'pre_construction', 'label': 'Pre-construction'},
                {'value': 'groundbreaking', 'label': 'Breaking ground soon'},
                {'value': 'vertical', 'label': 'Vertical construction underway'},
            ]),
        ],
        notification_priority='immediate',
        deliverable_name='BR Structure Review',
        deliverable_description="A limits/soft-cost/delay/OCP checklist read against your loan requirements.",
        required_inputs=['Project start date', 'Hard costs (optional)', 'Soft costs (optional)', 'Who controls the policy', 'Construction stage'],
        artifact_type='Structure-review checklist (PDF)',
        turnaround_promise='5 business days',
    ),
    'completion-leaseup': FormVariant(
        slug='completion-leaseup',
        offer_type='completion_leaseup_review',
        lead_situation='completion',
        headline="Map Your Builder's-Risk-to-Operating Transition",
        subheadline="Don't let the switch from builder's risk to an operating program create a coverage gap during lease-up.",
        cta='Map My Transition',
        confirmation="Thanks — we'll follow up same day (right away if you're within 90 days of first occupancy).",
        conditional_fields=[
            FormFieldSpec('expectedCompletionDate', 'Expected completion date', 'date', required=True),
            FormFieldSpec('firstOccupancyDate', 'First occupancy date (optional)', 'date'),
            FormFieldSpec('phasing', 'Completion type', 'select', options=[
                {'value': 'full', 'label': 'Full completion'},
                {'value': 'phased', 'label': 'Phased occupancy'},
            ]),
            FormFieldSpec('operatingCoveragePlaced', 'Is operating coverage already placed?', 'select', options=[
                {'value': 'yes', 'label': 'Yes'},
                {'value': 'no', 'label': 'No'},
                {'value': 'unknown', 'label': 'Not sure yet'},
            ]),
        ],
        notification_priority='same_day',
        deliverable_name='Transition Map',
        deliverable_description="A milestone-keyed coverage map from builder's risk to your operating program, plus an operating-budget range.",
        required_inputs=['Expected completion date', 'First occupancy date (optional)', 'Completion type', 'Is operating coverage already placed?'],
        artifact_type='Transition map (milestone-keyed diagram + budget range)',
        turnaround_promise='5 business days',
    ),
}


def get_form_variant(slug: str) -> Optional[FormVariant]:
    return FORM_VARIANTS.get(slug)


def default_form_variant() -> FormVariant:
    return FORM_VARIANTS[DEFAULT_FORM_VARIANT_SLUG]


def form_variant_for_offer_type(offer_type: str) -> Optional[FormVariant]:
    """Reverse lookup — used by intake.py to derive page_variant when a
    submission carries offer_type but not an explicit pageVariant, and by
    the Outreach Workbench's page-recommendation (Phase 3)."""
    for variant in FORM_VARIANTS.values():
        if variant.offer_type == offer_type:
            return variant
    return None


# Why each variant fits a given self-reported situation — surfaced by the
# Outreach Workbench alongside the recommended page (Funnel Phase 3) so an
# operator understands the reasoning, not just the slug.
_RECOMMENDATION_REASON_BY_SLUG = {
    'renewal-pressure': "This lead has a renewal coming up — this page pressure-tests it before they re-sign.",
    'acquisition': "This lead is mid-acquisition — this page reviews the insurance numbers before they close.",
    'lender-requirement': "This lead has a refinance/lender situation — this page clears the specific requirement fast.",
    'builders-risk': "This lead has a construction project — this page locks in builder's risk before ground breaks.",
    'completion-leaseup': "This lead is nearing completion/lease-up — this page maps the builder's-risk-to-operating transition.",
    'benchmark': "No specific trigger identified yet — the general benchmark review is the safest fit.",
}


def recommend_form_variant_for_situation(lead_situation: Optional[str]) -> FormVariant:
    """Forward lookup — given a lead's self-reported (or inferred)
    situation, which offer page best fits sending them next? Falls back
    to the benchmark variant for an unrecognized/absent situation."""
    for variant in FORM_VARIANTS.values():
        if variant.lead_situation == lead_situation:
            return variant
    return default_form_variant()


def recommendation_reason_for_slug(slug: str) -> str:
    return _RECOMMENDATION_REASON_BY_SLUG.get(slug, _RECOMMENDATION_REASON_BY_SLUG['benchmark'])
