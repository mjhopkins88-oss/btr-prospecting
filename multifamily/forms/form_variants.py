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

'benchmark' is the default variant and is deliberately identical in
shape to the form that already exists (static/multifamily-benchmark-form.html)
— this module documents/derives metadata for it, it does not change its
behavior.
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
