"""
Phase B — Deliverable Composer.

Composes a branded, print-ready PDF deliverable for one lead, using that
lead's offer type (one of the six form-variant offers in
multifamily/forms/form_variants.py) to pick the deliverable name/
description/required-input template, then best-effort pre-fills the
inputs from what's already known about the lead (company/property/
contact basics plus whatever the lead's situation signal carries in its
`detail` dict — see multifamily/intake.py's `_situation_signals()` for
exactly which keys each self-reported situation populates).

This module never generates persuasive/marketing copy — the PDF body is
a straightforward "field: value" rendering of admin-edited, factual
data plus the offer's own (already-reviewed) deliverable_description
copy from form_variants.py. There is nothing here for the tone
guardrails (multifamily/sales_intelligence/tone_guardrails.py) to catch
because nothing here is generated prose; the "never overstate savings /
never attack the incumbent broker" constraints are satisfied by
construction. The one piece of copy that IS mandatory on every single
generated deliverable is the indicative-only disclaimer below — it is
NON-NEGOTIABLE and must never be dropped, reworded, or watered down.

Nothing in this module ever sends anything — it only returns PDF bytes
for the caller (an admin-only API endpoint) to hand back as a file
download.
"""
from datetime import datetime
from typing import Any, Dict, Optional

from multifamily.forms.form_variants import (
    FormVariant, get_form_variant, form_variant_for_offer_type, default_form_variant,
)

# ---------------------------------------------------------------------------
# The mandatory indicative-only / not-a-quote disclaimer. Verbatim, on every
# generated deliverable, full stop. Do not edit this string without an
# explicit, separate instruction to change the compliance language itself.
# ---------------------------------------------------------------------------
DISCLAIMER = (
    "This is an indicative estimate only, not a quote or binding proposal. "
    "Coverage, terms, and pricing are subject to full underwriting review. "
    "This is not an offer of insurance."
)

# ---------------------------------------------------------------------------
# Unicode font setup — DejaVu Sans, same pattern/paths as
# api/routes/daily_brief.py's PDF builder, kept as a small local copy so
# this business-logic module doesn't import a Flask route module.
# ---------------------------------------------------------------------------
import os as _os

_PROJECT_FONT_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'fonts')
_SYSTEM_FONT_DIR = '/usr/share/fonts/truetype/dejavu'

_FONT_REGULAR = None
_FONT_BOLD = None
for _dir in (_PROJECT_FONT_DIR, _SYSTEM_FONT_DIR):
    _r = _os.path.join(_dir, 'DejaVuSans.ttf')
    _b = _os.path.join(_dir, 'DejaVuSans-Bold.ttf')
    if _os.path.exists(_r) and _os.path.exists(_b):
        _FONT_REGULAR = _r
        _FONT_BOLD = _b
        break

UNICODE_FONTS_AVAILABLE = _FONT_REGULAR is not None


def _register_unicode_fonts(pdf):
    if UNICODE_FONTS_AVAILABLE:
        for style, path in [('', _FONT_REGULAR), ('B', _FONT_BOLD),
                             ('I', _FONT_REGULAR), ('BI', _FONT_BOLD)]:
            try:
                pdf.add_font('DejaVu', style, path, uni=True)
            except TypeError:
                pdf.add_font('DejaVu', style, path)
        return 'DejaVu'
    return 'Helvetica'


def _sanitize_pdf_text(text):
    if not text:
        return ''
    text = str(text)
    replacements = {
        '’': "'", '‘': "'",
        '“': '"', '”': '"',
        '—': ' - ', '–': ' - ',
        '…': '...', ' ': ' ',
        '​': '', '‎': '', '‏': '',
        '﻿': '',
        '•': '-',
        '→': '->', '←': '<-',
        '✓': '[x]', '✗': '[ ]',
        '·': '-',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.replace('\r\n', '\n').replace('\r', '\n')


# ---------------------------------------------------------------------------
# Offer-type resolution
# ---------------------------------------------------------------------------

def _variant_for_lead(lead) -> FormVariant:
    """Which of the six offer configs applies to this lead. Prefers the
    canonical offer_type, falls back to page_variant, falls back to the
    default (benchmark) — same fallback order intake.py/outreach already
    use elsewhere, so this never raises for a lead with no offer info."""
    variant = None
    offer_type = getattr(lead, 'offer_type', None)
    page_variant = getattr(lead, 'page_variant', None)
    if offer_type:
        variant = form_variant_for_offer_type(offer_type)
    if not variant and page_variant:
        variant = get_form_variant(page_variant)
    if not variant:
        variant = default_form_variant()
    return variant


def deliverable_meta_for_lead(lead) -> Dict[str, Any]:
    """The template envelope for this lead's offer: slug + every
    FormVariant deliverable field the composer form needs to display."""
    variant = _variant_for_lead(lead)
    return {
        'slug': variant.slug,
        'offer_type': variant.offer_type,
        'deliverable_name': variant.deliverable_name,
        'deliverable_description': variant.deliverable_description,
        'artifact_type': variant.artifact_type,
        'turnaround_promise': variant.turnaround_promise,
    }


# ---------------------------------------------------------------------------
# Prefill — best-effort label -> value mapping
# ---------------------------------------------------------------------------

_ASSET_TYPE_LABELS = {
    'garden': 'Garden-style', 'mid_rise': 'Mid-rise', 'high_rise': 'High-rise',
    'mixed_use': 'Mixed-use', 'unknown': 'Unknown',
}


def _s(value: Any) -> str:
    if value in (None, ''):
        return ''
    return str(value)


def _asset_type_label(value: Optional[str]) -> str:
    if not value:
        return ''
    return _ASSET_TYPE_LABELS.get(value, value)


def _merged_signal_detail(lead) -> Dict[str, Any]:
    """Every signal's `detail` dict merged together (later signals win on
    key collision). Timing-specific fields — renewal_date, target_close_
    date, year_built, lender_deadline, project_start_date,
    expected_completion_date, etc. — ride in whichever situation signal
    intake.py attached (multifamily/intake.py's `_situation_signals()`),
    not necessarily signals[0], so this merges across all of them rather
    than assuming a fixed index."""
    merged: Dict[str, Any] = {}
    for signal in (getattr(lead, 'signals', None) or []):
        if signal.detail:
            merged.update(signal.detail)
    return merged


def _basic_fields(lead) -> Dict[str, str]:
    contact = lead.contacts[0] if getattr(lead, 'contacts', None) else None
    company = getattr(lead, 'company', None)
    prop = getattr(lead, 'property', None)

    address = (prop.address if prop else None) or ''
    if not address:
        city = (prop.city if prop else None) or getattr(lead, 'city', None)
        state = (prop.state if prop else None) or getattr(lead, 'state', None)
        address = ', '.join([p for p in (city, state) if p])

    return {
        'Contact name': _s(contact.full_name if contact else ''),
        'Contact email': _s(contact.email if contact else ''),
        'Contact phone': _s(contact.phone if contact else ''),
        'Company name': _s(company.name if company else ''),
        'Property address': _s(address),
        'City': _s((prop.city if prop else None) or getattr(lead, 'city', None)),
        'State': _s((prop.state if prop else None) or getattr(lead, 'state', None)),
        'Unit count': _s(prop.unit_count if prop else ''),
        'Asset type': _asset_type_label(prop.asset_type if prop else ''),
    }


def _option_label(variant: FormVariant, field_name: str, value: Optional[str]) -> str:
    """Look up the human-readable label for a select-field value from the
    variant's own conditional_fields, so the deliverable shows the exact
    same wording the lead saw on the offer page (not the raw payload
    code). Falls back to the raw value if no match is found."""
    if not value:
        return ''
    for spec in variant.conditional_fields:
        if spec.name == field_name:
            for opt in spec.options:
                if opt.get('value') == value:
                    return opt.get('label', value)
    return value


def _primary_concern_label(lead, variant: FormVariant) -> str:
    code = lead.pain_flags[0] if getattr(lead, 'pain_flags', None) else None
    if not code:
        return ''
    return _option_label(variant, 'primaryConcern', code) or code


# Per-slug label -> resolver(lead, merged_detail, variant). Only covers
# required_inputs labels NOT already satisfied by _basic_fields() (e.g.
# 'Unit count'/'Asset type'/'Property address' are basics — every slug
# that lists them in required_inputs gets them for free).
_RESOLVERS = {
    'benchmark': {
        'Year built': lambda lead, d, v: _s(d.get('year_built')),
        'Construction type': lambda lead, d, v: _s(d.get('construction_type')),
        'Current premium': lambda lead, d, v: _s(d.get('current_premium_range')),
    },
    'renewal-pressure': {
        'Renewal date': lambda lead, d, v: _s(d.get('renewal_date')),
        'Current premium range (optional)': lambda lead, d, v: _s(d.get('current_premium_range')),
        'Main concern': lambda lead, d, v: _primary_concern_label(lead, v),
    },
    'acquisition': {
        'Vintage (year built)': lambda lead, d, v: _s(d.get('year_built')),
        'Assumed insurance line': lambda lead, d, v: _s(d.get('assumed_insurance_line')),
        'Target close date': lambda lead, d, v: _s(d.get('target_close_date')),
    },
    'lender-requirement': {
        'Lender deadline': lambda lead, d, v: _s(d.get('lender_deadline')),
        'Type of lender issue': lambda lead, d, v: _option_label(v, 'issueType', d.get('lender_issue_type')),
    },
    'builders-risk': {
        'Project start date': lambda lead, d, v: _s(d.get('project_start_date')),
        'Hard costs (optional)': lambda lead, d, v: _s(d.get('hard_costs')),
        'Soft costs (optional)': lambda lead, d, v: _s(d.get('soft_costs')),
        'Who controls the policy': lambda lead, d, v: _option_label(v, 'controlType', d.get('control_type')),
        'Construction stage': lambda lead, d, v: _option_label(v, 'constructionStage', d.get('construction_stage_selfreport')),
    },
    'completion-leaseup': {
        'Expected completion date': lambda lead, d, v: _s(d.get('expected_completion_date')),
        'First occupancy date (optional)': lambda lead, d, v: _s(d.get('first_occupancy_date')),
        'Completion type': lambda lead, d, v: _option_label(v, 'phasing', d.get('phasing')),
        'Is operating coverage already placed?': lambda lead, d, v: _option_label(v, 'operatingCoveragePlaced', d.get('operating_coverage_placed')),
    },
}


def build_prefill(lead) -> Dict[str, str]:
    """Best-effort pre-filled {label: value} map for this lead's offer —
    contact/company/property basics plus every one of the offer's
    required_inputs labels (form_variants.py), each mapped to its real
    source field. Every value is a plain string (possibly empty) so the
    admin composer form can bind directly to it and edit freely; nothing
    here is ever auto-sent."""
    variant = _variant_for_lead(lead)
    detail = _merged_signal_detail(lead)

    fields: Dict[str, str] = dict(_basic_fields(lead))
    resolver_map = _RESOLVERS.get(variant.slug, {})
    for label in variant.required_inputs:
        if label in fields:
            continue
        resolver = resolver_map.get(label)
        fields[label] = resolver(lead, detail, variant) if resolver else ''
    return fields


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

# mf-theme.css palette (static/mf-theme.css) — used so the PDF visually
# matches the in-app porcelain/gold Multifamily theme.
_MF_INK_RGB = (23, 34, 59)      # #17223b
_MF_GOLD_RGB = (175, 138, 78)   # #af8a4e
_MF_MUTED_RGB = (100, 100, 100)


def render_pdf(lead, offer_type: Optional[str], fields: Dict[str, Any], credibility: Dict[str, Any]) -> bytes:
    """Render the branded, print-ready deliverable PDF. `offer_type` is
    taken as the authoritative template selector (falls back to the
    lead's own resolved variant if not recognized); `fields` is the
    final, admin-edited value set — exactly what gets baked into the
    PDF and persisted alongside it. `credibility` should be
    `public_credibility_view()`'s output so no placeholder/empty
    branding field ever renders. Returns raw PDF bytes; never writes to
    disk, never sends anything."""
    from fpdf import FPDF

    variant = (form_variant_for_offer_type(offer_type) if offer_type else None) or _variant_for_lead(lead)

    s = _sanitize_pdf_text
    company_name = credibility.get('company_name') or 'Insurance Review'
    deliverable_name = variant.deliverable_name or 'Deliverable'
    rep_name = credibility.get('representative_name') or ''
    rep_title = credibility.get('representative_title') or ''

    # `F` is resolved just below (after the FPDF instance exists, since
    # _register_unicode_fonts needs it) but referenced here — same
    # closure-over-enclosing-scope pattern as daily_brief.py's _build_pdf:
    # header()/footer() read the name `F` at CALL time (via add_page()),
    # by which point it's already been reassigned to the real value.
    F = 'DejaVu' if UNICODE_FONTS_AVAILABLE else 'Helvetica'

    class DeliverablePDF(FPDF):
        def header(self):
            self.set_font(F, 'B', 15)
            self.set_text_color(*_MF_INK_RGB)
            self.cell(0, 9, s(company_name), new_x='LMARGIN', new_y='NEXT')
            self.set_font(F, '', 11)
            self.set_text_color(*_MF_GOLD_RGB)
            self.cell(0, 7, s(deliverable_name), new_x='LMARGIN', new_y='NEXT')
            self.set_draw_color(210, 210, 210)
            self.line(self.l_margin, self.get_y() + 2, self.w - self.r_margin, self.get_y() + 2)
            self.ln(8)

        def footer(self):
            self.set_y(-24)
            self.set_draw_color(210, 210, 210)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.set_font(F, 'I', 7)
            self.set_text_color(*_MF_MUTED_RGB)
            self.multi_cell(0, 3.6, s(DISCLAIMER), align='C')

    pdf = DeliverablePDF('P', 'mm', 'Letter')
    F = _register_unicode_fonts(pdf)
    pdf.set_auto_page_break(auto=True, margin=30)
    pdf.add_page()

    pdf.set_font(F, '', 9)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 6, s(f'Prepared {datetime.utcnow().strftime("%B %d, %Y")}'), new_x='LMARGIN', new_y='NEXT')
    if rep_name:
        by_line = f'Prepared by {rep_name}' + (f' — {rep_title}' if rep_title else '')
        pdf.cell(0, 6, s(by_line), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    if variant.deliverable_description:
        pdf.set_font(F, '', 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 5, s(variant.deliverable_description))
        pdf.ln(4)

    pdf.set_font(F, 'B', 12)
    pdf.set_text_color(*_MF_INK_RGB)
    pdf.cell(0, 8, 'DETAILS', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(1)

    for label, value in (fields or {}).items():
        pdf.set_font(F, 'B', 9)
        pdf.set_text_color(90, 90, 90)
        pdf.cell(62, 6, s(str(label)))
        pdf.set_font(F, '', 9)
        pdf.set_text_color(30, 30, 30)
        display_value = str(value) if value not in (None, '') else '—'
        pdf.multi_cell(0, 6, s(display_value), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(3)

    if variant.turnaround_promise:
        pdf.set_font(F, 'I', 9)
        pdf.set_text_color(*_MF_MUTED_RGB)
        pdf.multi_cell(0, 5, s(f'Turnaround: {variant.turnaround_promise}'))

    output = pdf.output()
    return bytes(output)
