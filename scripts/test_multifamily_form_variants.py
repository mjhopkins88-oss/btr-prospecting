#!/usr/bin/env python
"""
Funnel Phase 1 tests: form-variant config (multifamily/forms/form_variants.py)
+ page_variant/campaign_id passthrough in real intake.

Covers: every variant maps to a valid offer_type/lead_situation; the
benchmark variant matches today's existing form/offer_type exactly
(no behavior change for the current form); explicit pageVariant/campaignId
persist through build_lead_from_intake + repository.insert_lead; a
submission with only offerType (no explicit pageVariant, exactly what
today's benchmark form sends) gets page_variant derived server-side;
attribution touches carry page_variant/campaign_id; existing
behavior (no offerType, no pageVariant at all) is completely unaffected.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.forms.form_variants import (
    FORM_VARIANTS, FORM_VARIANT_SLUGS, DEFAULT_FORM_VARIANT_SLUG,
    get_form_variant, default_form_variant, form_variant_for_offer_type,
)
from multifamily.intake import build_lead_from_intake, LEAD_SITUATIONS

_FAILURES = []
_M = '(FORMVARIANT TEST)'
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def test_every_variant_maps_to_a_valid_lead_situation():
    for slug in FORM_VARIANT_SLUGS:
        variant = get_form_variant(slug)
        check(f'{slug}: variant exists', variant is not None)
        check(f'{slug}: lead_situation is a recognized value', variant.lead_situation in LEAD_SITUATIONS)
        check(f'{slug}: offer_type is set', bool(variant.offer_type))
        check(f'{slug}: has a headline/subheadline/CTA/confirmation', all([
            variant.headline, variant.subheadline, variant.cta, variant.confirmation,
        ]))
        check(f'{slug}: does not require SOV/loss-runs upfront',
              not any(f.name.lower() in ('sov', 'lossruns', 'loss_runs') for f in variant.conditional_fields))


def test_default_variant_matches_todays_benchmark_form():
    default = default_form_variant()
    check('default slug is benchmark', default.slug == DEFAULT_FORM_VARIANT_SLUG == 'benchmark')
    check("default offer_type matches today's benchmark form value",
          default.offer_type == 'multifamily_benchmark_review')
    check('default lead_situation is benchmark', default.lead_situation == 'benchmark')


def test_reverse_lookup_by_offer_type():
    for slug, variant in FORM_VARIANTS.items():
        found = form_variant_for_offer_type(variant.offer_type)
        check(f'{slug}: reverse lookup by offer_type finds the same variant', found is not None and found.slug == slug)
    check('unknown offer_type returns None', form_variant_for_offer_type('not_a_real_offer_type') is None)


def test_intake_persists_explicit_page_variant_and_campaign_id():
    payload = {
        'name': 'Variant Tester', 'company': f'Variantflow Co {_M}', 'email': 'variantflow@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal', 'source': 'benchmark_form',
        'renewalDate': '2026-09-01', 'pageVariant': 'renewal-pressure', 'campaignId': 'q3-renewal-push',
        'offerType': 'renewal_pressure_test',
    }
    lead, errors = build_lead_from_intake(payload)
    check('lead built with no errors', errors == [] and lead is not None)
    check('explicit pageVariant persists on the lead', lead.page_variant == 'renewal-pressure')
    check('campaignId persists on the lead', lead.campaign_id == 'q3-renewal-push')

    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    _lead_ids.append(lead.id)

    row = repository.get_lead_row(lead.id)
    check('page_variant persists in the DB row', row and row.get('page_variant') == 'renewal-pressure')
    check('campaign_id persists in the DB row', row and row.get('campaign_id') == 'q3-renewal-push')

    reloaded = repository.get_lead_by_id(lead.id)
    check('page_variant survives lead_json round-trip', reloaded.page_variant == 'renewal-pressure')

    touches = repository.get_attribution_for_lead(lead.id)
    check('attribution touch carries page_variant', touches and touches[0].get('page_variant') == 'renewal-pressure')
    check('attribution touch carries campaign_id', touches and touches[0].get('campaign_id') == 'q3-renewal-push')


def test_intake_derives_page_variant_from_offer_type_when_not_explicit():
    # Exactly what today's benchmark form sends: offerType but no pageVariant.
    payload = {
        'name': 'Derive Tester', 'company': f'Deriveflow Co {_M}', 'email': 'deriveflow@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
        'offerType': 'multifamily_benchmark_review',
    }
    lead, errors = build_lead_from_intake(payload)
    check('lead built with no errors', errors == [] and lead is not None)
    check('page_variant is derived from offerType when not explicitly given', lead.page_variant == 'benchmark')


def test_existing_submission_with_no_offer_or_variant_is_unaffected():
    # A bare-minimum submission (no offerType, no pageVariant at all) —
    # confirms the new fields are purely additive.
    payload = {
        'name': 'Plain Tester', 'company': f'Plainflow Co {_M}', 'email': 'plainflow@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
    }
    lead, errors = build_lead_from_intake(payload)
    check('lead built with no errors', errors == [] and lead is not None)
    check('page_variant stays None with no offerType/pageVariant given', lead.page_variant is None)
    check('campaign_id stays None when not given', lead.campaign_id is None)
    check('lead is scored normally (unaffected by the new fields)', lead.score is not None)


def test_form_variants_endpoint_config_is_json_serializable():
    import dataclasses
    for slug, variant in FORM_VARIANTS.items():
        d = dataclasses.asdict(variant)
        check(f'{slug}: dataclasses.asdict() round-trips cleanly', d['slug'] == slug)
        check(f'{slug}: conditional_fields serialize as plain dicts',
              all(isinstance(f, dict) for f in d['conditional_fields']))


def main():
    try:
        test_every_variant_maps_to_a_valid_lead_situation()
        test_default_variant_matches_todays_benchmark_form()
        test_reverse_lookup_by_offer_type()
        test_intake_persists_explicit_page_variant_and_campaign_id()
        test_intake_derives_page_variant_from_offer_type_when_not_explicit()
        test_existing_submission_with_no_offer_or_variant_is_unaffected()
        test_form_variants_endpoint_config_is_json_serializable()
    finally:
        for lid in _lead_ids:
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} tracked lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All form-variant (Funnel Phase 1) tests passed.')


if __name__ == '__main__':
    main()
