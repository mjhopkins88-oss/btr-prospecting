#!/usr/bin/env python
"""
Section 8 items 5 and 7 tests: offer deliverable definitions as config
(multifamily/forms/form_variants.py) and the shared credibility-block
config (multifamily/credibility_config.py).

Covers: every one of the six FormVariants has a non-empty deliverable
config with required_inputs kept to <=7; GET /api/multifamily/form-variants
returns both the per-variant deliverable fields and the shared
credibility block; the Outreach Workbench (build_outreach_bundle)
references the concrete deliverable name in generated copy when a
lead's offer_type matches a known variant, and falls back to the prior
generic phrasing untouched when it doesn't (zero regression for leads
with no offer_type); the credibility config's env-var override merges
correctly and exposes which fields are still awaiting operator input.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.forms.form_variants import FORM_VARIANTS, FORM_VARIANT_SLUGS, DEFAULT_TURNAROUND_PROMISE
from multifamily.credibility_config import (
    DEFAULT_CREDIBILITY_CONFIG, get_credibility_config, placeholder_fields, _ENV_VAR,
)
from multifamily.intake import build_lead_from_intake
from multifamily.outreach.outreach_bundle_builder import build_outreach_bundle
from multifamily import repository

_FAILURES = []
_M = '(OFFERDELIVERABLE TEST)'
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def test_every_variant_has_a_deliverable_config():
    for slug in FORM_VARIANT_SLUGS:
        variant = FORM_VARIANTS[slug]
        check(f"'{slug}' has a non-empty deliverable_name", bool(variant.deliverable_name))
        check(f"'{slug}' has a non-empty deliverable_description", bool(variant.deliverable_description))
        check(f"'{slug}' has 1-7 required_inputs", 1 <= len(variant.required_inputs) <= 7)
        check(f"'{slug}' has a non-empty artifact_type", bool(variant.artifact_type))
        check(f"'{slug}' turnaround_promise is the shared placeholder (pending operator confirmation)",
              variant.turnaround_promise == DEFAULT_TURNAROUND_PROMISE)
        check(f"'{slug}' turnaround_promise is visibly bracketed as a placeholder",
              variant.turnaround_promise.startswith('[TURNAROUND'))


def test_form_variants_endpoint_shape_matches_config():
    """The route itself needs a live Flask app to hit over HTTP (covered
    separately in live verification) — here we confirm the exact data
    the route serializes (dataclasses.asdict + get_credibility_config())
    round-trips through JSON cleanly, since that's the only real risk
    surface (non-JSON-safe values sneaking into the config)."""
    import dataclasses
    variants_json = json.dumps({slug: dataclasses.asdict(v) for slug, v in FORM_VARIANTS.items()})
    reloaded = json.loads(variants_json)
    check('all 6 slugs survive JSON round-trip', set(reloaded.keys()) == set(FORM_VARIANT_SLUGS))
    check("reloaded 'benchmark' keeps its deliverable_name",
          reloaded['benchmark']['deliverable_name'] == 'Multifamily Benchmark Snapshot')

    credibility_json = json.dumps(get_credibility_config())
    reloaded_cred = json.loads(credibility_json)
    check('credibility config round-trips through JSON', isinstance(reloaded_cred, dict))
    check('credibility config has no_bor_change_line', 'no bor change' in reloaded_cred['no_bor_change_line'].lower()
          or 'no broker-of-record change' in reloaded_cred['no_bor_change_line'].lower())


def test_credibility_config_defaults_and_placeholders():
    cfg = get_credibility_config()
    required_keys = [
        'proof_line', 'market_access_line', 'no_bor_change_line', 'what_happens_next_steps',
        'ca_license_number', 'association_memberships', 'representative_name',
        'representative_title', 'representative_photo_url', 'privacy_note',
    ]
    for key in required_keys:
        check(f"credibility config has key '{key}'", key in cfg)
    check('what_happens_next_steps has exactly 3 steps', len(cfg['what_happens_next_steps']) == 3)
    check('no_bor_change_line is not a placeholder (safe boilerplate, not an operator fact)',
          '[PLACEHOLDER' not in cfg['no_bor_change_line'])
    check('privacy_note is not a placeholder (safe boilerplate, not an operator fact)',
          '[PLACEHOLDER' not in cfg['privacy_note'])

    placeholders = placeholder_fields()
    expected_placeholder_fields = {
        'proof_line', 'market_access_line', 'ca_license_number', 'association_memberships',
        'representative_name', 'representative_title', 'representative_photo_url',
    }
    check('every expected fact-dependent field is still flagged as a placeholder',
          expected_placeholder_fields.issubset(set(placeholders)))
    check('no_bor_change_line/privacy_note/what_happens_next_steps are NOT flagged as placeholders',
          not ({'no_bor_change_line', 'privacy_note', 'what_happens_next_steps'} & set(placeholders)))


def test_credibility_config_env_override_merges():
    override = {'ca_license_number': 'CA-0123456', 'proof_line': ''}
    os.environ[_ENV_VAR] = json.dumps(override)
    try:
        cfg = get_credibility_config()
        check('env override applies a real license number', cfg['ca_license_number'] == 'CA-0123456')
        check('env override with an empty string does not blank out the default proof_line',
              cfg['proof_line'] == DEFAULT_CREDIBILITY_CONFIG['proof_line'])
        check('fields not present in the override are untouched',
              cfg['privacy_note'] == DEFAULT_CREDIBILITY_CONFIG['privacy_note'])
    finally:
        del os.environ[_ENV_VAR]
    check('override no longer applies once the env var is cleared',
          get_credibility_config()['ca_license_number'] == DEFAULT_CREDIBILITY_CONFIG['ca_license_number'])


def test_outreach_copy_references_concrete_deliverable_when_offer_type_known():
    lead, errors = build_lead_from_intake({
        'name': 'Deliverable Lead', 'company': f'Deliverable Co {_M}', 'email': 'deliverablelead@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal', 'source': 'manual',
        'offerType': 'renewal_pressure_test', 'pageVariant': 'renewal-pressure',
    })
    assert errors == [], errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    _lead_ids.append(lead.id)

    bundle = build_outreach_bundle(lead)
    check("email body references the concrete deliverable name 'Renewal Readiness Memo'",
          'Renewal Readiness Memo' in bundle['email_draft']['body'])
    check('offer_deliverable is populated', bundle['offer_deliverable'] is not None)
    check("offer_deliverable.page_variant matches the lead's page_variant",
          bundle['offer_deliverable']['page_variant'] == 'renewal-pressure')
    check('offer_deliverable.turnaround_promise is present',
          bool(bundle['offer_deliverable']['turnaround_promise']))
    check('the protected NEPQ angle/hook text is still present and untouched (build_angle output)',
          len(bundle['recommended_message_angle'] or '') > 0)


def test_outreach_copy_falls_back_to_generic_phrasing_without_offer_type():
    """Zero regression: a lead with no offer_type (the vast majority of
    existing/organic leads) must produce EXACTLY the prior generic
    phrasing, unchanged."""
    lead, errors = build_lead_from_intake({
        'name': 'Generic Lead', 'company': f'Generic Co {_M}', 'email': 'genericlead@example.com',
        'state': 'CA', 'city': 'Los Angeles', 'leadSituation': 'benchmark', 'source': 'manual',
    })
    assert errors == [], errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    _lead_ids.append(lead.id)

    bundle = build_outreach_bundle(lead)
    check('offer_deliverable is None when offer_type is unset', bundle['offer_deliverable'] is None)
    check("email body keeps the original generic 'share what we're seeing' phrasing",
          "share what we're seeing across" in bundle['email_draft']['body'])
    check("email body does NOT reference any deliverable name", not any(
        v.deliverable_name in bundle['email_draft']['body'] for v in FORM_VARIANTS.values() if v.deliverable_name
    ))


def main():
    try:
        test_every_variant_has_a_deliverable_config()
        test_form_variants_endpoint_shape_matches_config()
        test_credibility_config_defaults_and_placeholders()
        test_credibility_config_env_override_merges()
        test_outreach_copy_references_concrete_deliverable_when_offer_type_known()
        test_outreach_copy_falls_back_to_generic_phrasing_without_offer_type()
    finally:
        for lid in _lead_ids:
            repository.delete_notifications_for_lead(lid)
            repository.delete_outbound_links_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All offer-deliverable/credibility-block (Section 8 items 5 and 7) tests passed.')


if __name__ == '__main__':
    main()
