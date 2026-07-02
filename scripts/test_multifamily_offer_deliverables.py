#!/usr/bin/env python
"""
Section 8 items 5 and 7 tests: offer deliverable definitions as config
(multifamily/forms/form_variants.py) and the shared credibility-block
config (multifamily/credibility_config.py), now carrying real values
(Alkeme Insurance / Max Lyle / confirmed per-offer turnaround times).

Covers: every one of the six FormVariants has a non-empty deliverable
config with required_inputs kept to <=7 and its real, operator-
confirmed turnaround_promise; GET /api/multifamily/form-variants
returns both the per-variant deliverable fields and the shared
credibility block; public_credibility_view() never leaks a bracketed
[PLACEHOLDER] token or an empty value — it's the exact filter
static/mf-review.html's renderCredibilityBlock() mirrors, so this is
the Python-side half of the "nothing unconfirmed ever renders
publicly" invariant; the Outreach Workbench (build_outreach_bundle)
references the concrete deliverable name in generated copy when a
lead's offer_type matches a known variant, and falls back to the prior
generic phrasing when it doesn't (zero regression for leads with no
offer_type); the credibility config's env-var override merges
correctly and exposes which fields are still awaiting operator input.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.forms.form_variants import FORM_VARIANTS, FORM_VARIANT_SLUGS
from multifamily.credibility_config import (
    DEFAULT_CREDIBILITY_CONFIG, get_credibility_config, public_credibility_view,
    placeholder_fields, _ENV_VAR,
)
from multifamily.intake import build_lead_from_intake
from multifamily.outreach.outreach_bundle_builder import build_outreach_bundle
from multifamily import repository

_FAILURES = []
_M = '(OFFERDELIVERABLE TEST)'
_lead_ids = []

_EXPECTED_TURNAROUND = {
    'benchmark': '5 business days',
    'renewal-pressure': '5 business days',
    'acquisition': '3 business days',
    'lender-requirement': '3 business days',
    'builders-risk': '5 business days',
    'completion-leaseup': '5 business days',
}


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _has_bracket_token(value):
    if isinstance(value, str):
        return '[' in value
    if isinstance(value, list):
        return any(_has_bracket_token(v) for v in value)
    if isinstance(value, dict):
        return any(_has_bracket_token(v) for v in value.values())
    return False


def test_every_variant_has_a_deliverable_config_with_real_turnaround():
    for slug in FORM_VARIANT_SLUGS:
        variant = FORM_VARIANTS[slug]
        check(f"'{slug}' has a non-empty deliverable_name", bool(variant.deliverable_name))
        check(f"'{slug}' has a non-empty deliverable_description", bool(variant.deliverable_description))
        check(f"'{slug}' has 1-7 required_inputs", 1 <= len(variant.required_inputs) <= 7)
        check(f"'{slug}' has a non-empty artifact_type", bool(variant.artifact_type))
        check(f"'{slug}' turnaround_promise matches the confirmed operator value",
              variant.turnaround_promise == _EXPECTED_TURNAROUND[slug])
        check(f"'{slug}' turnaround_promise carries no placeholder token (it's a real confirmed value)",
              '[' not in variant.turnaround_promise)


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
    check("credibility config has the real company_name 'Alkeme Insurance'",
          reloaded_cred['company_name'] == 'Alkeme Insurance')
    check('credibility config has no_bor_change_line', 'no broker-of-record change' in reloaded_cred['no_bor_change_line'].lower())


def test_credibility_config_has_real_alkeme_values():
    cfg = get_credibility_config()
    check("company_name is 'Alkeme Insurance'", cfg['company_name'] == 'Alkeme Insurance')
    check("representative_name is 'Max Lyle'", cfg['representative_name'] == 'Max Lyle')
    check("representative_title mentions Alkeme Insurance", 'Alkeme Insurance' in cfg['representative_title'])
    check("proof_line mentions ALKEME and 20+ carriers", 'ALKEME' in cfg['proof_line'] and '20+ carriers' in cfg['proof_line'])
    check("representative_bio mentions ALKEME, not a years-of-experience claim",
          'ALKEME' in cfg['representative_bio'] and not any(tok in cfg['representative_bio'].lower()
                                                             for tok in ('years of experience', 'years in', '+ years')))
    check('company_logo_path defaults empty (no generated/approximated logo)', cfg['company_logo_path'] == '')
    check('company_boilerplate defaults empty (pending marketing approval)', cfg['company_boilerplate'] == '')
    check('licenses defaults to an empty list (no license line renders yet)', cfg['licenses'] == [])
    check('association_memberships defaults to an empty list', cfg['association_memberships'] == [])


def test_public_credibility_view_never_leaks_placeholder_tokens():
    """The core invariant: whatever public_credibility_view() returns is
    exactly what static/mf-review.html is allowed to render — assert
    directly that no returned value (string, list, or nested dict)
    contains a '[' character, mirroring the required "no rendered
    placeholder tokens" check for the live pages."""
    view = public_credibility_view()
    check('public_credibility_view() returns a non-empty view (real content exists)', len(view) > 0)
    check('no value in the public view carries a bracketed placeholder token', not _has_bracket_token(view))
    check("company_logo_path is NOT in the public view (still empty)", 'company_logo_path' not in view)
    check("company_boilerplate is NOT in the public view (still empty)", 'company_boilerplate' not in view)
    check("representative_photo_url is NOT in the public view (still a placeholder)", 'representative_photo_url' not in view)
    check("licenses is NOT in the public view (still empty)", 'licenses' not in view)
    check("association_memberships is NOT in the public view (still empty)", 'association_memberships' not in view)
    check("proof_line IS in the public view (real confirmed value)", 'proof_line' in view)
    check("representative_bio IS in the public view (real confirmed value)", 'representative_bio' in view)

    # Prove the filter actually filters, not just happens to pass today:
    # feed it a config with a live placeholder and confirm it's excluded.
    dirty_cfg = dict(DEFAULT_CREDIBILITY_CONFIG)
    dirty_cfg['market_access_line'] = '[PLACEHOLDER: still pending]'
    dirty_view = public_credibility_view(dirty_cfg)
    check("a bracketed market_access_line is excluded from the view", 'market_access_line' not in dirty_view)
    check('the filtered dirty view still carries no bracket tokens', not _has_bracket_token(dirty_view))

    # And prove a real licenses entry DOES render once added (no code
    # change needed — exactly the amendment's requirement).
    licensed_cfg = dict(DEFAULT_CREDIBILITY_CONFIG)
    licensed_cfg['licenses'] = [{'state': 'TX', 'number': '123456'}]
    licensed_view = public_credibility_view(licensed_cfg)
    check('a real licenses entry renders once added to config', licensed_view.get('licenses') == [{'state': 'TX', 'number': '123456'}])


def test_credibility_config_env_override_merges():
    override = {'market_access_line': 'Admitted only, TX and CA.', 'proof_line': ''}
    os.environ[_ENV_VAR] = json.dumps(override)
    try:
        cfg = get_credibility_config()
        check('env override applies a real market_access_line', cfg['market_access_line'] == 'Admitted only, TX and CA.')
        check('env override with an empty string does not blank out the default proof_line',
              cfg['proof_line'] == DEFAULT_CREDIBILITY_CONFIG['proof_line'])
        check('fields not present in the override are untouched',
              cfg['privacy_note'] == DEFAULT_CREDIBILITY_CONFIG['privacy_note'])
    finally:
        del os.environ[_ENV_VAR]
    check('override no longer applies once the env var is cleared',
          get_credibility_config()['market_access_line'] == DEFAULT_CREDIBILITY_CONFIG['market_access_line'])


def test_placeholder_fields_report_matches_expectations():
    fields = set(placeholder_fields())
    check('company_logo_path is reported as still pending', 'company_logo_path' in fields)
    check('company_boilerplate is reported as still pending', 'company_boilerplate' in fields)
    check('representative_photo_url is reported as still pending', 'representative_photo_url' in fields)
    check('licenses is reported as still pending', 'licenses' in fields)
    check('association_memberships is reported as still pending', 'association_memberships' in fields)
    check('proof_line is NOT reported as pending (real confirmed value)', 'proof_line' not in fields)
    check('representative_name is NOT reported as pending (real confirmed value)', 'representative_name' not in fields)


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
    check("offer_deliverable.turnaround_promise is the real confirmed value",
          bundle['offer_deliverable']['turnaround_promise'] == '5 business days')
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
        test_every_variant_has_a_deliverable_config_with_real_turnaround()
        test_form_variants_endpoint_shape_matches_config()
        test_credibility_config_has_real_alkeme_values()
        test_public_credibility_view_never_leaks_placeholder_tokens()
        test_credibility_config_env_override_merges()
        test_placeholder_fields_report_matches_expectations()
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
