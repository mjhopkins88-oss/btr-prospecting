#!/usr/bin/env python
"""
Pilot Campaign Control Center Phase 2 tests: conversion / merge-back.

Exercises the SAME resolution building blocks api/routes/multifamily.py's
create_lead() composes (repository.get_campaign_target_by_token,
matching.classify, merge_incoming_on_intake, mark_campaign_target_converted,
notify_campaign_conversion) — this codebase's test scripts call modules
directly rather than through a Flask test client (see
test_multifamily_outbound_links.py for the same pattern on Funnel
Phase 3's ad-hoc link conversion).

Covers: a cold-prospect target (no lead_id) with no identity match
creates a brand-new lead and converts to it; a cold-prospect target
whose submission exact-matches an EXISTING real lead auto-merges into
that lead instead of creating a duplicate; a target that already has a
lead_id attached merges deterministically into it, bypassing the
matching pool entirely; the campaign's own page_variant/offer_type/
campaign_id stamp the lead regardless of what the payload claims; a
spam/rejected submission carrying a valid token never touches the
campaign target at all; and an already-converted target's token is
inert on a second submission.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily import matching as mf_matching
from multifamily.intake import build_lead_from_intake
from multifamily.forms.form_variants import FORM_VARIANTS
from multifamily.snapshots import snapshot_lead

_FAILURES = []
_M = '(CAMPAIGNCONVERT TEST)'
_campaign_ids = []
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_campaign(name_suffix, page_variant='acquisition', **overrides):
    variant = FORM_VARIANTS[page_variant]
    kwargs = dict(
        name=f'{name_suffix} {_M}', page_variant=page_variant, offer_type=variant.offer_type,
        utm_source='manual_outreach', utm_medium='email', utm_campaign=f'campaign-{name_suffix.lower()}',
    )
    kwargs.update(overrides)
    campaign = repository.create_campaign(**kwargs)
    _campaign_ids.append(campaign['id'])
    return campaign


def _incoming_lead(company, email, campaign, campaign_token, situation='acquisition', **extra):
    payload = {
        'name': 'Campaign Prospect', 'company': f'{company} {_M}', 'email': email,
        'state': 'TX', 'city': 'Austin', 'leadSituation': situation, 'source': 'benchmark_form',
        'offerType': campaign['offer_type'], 'pageVariant': campaign['page_variant'],
        'campaignToken': campaign_token,
    }
    payload.update(extra)
    lead, errors = build_lead_from_intake(payload)
    assert errors == [], errors
    return lead


def _resolve_campaign_submission(lead, campaign_target, campaign_row, spam_status='clean'):
    """Replicates create_lead()'s campaign_target branch exactly, so this
    test exercises the real underlying functions rather than a
    reimplementation of scoring/merge logic."""
    if spam_status == 'rejected':
        repository.insert_lead(lead)
        repository.persist_lead_signals(lead)
        repository.record_lead_attribution_touch(lead, touch_type='first')
        return lead, None

    lead.page_variant = campaign_row['page_variant']
    lead.offer_type = campaign_row['offer_type']
    lead.campaign_id = campaign_row['id']

    existing_target_lead = (
        repository.get_active_lead_by_id(campaign_target['lead_id']) if campaign_target.get('lead_id') else None
    )
    if existing_target_lead:
        mf_matching.merge_incoming_on_intake(existing_target_lead, lead, touch_type='conversion')
        lead = repository.get_lead_by_id(existing_target_lead.id) or existing_target_lead
        merged_into = lead.id
        snapshot_lead(lead, 'merged')
    else:
        result = mf_matching.classify(lead, repository.get_real_leads())
        auto = result.get('auto')
        if auto:
            mf_matching.merge_incoming_on_intake(auto.lead, lead, touch_type='conversion')
            lead = repository.get_lead_by_id(auto.lead.id) or auto.lead
            merged_into = lead.id
            snapshot_lead(lead, 'merged')
        else:
            repository.insert_lead(lead)
            repository.persist_lead_signals(lead)
            repository.record_lead_attribution_touch(lead, touch_type='conversion')
            merged_into = None
            snapshot_lead(lead, 'created')
    repository.mark_campaign_target_converted(campaign_target['id'], lead.id)
    _lead_ids.append(lead.id)
    return lead, merged_into


def test_cold_prospect_no_match_creates_new_lead():
    campaign = _make_campaign('ColdNoMatch')
    target = repository.create_campaign_target(campaign['id'], company='Cold Prospect Co', email='coldnomatch@example.com')
    check('target starts unconverted', target.get('converted_at') is None)

    lead = _incoming_lead('Cold Prospect Co', 'coldnomatch@example.com', campaign, target['tracking_token'], targetCloseDate='2026-09-01')
    resolved_lead, merged_into = _resolve_campaign_submission(lead, target, campaign)

    check('a brand-new lead was created (no merge)', merged_into is None)
    check('the lead was stamped with the campaign page_variant', resolved_lead.page_variant == 'acquisition')
    check('the lead was stamped with the campaign offer_type', resolved_lead.offer_type == campaign['offer_type'])
    check('the lead was stamped with the real campaign_id', resolved_lead.campaign_id == campaign['id'])

    reloaded_target = repository.get_campaign_target(target['id'])
    check('target is now converted', reloaded_target['status'] == 'converted')
    check('target lead_id backfilled to the new lead', reloaded_target['lead_id'] == resolved_lead.id)
    check('target converted_at is set', reloaded_target['converted_at'] is not None)

    touches = repository.get_attribution_for_lead(resolved_lead.id)
    conversion_touches = [t for t in touches if t.get('touch_type') == 'conversion']
    check('a conversion attribution touch exists', len(conversion_touches) == 1)
    check('the conversion touch carries the real campaign_id', conversion_touches[0].get('campaign_id') == campaign['id'])


def test_cold_prospect_exact_match_merges_not_duplicates():
    campaign = _make_campaign('ColdExactMatch')
    # An existing real lead with the same email — this is what the
    # campaign submission should merge into instead of duplicating.
    existing_payload = {
        'name': 'Existing Contact', 'company': f'Existing Match Co {_M}', 'email': 'exactmatch@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'manual',
    }
    existing_lead, errors = build_lead_from_intake(existing_payload)
    assert errors == [], errors
    repository.insert_lead(existing_lead)
    repository.persist_lead_signals(existing_lead)
    repository.record_lead_attribution_touch(existing_lead, touch_type='first')
    _lead_ids.append(existing_lead.id)

    target = repository.create_campaign_target(campaign['id'], company='Existing Match Co', email='exactmatch@example.com')
    lead = _incoming_lead('Existing Match Co', 'exactmatch@example.com', campaign, target['tracking_token'], targetCloseDate='2026-09-01')
    resolved_lead, merged_into = _resolve_campaign_submission(lead, target, campaign)

    check('resolved into the EXISTING lead, not a new one', resolved_lead.id == existing_lead.id)
    check('merged_into reflects the existing lead', merged_into == existing_lead.id)

    all_leads_with_email = [
        r for r in repository.get_real_leads()
        if any((c.email or '').lower() == 'exactmatch@example.com' for c in (r.contacts or []))
    ]
    check('no duplicate lead was created for this email', len(all_leads_with_email) == 1)

    reloaded_target = repository.get_campaign_target(target['id'])
    check('target lead_id points at the existing lead', reloaded_target['lead_id'] == existing_lead.id)


def test_target_with_existing_lead_merges_deterministically():
    campaign = _make_campaign('ExistingLeadTarget')
    survivor_payload = {
        'name': 'Survivor Contact', 'company': f'Survivor Co {_M}', 'email': 'survivordiff@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'manual',
    }
    survivor, errors = build_lead_from_intake(survivor_payload)
    assert errors == [], errors
    repository.insert_lead(survivor)
    repository.persist_lead_signals(survivor)
    repository.record_lead_attribution_touch(survivor, touch_type='first')
    _lead_ids.append(survivor.id)

    target = repository.create_campaign_target(campaign['id'], company='Survivor Co')
    repository.set_campaign_target_lead(target['id'], survivor.id)
    target_reloaded = repository.get_campaign_target(target['id'])
    check('target is now linked to the survivor lead (but not converted)', target_reloaded['lead_id'] == survivor.id)
    check('linking a lead does not convert the target', target_reloaded['status'] != 'converted')

    # A DIFFERENT email submits through the same tracked link — since the
    # target already names a specific lead, this should merge into THAT
    # lead deterministically, bypassing the matching pool entirely (the
    # matching engine would never have matched this on identity alone).
    lead = _incoming_lead(
        'Totally Different Name Co', 'adifferentemailentirely@example.com', campaign,
        target_reloaded['tracking_token'], targetCloseDate='2026-09-01',
    )
    resolved_lead, merged_into = _resolve_campaign_submission(lead, target_reloaded, campaign)

    check('merged deterministically into the pre-linked survivor lead', resolved_lead.id == survivor.id)
    check('merged_into reflects the survivor', merged_into == survivor.id)
    check('survivor absorbed the acquisition signal from the different-identity submission',
          any(s.signal_type == 'acquisition' for s in resolved_lead.signals))


def test_spam_submission_with_valid_token_never_converts():
    campaign = _make_campaign('SpamToken')
    target = repository.create_campaign_target(campaign['id'], company='Spam Target Co', email='spamtarget@example.com')
    lead = _incoming_lead('Spam Target Co', 'spamtarget@example.com', campaign, target['tracking_token'])

    resolved_lead, merged_into = _resolve_campaign_submission(lead, target, campaign, spam_status='rejected')
    _lead_ids.append(resolved_lead.id)

    reloaded_target = repository.get_campaign_target(target['id'])
    check('target is NOT converted after a rejected/spam submission', reloaded_target['status'] == 'planned')
    check('target converted_at stays unset', reloaded_target['converted_at'] is None)
    check('target lead_id stays unset (never strengthened)', reloaded_target['lead_id'] is None)


def test_already_converted_target_token_is_inert():
    campaign = _make_campaign('AlreadyConverted')
    target = repository.create_campaign_target(campaign['id'], company='Already Converted Co', email='alreadyconverted@example.com')
    lead1 = _incoming_lead('Already Converted Co', 'alreadyconverted@example.com', campaign, target['tracking_token'])
    resolved1, _ = _resolve_campaign_submission(lead1, target, campaign)
    converted_target = repository.get_campaign_target(target['id'])
    check('first submission converts the target', converted_target['status'] == 'converted')

    # Simulate the route's precedence check: an already-converted target
    # is treated as if the token didn't resolve at all.
    fetched_again = repository.get_campaign_target_by_token(target['tracking_token'])
    should_be_ignored = bool(fetched_again and fetched_again.get('converted_at'))
    check("a second lookup by the SAME token still finds the target row (for audit)", fetched_again is not None)
    check('the route-level check would treat it as already-used (converted_at set)', should_be_ignored)


def main():
    try:
        test_cold_prospect_no_match_creates_new_lead()
        test_cold_prospect_exact_match_merges_not_duplicates()
        test_target_with_existing_lead_merges_deterministically()
        test_spam_submission_with_valid_token_never_converts()
        test_already_converted_target_token_is_inert()
    finally:
        for lid in _lead_ids:
            repository.delete_outbound_links_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        for cid in _campaign_ids:
            try:
                repository.delete_campaign(cid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} lead(s), {len(_campaign_ids)} campaign(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Pilot Campaign conversion (Phase 2) tests passed.')


if __name__ == '__main__':
    main()
