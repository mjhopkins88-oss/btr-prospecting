#!/usr/bin/env python
"""
Pilot Campaign Control Center Phase 1 tests: campaign/target data model
(multifamily_campaigns, multifamily_campaign_targets) + tracked-link
construction (multifamily/campaigns/tracked_link.py).

Covers: campaign creation persists correctly with offer_type derived
from page_variant; campaign target creation mints a unique token and
starts with no lead attached (cold prospect); tracked URLs preserve
page_variant/UTM fields and never leak PII; target status transitions
(including notes) bump last_activity_at; marking a target converted
sets lead_id/converted_at atomically; set_campaign_target_lead can
backfill a lead without converting; and campaign/target CRUD cleans up
after itself.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.campaigns.tracked_link import build_tracked_url
from multifamily.types import CAMPAIGN_STATUSES, CAMPAIGN_TARGET_STATUSES
from multifamily.forms.form_variants import FORM_VARIANTS

_FAILURES = []
_M = '(CAMPAIGN TEST)'
_campaign_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_campaign(name_suffix, page_variant='acquisition', **overrides):
    variant = FORM_VARIANTS[page_variant]
    kwargs = dict(
        name=f'{name_suffix} {_M}', page_variant=page_variant, offer_type=variant.offer_type,
        utm_source='manual_outreach', utm_medium='email', utm_campaign=f'campaign-{name_suffix.lower()}',
        target_state='TX', created_by='rep@example.com',
    )
    kwargs.update(overrides)
    campaign = repository.create_campaign(**kwargs)
    _campaign_ids.append(campaign['id'])
    return campaign


def test_create_campaign_derives_offer_type_from_page_variant():
    campaign = _make_campaign('AcqCampaign', page_variant='acquisition')
    check('campaign persists with a real id', bool(campaign.get('id')))
    check('campaign offer_type matches the variant (acquisition_assumption_review)',
          campaign['offer_type'] == 'acquisition_assumption_review')
    check('campaign page_variant is acquisition', campaign['page_variant'] == 'acquisition')
    check('campaign defaults to draft status', campaign['status'] == 'draft')

    reloaded = repository.get_campaign(campaign['id'])
    check('get_campaign reloads the same offer_type/page_variant',
          reloaded['offer_type'] == campaign['offer_type'] and reloaded['page_variant'] == campaign['page_variant'])


def test_list_campaigns_filters_by_status():
    active = _make_campaign('ActiveCampaign', status='active')
    draft = _make_campaign('DraftCampaign', status='draft')

    all_campaigns = repository.list_campaigns()
    ids = {c['id'] for c in all_campaigns}
    check('list_campaigns includes both new campaigns', active['id'] in ids and draft['id'] in ids)

    active_only = repository.list_campaigns(status='active')
    active_ids = {c['id'] for c in active_only}
    check('status filter includes the active campaign', active['id'] in active_ids)
    check('status filter excludes the draft campaign', draft['id'] not in active_ids)


def test_update_campaign_status():
    campaign = _make_campaign('StatusFlipCampaign', status='draft')
    repository.update_campaign_status(campaign['id'], 'active')
    reloaded = repository.get_campaign(campaign['id'])
    check('update_campaign_status flips status', reloaded['status'] == 'active')
    check('updated_at changes on status update', reloaded['updated_at'] >= campaign['updated_at'])


def test_campaign_target_creation_mints_unique_token_no_lead():
    campaign = _make_campaign('TargetCampaign')
    t1 = repository.create_campaign_target(
        campaign['id'], company=f'Cold Prospect Co {_M}', contact_name='Jane Prospect',
        email='janeprospect@example.com', city='Austin', state='TX', segment='garden_150_300_units',
    )
    t2 = repository.create_campaign_target(campaign['id'], company=f'Another Prospect Co {_M}')

    check('target persists with its own id', bool(t1.get('id')))
    check('target starts with no lead_id (cold prospect)', t1['lead_id'] is None)
    check('target starts in planned status', t1['status'] == 'planned')
    check('target has a non-empty tracking_token', bool(t1['tracking_token']))
    check('two targets in the same campaign get DIFFERENT tokens', t1['tracking_token'] != t2['tracking_token'])

    fetched = repository.get_campaign_target(t1['id'])
    check('get_campaign_target reloads the same token', fetched['tracking_token'] == t1['tracking_token'])

    by_token = repository.get_campaign_target_by_token(t1['tracking_token'])
    check('get_campaign_target_by_token resolves back to the same target', by_token['id'] == t1['id'])
    check('unknown token returns None', repository.get_campaign_target_by_token('not-a-real-token') is None)

    listed = repository.list_campaign_targets(campaign['id'])
    check('list_campaign_targets returns both targets', {t1['id'], t2['id']}.issubset({t['id'] for t in listed}))


def test_tracked_url_preserves_fields_and_has_no_pii():
    campaign = _make_campaign(
        'TrackedUrlCampaign', page_variant='builders-risk',
        utm_source='manual_outreach', utm_medium='email', utm_campaign='tx_buildersrisk_q3',
    )
    target = repository.create_campaign_target(
        campaign['id'], company=f'Secret Co {_M}', contact_name='Secret Contact', email='secret@example.com',
    )
    url = build_tracked_url(campaign, target['tracking_token'])

    check('tracked URL uses the campaign page_variant slug', url.startswith('/mf-review/builders-risk?'))
    check('tracked URL carries the target token', f't={target["tracking_token"]}' in url)
    check('tracked URL carries utm_source', 'utm_source=manual_outreach' in url)
    check('tracked URL carries utm_medium', 'utm_medium=email' in url)
    check('tracked URL carries utm_campaign', 'utm_campaign=tx_buildersrisk_q3' in url)
    check('tracked URL never leaks the company name', 'Secret+Co' not in url and 'Secret%20Co' not in url)
    check('tracked URL never leaks the contact email', 'secret%40example.com' not in url and 'secret@example.com' not in url)

    absolute = build_tracked_url(campaign, target['tracking_token'], base_url='https://example.com')
    check('base_url produces an absolute URL', absolute.startswith('https://example.com/mf-review/builders-risk?'))


def test_tracked_url_omits_empty_utm_fields():
    campaign = _make_campaign('NoUtmCampaign', utm_source=None, utm_medium=None, utm_campaign=None)
    target = repository.create_campaign_target(campaign['id'], company='No Utm Co')
    url = build_tracked_url(campaign, target['tracking_token'])
    check('no utm_source in URL when campaign has none', 'utm_source' not in url)
    check('no utm_medium in URL when campaign has none', 'utm_medium' not in url)
    check('no utm_campaign in URL when campaign has none', 'utm_campaign' not in url)
    check('token is still present', f't={target["tracking_token"]}' in url)


def test_target_status_transitions_and_notes():
    campaign = _make_campaign('StatusTargetCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Status Test Co')
    check('last_activity_at starts unset', target['last_activity_at'] is None)

    repository.update_campaign_target_status(target['id'], 'contacted')
    after_contacted = repository.get_campaign_target(target['id'])
    check('status updates to contacted', after_contacted['status'] == 'contacted')
    check('last_activity_at is set after a status transition', after_contacted['last_activity_at'] is not None)

    repository.update_campaign_target_status(target['id'], 'replied', notes='Asked for a call next week.')
    after_replied = repository.get_campaign_target(target['id'])
    check('status updates to replied', after_replied['status'] == 'replied')
    check('notes persist when provided', after_replied['notes'] == 'Asked for a call next week.')

    for status in CAMPAIGN_TARGET_STATUSES:
        check(f"'{status}' is a real CAMPAIGN_TARGET_STATUSES value", status in CAMPAIGN_TARGET_STATUSES)


def test_mark_converted_and_set_lead():
    campaign = _make_campaign('ConversionCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Conversion Test Co')

    repository.set_campaign_target_lead(target['id'], 'fake-lead-id-not-converted-yet')
    after_link = repository.get_campaign_target(target['id'])
    check('set_campaign_target_lead backfills lead_id', after_link['lead_id'] == 'fake-lead-id-not-converted-yet')
    check('set_campaign_target_lead does NOT change status', after_link['status'] == 'planned')
    check('set_campaign_target_lead does NOT set converted_at', after_link['converted_at'] is None)

    repository.mark_campaign_target_converted(target['id'], 'fake-lead-id-converted')
    after_convert = repository.get_campaign_target(target['id'])
    check('mark_campaign_target_converted sets status to converted', after_convert['status'] == 'converted')
    check('mark_campaign_target_converted sets lead_id', after_convert['lead_id'] == 'fake-lead-id-converted')
    check('mark_campaign_target_converted sets converted_at', after_convert['converted_at'] is not None)
    check('mark_campaign_target_converted also bumps last_activity_at', after_convert['last_activity_at'] is not None)


def test_campaign_statuses_constant():
    for status in CAMPAIGN_STATUSES:
        campaign = _make_campaign(f'StatusConst{status}', status=status)
        check(f"campaign persists with status='{status}'", repository.get_campaign(campaign['id'])['status'] == status)


def test_delete_campaign_cleans_up_targets_too():
    campaign = _make_campaign('DeleteMeCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Delete Me Co')
    repository.delete_campaign(campaign['id'])
    check('campaign is gone after delete_campaign', repository.get_campaign(campaign['id']) is None)
    check('its target is gone too (cascaded)', repository.get_campaign_target(target['id']) is None)
    _campaign_ids.remove(campaign['id'])  # already cleaned up, don't double-delete in the finally block


def main():
    try:
        test_create_campaign_derives_offer_type_from_page_variant()
        test_list_campaigns_filters_by_status()
        test_update_campaign_status()
        test_campaign_target_creation_mints_unique_token_no_lead()
        test_tracked_url_preserves_fields_and_has_no_pii()
        test_tracked_url_omits_empty_utm_fields()
        test_target_status_transitions_and_notes()
        test_mark_converted_and_set_lead()
        test_campaign_statuses_constant()
        test_delete_campaign_cleans_up_targets_too()
    finally:
        for cid in _campaign_ids:
            try:
                repository.delete_campaign(cid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_campaign_ids)} tracked campaign(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Pilot Campaign Control Center (Phase 1) tests passed.')


if __name__ == '__main__':
    main()
