#!/usr/bin/env python
"""
Pilot Campaign Control Center Phase 4 tests: Outreach Workbench
tracked-link integration.

Covers the exact composition api/routes/multifamily.py's
create_campaign_target() route performs when the request carries a
leadId (the Workbench generating a campaign-tracked link for a lead
already sitting in the pipeline): create_campaign_target() followed by
set_campaign_target_lead() pre-links the target to that lead BEFORE
any conversion happens, so a submission through that tracked link
later merges deterministically into this exact lead (Phase 2's
existing-target-lead path) rather than routing through the matching
engine as a cold prospect.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.campaigns.tracked_link import build_tracked_url
from multifamily.intake import build_lead_from_intake
from multifamily.forms.form_variants import FORM_VARIANTS

_FAILURES = []
_M = '(WORKBENCHLINK TEST)'
_campaign_ids = []
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def test_workbench_generated_target_prelinks_to_the_lead():
    variant = FORM_VARIANTS['acquisition']
    campaign = repository.create_campaign(
        name=f'Workbench Link Campaign {_M}', page_variant='acquisition', offer_type=variant.offer_type,
    )
    _campaign_ids.append(campaign['id'])

    # A real lead already sitting in the pipeline (what the Outreach
    # Workbench would be looking at when it generates this link).
    lead_payload = {
        'name': 'Workbench Tester', 'company': f'Workbench Lead Co {_M}', 'email': 'workbenchlead@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'manual',
    }
    lead, errors = build_lead_from_intake(lead_payload)
    assert errors == [], errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    _lead_ids.append(lead.id)

    # Replicates exactly what the route does: create the target from
    # the lead's own contact fields, then pre-link it.
    contact = lead.contacts[0] if lead.contacts else None
    target = repository.create_campaign_target(
        campaign['id'], company=lead.company.name,
        contact_name=(contact.full_name if contact else None),
        email=(contact.email if contact else None),
        city=lead.city, state=lead.state,
    )
    repository.set_campaign_target_lead(target['id'], lead.id)

    reloaded = repository.get_campaign_target(target['id'])
    check('target is pre-linked to the lead', reloaded['lead_id'] == lead.id)
    check('target is NOT converted just from pre-linking', reloaded['status'] != 'converted')
    check('target company matches the lead', reloaded['company'] == lead.company.name)

    tracked_url = build_tracked_url(campaign, reloaded['tracking_token'])
    check('the tracked URL still uses the campaign page_variant', tracked_url.startswith('/mf-review/acquisition?'))
    check('the tracked URL carries this specific token', reloaded['tracking_token'] in tracked_url)


def test_prelinked_target_has_no_pii_leak_via_tracking_token_alone():
    # The token itself must not encode/derive from the lead's identity —
    # confirms the token is independent random data, not something an
    # outside party could compute from public lead info.
    variant = FORM_VARIANTS['benchmark']
    campaign = repository.create_campaign(name=f'NoLeakCampaign {_M}', page_variant='benchmark', offer_type=variant.offer_type)
    _campaign_ids.append(campaign['id'])
    t1 = repository.create_campaign_target(campaign['id'], company='Same Co', email='same@example.com')
    t2 = repository.create_campaign_target(campaign['id'], company='Same Co', email='same@example.com')
    check('identical target details still produce different tokens', t1['tracking_token'] != t2['tracking_token'])


def main():
    try:
        test_workbench_generated_target_prelinks_to_the_lead()
        test_prelinked_target_has_no_pii_leak_via_tracking_token_alone()
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
    print('All Pilot Campaign Workbench-link (Phase 4) tests passed.')


if __name__ == '__main__':
    main()
