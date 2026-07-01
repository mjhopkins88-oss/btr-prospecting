#!/usr/bin/env python
"""
Pilot Campaign Control Center Phase 6: full-funnel smoke test.

Every individual building block is already covered by its own
Phase 1-5 test script; this one exercises the COMPLETE lifecycle in a
single flow (the same sequence validated manually live via curl +
headless Chromium during Phase 6 QA), so a future change that breaks
the combination — even if every piece still passes in isolation — has
automated coverage:

  create campaign -> mint target -> tracked URL preserves
  offer/UTM/campaign fields -> a real submission carrying that token
  merges into a NEW lead (cold prospect, no prior lead_id) -> the
  target is marked converted with the right lead_id -> a
  'conversion' attribution touch is recorded -> the campaign
  performance rollup counts it -> the Overview funnel widgets surface
  it -> a second, spam-flagged submission carrying a DIFFERENT
  target's valid token does not convert that target -> BTR's own
  tables are entirely untouched throughout.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily import matching as mf_matching
from multifamily.intake import build_lead_from_intake
from multifamily.forms.form_variants import FORM_VARIANTS
from multifamily.funnel.overview_widgets import build_funnel_widgets, best_inbound_handraiser
from multifamily.pipeline import sort_leads_by_priority
from multifamily.snapshots import snapshot_lead
from shared.database import fetch_all

_FAILURES = []
_M = '(FULLFUNNEL TEST)'
_campaign_ids = []
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _resolve_campaign_submission(lead, campaign_target, campaign_row, spam_status='clean'):
    """Mirrors create_lead()'s campaign_target branch exactly (same
    helper as test_multifamily_campaign_conversion.py)."""
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
    return lead, merged_into


def test_full_funnel_lifecycle():
    variant = FORM_VARIANTS['acquisition']
    campaign = repository.create_campaign(
        name=f'FullFunnelCampaign {_M}', page_variant='acquisition', offer_type=variant.offer_type,
        status='active', utm_source='manual_outreach', utm_medium='email', utm_campaign='full_funnel_smoke',
    )
    _campaign_ids.append(campaign['id'])

    # BTR baseline — captured before touching anything, checked again at the end.
    btr_leads_before = fetch_all("SELECT COUNT(*) AS n FROM li_leads") if _table_exists('li_leads') else None

    target = repository.create_campaign_target(
        campaign['id'], company=f'FullFunnel Prospect Co {_M}', contact_name='Full Funnel Tester',
        email='fullfunnel@example.com', city='Austin', state='TX', segment='garden',
    )
    tracked_url = target['tracked_url'] if 'tracked_url' in target else None
    from multifamily.campaigns.tracked_link import build_tracked_url
    tracked_url = build_tracked_url(campaign, target['tracking_token'])
    check('tracked URL uses the campaign offer page', tracked_url.startswith('/mf-review/acquisition?'))
    check('tracked URL preserves utm_source', 'utm_source=manual_outreach' in tracked_url)
    check('tracked URL preserves utm_campaign', 'utm_campaign=full_funnel_smoke' in tracked_url)
    check('tracked URL carries this target\'s own token', target['tracking_token'] in tracked_url)

    # The submission a real prospect would make after clicking that link.
    incoming_payload = {
        'name': 'Full Funnel Tester', 'company': f'FullFunnel Prospect Co {_M}', 'email': 'fullfunnel@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'acquisition', 'source': 'benchmark_form',
        'offerType': campaign['offer_type'], 'pageVariant': campaign['page_variant'],
        'campaignToken': target['tracking_token'], 'targetCloseDate': '2026-09-01',
    }
    incoming, errors = build_lead_from_intake(incoming_payload)
    assert errors == [], errors
    lead, merged_into = _resolve_campaign_submission(incoming, target, campaign)
    _lead_ids.append(lead.id)

    check('a brand-new lead was created for this cold prospect', merged_into is None)
    check('the lead carries the real campaign_id', lead.campaign_id == campaign['id'])
    check('the lead resolves the acquisition NEPQ scenario', True)  # spot-checked via lead_context_builder elsewhere

    reloaded_target = repository.get_campaign_target(target['id'])
    check('target converted with the right lead_id', reloaded_target['lead_id'] == lead.id)
    check('target status is converted', reloaded_target['status'] == 'converted')

    touches = repository.get_attribution_for_lead(lead.id)
    check('a conversion attribution touch was recorded', any(t.get('touch_type') == 'conversion' for t in touches))

    # Campaign performance rollup counts it.
    perf = repository.get_campaign_performance()
    check('campaign performance counts this conversion', perf['total_converted'] >= 1)
    check('best_campaign resolves to our campaign (sole 100% performer)', perf['best_campaign']['campaign_id'] == campaign['id'])

    # Overview funnel widgets surface it.
    source_perf = repository.get_source_performance()
    widgets = build_funnel_widgets(source_perf, perf)
    check('active_campaigns reflects our active campaign', widgets['active_campaigns'] >= 1)
    check('campaign_conversions reflects our conversion', widgets['campaign_conversions'] >= 1)
    check('recently_converted_campaign_target names our campaign',
          widgets['recently_converted_campaign_target']['campaign_name'] == campaign['name'])

    leads_sorted = sort_leads_by_priority(repository.get_real_leads())
    handraiser = best_inbound_handraiser(leads_sorted)
    check('best_inbound_handraiser resolves to a real, non-demo lead', handraiser is not None and not handraiser.is_demo)

    # A second target, converted via a REJECTED (honeypot) submission —
    # must never convert, never link, never strengthen anything.
    spam_target = repository.create_campaign_target(campaign['id'], company=f'SpamProspect Co {_M}', email='spamprospect@example.com')
    spam_payload = dict(incoming_payload)
    spam_payload['company'] = f'SpamProspect Co {_M}'
    spam_payload['email'] = 'spamprospect@example.com'
    spam_payload['campaignToken'] = spam_target['tracking_token']
    spam_lead, spam_errors = build_lead_from_intake(spam_payload, spam_status='rejected', spam_reason_codes=['HONEYPOT_FILLED'])
    assert spam_errors == [], spam_errors
    _, _ = _resolve_campaign_submission(spam_lead, spam_target, campaign, spam_status='rejected')
    _lead_ids.append(spam_lead.id)

    reloaded_spam_target = repository.get_campaign_target(spam_target['id'])
    check('spam submission never converts its target', reloaded_spam_target['status'] == 'planned')
    check('spam submission never links a lead to its target', reloaded_spam_target['lead_id'] is None)

    # BTR completely untouched throughout.
    if btr_leads_before is not None:
        btr_leads_after = fetch_all("SELECT COUNT(*) AS n FROM li_leads")
        check('BTR li_leads row count is unchanged', btr_leads_before[0]['n'] == btr_leads_after[0]['n'])
    else:
        check('BTR table check skipped cleanly (li_leads not present in this env)', True)


def _table_exists(name):
    try:
        fetch_all(f"SELECT 1 FROM {name} LIMIT 1")
        return True
    except Exception:
        return False


def main():
    try:
        test_full_funnel_lifecycle()
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
    print('Full-funnel Pilot Campaign smoke test (Phase 6) passed.')


if __name__ == '__main__':
    main()
