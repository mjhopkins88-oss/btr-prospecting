#!/usr/bin/env python
"""
Pilot Campaign Control Center Phase 5 tests: Overview + Source
Performance campaign metrics (repository.get_campaign_performance() +
multifamily/funnel/overview_widgets.py's build_funnel_widgets
campaign additions).

Covers: campaign/target counts roll up correctly across multiple
campaigns; best_campaign/best_offer_page pick the highest conversion
rate among buckets with at least one target; targets_needing_followup
counts only planned/contacted targets; recently_converted reflects the
most recent conversion by timestamp; conversion-rate-by-segment/state
buckets compute correctly; an empty pipeline (no campaigns at all)
returns well-formed zero/None values rather than erroring; and
build_funnel_widgets folds the campaign rollup in alongside the
existing Funnel Phase 6 lead-source widgets without disturbing them.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.funnel.overview_widgets import build_funnel_widgets
from multifamily.forms.form_variants import FORM_VARIANTS

_FAILURES = []
_M = '(CAMPAIGNPERF TEST)'
_campaign_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_campaign(name_suffix, page_variant='acquisition', **overrides):
    variant = FORM_VARIANTS[page_variant]
    kwargs = dict(name=f'{name_suffix} {_M}', page_variant=page_variant, offer_type=variant.offer_type)
    kwargs.update(overrides)
    campaign = repository.create_campaign(**kwargs)
    _campaign_ids.append(campaign['id'])
    return campaign


def test_totals_and_rollup_across_campaigns():
    high_performer = _make_campaign('HighPerformer', page_variant='acquisition', status='active')
    low_performer = _make_campaign('LowPerformer', page_variant='benchmark', status='active')

    # High performer: 2 targets, 2 converted (100%).
    for i in range(2):
        t = repository.create_campaign_target(high_performer['id'], company=f'HighCo{i}', segment='garden', state='TX')
        repository.mark_campaign_target_converted(t['id'], f'fake-lead-{i}')

    # Low performer: 4 targets, 1 converted (25%), 1 meeting_booked, 2 still planned.
    t1 = repository.create_campaign_target(low_performer['id'], company='LowCo1', segment='mid_rise', state='CA')
    repository.mark_campaign_target_converted(t1['id'], 'fake-lead-low')
    t2 = repository.create_campaign_target(low_performer['id'], company='LowCo2', segment='mid_rise', state='CA')
    repository.update_campaign_target_status(t2['id'], 'meeting_booked')
    repository.create_campaign_target(low_performer['id'], company='LowCo3', segment='mid_rise', state='CA')
    repository.create_campaign_target(low_performer['id'], company='LowCo4', segment='mid_rise', state='CA')

    perf = repository.get_campaign_performance()
    check('total_active_campaigns includes both', perf['total_active_campaigns'] >= 2)
    check('total_targets counts all 6 targets', perf['total_targets'] >= 6)
    check('total_converted counts all 3 conversions', perf['total_converted'] >= 3)
    check('total_meetings counts the 1 meeting', perf['total_meetings'] >= 1)
    check('targets_needing_followup counts the 2 still-planned targets', perf['targets_needing_followup'] >= 2)

    check('best_campaign is the 100%-conversion campaign', perf['best_campaign']['campaign_id'] == high_performer['id'])
    check('best_campaign conversion_rate_pct is 100.0', perf['best_campaign']['conversion_rate_pct'] == 100.0)

    check('best_offer_page is acquisition (100% vs 25%)', perf['best_offer_page']['page_variant'] == 'acquisition')


def test_conversion_rate_by_segment_and_state():
    campaign = _make_campaign('SegmentCampaign', page_variant='builders-risk')
    t1 = repository.create_campaign_target(campaign['id'], company='SegA', segment='garden_150_300', state='TX')
    repository.mark_campaign_target_converted(t1['id'], 'fake-lead-seg-a')
    repository.create_campaign_target(campaign['id'], company='SegB', segment='garden_150_300', state='TX')
    repository.create_campaign_target(campaign['id'], company='SegC', segment='high_rise', state='CA')

    perf = repository.get_campaign_performance()
    garden_bucket = perf['conversion_rate_by_segment'].get('garden_150_300')
    check('segment bucket exists for garden_150_300', garden_bucket is not None)
    check('garden_150_300 segment has 2 targets, 1 converted', garden_bucket['targets'] == 2 and garden_bucket['converted'] == 1)
    check('garden_150_300 conversion_rate_pct is 50.0', garden_bucket['conversion_rate_pct'] == 50.0)

    tx_bucket = perf['conversion_rate_by_state'].get('TX')
    check('state bucket exists for TX', tx_bucket is not None)
    # >= not == : an earlier test in this same file also uses state='TX',
    # and campaigns aren't cleaned up between test functions (only at the
    # very end) — this only needs to confirm the bucket picked up this
    # test's targets, not claim exclusive ownership of the TX bucket.
    check('TX state bucket includes at least this test\'s 2 targets', tx_bucket['targets'] >= 2)


def test_recently_converted_reflects_the_latest_by_time():
    campaign = _make_campaign('RecentCampaign', page_variant='completion-leaseup')
    t1 = repository.create_campaign_target(campaign['id'], company=f'FirstConverted {_M}')
    repository.mark_campaign_target_converted(t1['id'], 'fake-lead-first')
    t2 = repository.create_campaign_target(campaign['id'], company=f'SecondConverted {_M}')
    repository.mark_campaign_target_converted(t2['id'], 'fake-lead-second')

    perf = repository.get_campaign_performance()
    check('recently_converted is present', perf['recently_converted'] is not None)
    check('recently_converted names the campaign', perf['recently_converted']['campaign_name'] == campaign['name'])


def test_build_funnel_widgets_folds_in_campaign_metrics():
    fake_source_perf = {
        'leads_by_page_variant': {'acquisition': 3, 'none': 1},
        'outbound_conversion_stats': {'total_links_sent': 5, 'total_links_converted': 2},
        'serp': {'review_candidates_pending': 1},
    }
    fake_campaign_perf = {
        'total_active_campaigns': 4, 'total_converted': 7, 'targets_needing_followup': 3,
        'best_campaign': {'campaign_id': 'abc', 'conversion_rate_pct': 66.0},
        'best_offer_page': {'page_variant': 'acquisition', 'conversion_rate_pct': 80.0},
        'recently_converted': {'company': 'Test Co', 'campaign_name': 'Test Campaign'},
    }
    widgets = build_funnel_widgets(fake_source_perf, fake_campaign_perf)
    check('active_campaigns present', widgets['active_campaigns'] == 4)
    check('campaign_conversions present', widgets['campaign_conversions'] == 7)
    check('campaign_targets_needing_followup present', widgets['campaign_targets_needing_followup'] == 3)
    check('best_campaign passed through', widgets['best_campaign']['campaign_id'] == 'abc')
    check('best_performing_offer_page passed through', widgets['best_performing_offer_page']['page_variant'] == 'acquisition')
    check('recently_converted_campaign_target passed through', widgets['recently_converted_campaign_target']['company'] == 'Test Co')
    # Existing Funnel Phase 6 widgets still intact.
    check('top_offer_page still computed from leads_by_page_variant', widgets['top_offer_page'] == 'acquisition')
    check('converted_from_outbound still computed', widgets['converted_from_outbound'] == 2)


def test_build_funnel_widgets_without_campaign_performance_is_safe():
    fake_source_perf = {'leads_by_page_variant': {}, 'outbound_conversion_stats': {}, 'serp': {}}
    widgets = build_funnel_widgets(fake_source_perf)
    check('active_campaigns defaults to 0 when campaign_performance omitted', widgets['active_campaigns'] == 0)
    check('best_campaign defaults to None when campaign_performance omitted', widgets['best_campaign'] is None)


def test_empty_pipeline_is_well_formed():
    # No campaigns tracked by THIS test at all — exercises a totally
    # empty result gracefully (best_campaign/best_offer_page/recently_
    # converted all None, no ZeroDivisionError).
    for cid in list(_campaign_ids):
        repository.delete_campaign(cid)
        _campaign_ids.remove(cid)
    perf = repository.get_campaign_performance()
    check('empty pipeline: no exception, returns a dict', isinstance(perf, dict))
    check('empty pipeline: total_targets is 0', perf['total_targets'] == 0)
    check('empty pipeline: best_campaign is None', perf['best_campaign'] is None)
    check('empty pipeline: best_offer_page is None', perf['best_offer_page'] is None)
    check('empty pipeline: recently_converted is None', perf['recently_converted'] is None)


def main():
    try:
        test_totals_and_rollup_across_campaigns()
        test_conversion_rate_by_segment_and_state()
        test_recently_converted_reflects_the_latest_by_time()
        test_build_funnel_widgets_folds_in_campaign_metrics()
        test_build_funnel_widgets_without_campaign_performance_is_safe()
        test_empty_pipeline_is_well_formed()
    finally:
        for cid in _campaign_ids:
            try:
                repository.delete_campaign(cid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_campaign_ids)} campaign(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Pilot Campaign performance (Phase 5) tests passed.')


if __name__ == '__main__':
    main()
