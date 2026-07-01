#!/usr/bin/env python
"""
Funnel Phase 6 tests: Source Performance upgrade — leads_by_page_variant/
leads_by_campaign_id in get_source_performance(), outbound_conversion_stats
(links sent/converted/rate, per page_variant), and page_variant/campaign_id
as two additional get_source_roi() dimensions (now 10 total).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake import build_lead_from_intake
from multifamily.matching.merge_engine import merge_incoming_on_intake

_FAILURES = []
_M = '(FUNNELSOURCEPERF TEST)'
_lead_ids = []
_tokens = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, page_variant, campaign_id, situation='benchmark', **extra):
    payload = {
        'name': 'Perf Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': situation, 'source': 'benchmark_form',
        'pageVariant': page_variant, 'campaignId': campaign_id,
    }
    payload.update(extra)
    lead, errors = build_lead_from_intake(payload)
    assert errors == [], errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    _lead_ids.append(lead.id)
    return lead


def test_leads_by_page_variant_and_campaign_id():
    campaign = f'perftest-campaign-{_M}'
    _make('PerfA', 'acquisition', campaign, situation='acquisition', targetCloseDate='2026-09-01', offerType='acquisition_assumption_review')
    _make('PerfB', 'acquisition', campaign, situation='acquisition', targetCloseDate='2026-09-01', offerType='acquisition_assumption_review')

    perf = repository.get_source_performance()
    check('leads_by_page_variant is present', 'leads_by_page_variant' in perf)
    check('leads_by_page_variant counts the 2 acquisition-page leads', perf['leads_by_page_variant'].get('acquisition', 0) >= 2)
    check('leads_by_campaign_id is present', 'leads_by_campaign_id' in perf)
    check('leads_by_campaign_id counts leads under this campaign', perf['leads_by_campaign_id'].get(campaign, 0) >= 2)


def test_source_roi_has_ten_dimensions_including_page_variant():
    _make('PerfRoi', 'renewal-pressure', f'perftest-roi-{_M}', situation='renewal', renewalDate='2026-09-01', offerType='renewal_pressure_test')
    roi = repository.get_source_roi()
    expected = {
        'source', 'source_page', 'offer_type', 'utm_source', 'utm_campaign',
        'first_touch_source', 'conversion_source', 'latest_signal_source',
        'page_variant', 'campaign_id',
    }
    check('get_source_roi() reports exactly 10 dimensions', set(roi.keys()) == expected)
    check("'renewal-pressure' bucket exists under page_variant", 'renewal-pressure' in roi['page_variant'])
    check("page_variant bucket has a leads_created count", roi['page_variant']['renewal-pressure']['leads_created'] >= 1)


def test_outbound_conversion_stats_reflect_real_conversions():
    survivor = _make('OutboundSurvivor', 'lender-requirement', f'perftest-outbound-{_M}',
                      situation='refinance', lenderDeadline='2026-08-01', offerType='lender_requirement_review')
    link = repository.create_outbound_link(
        lead_id=survivor.id, offer_type='lender_requirement_review', page_variant='lender-requirement',
        campaign_id='outbound-perf-test', source='outbound_email',
    )
    _tokens.append(link['token'])

    perf_before = repository.get_source_performance()
    sent_before = perf_before['outbound_conversion_stats']['by_page_variant'].get('lender-requirement', {}).get('sent', 0)
    converted_before = perf_before['outbound_conversion_stats']['by_page_variant'].get('lender-requirement', {}).get('converted', 0)
    check('link is counted as sent before conversion', sent_before >= 1)

    incoming, errors = build_lead_from_intake({
        'name': 'Converted Contact', 'company': f'ConvertedCo {_M}', 'email': 'convertedperf@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'refinance', 'source': 'benchmark_form',
        'offerType': 'lender_requirement_review', 'pageVariant': 'lender-requirement', 'lenderDeadline': '2026-08-01',
    })
    assert errors == [], errors
    merge_incoming_on_intake(survivor, incoming, touch_type='conversion')
    repository.mark_outbound_link_converted(link['token'], survivor.id)

    perf_after = repository.get_source_performance()
    stats_after = perf_after['outbound_conversion_stats']['by_page_variant']['lender-requirement']
    check('converted count increased by 1 after marking converted', stats_after['converted'] == converted_before + 1)
    check('conversion_rate_pct is computed (not zero when there are conversions)', stats_after['conversion_rate_pct'] > 0)
    check('total_links_sent/converted roll up at the top level',
          perf_after['outbound_conversion_stats']['total_links_sent'] >= 1 and
          perf_after['outbound_conversion_stats']['total_links_converted'] >= 1)


def main():
    try:
        test_leads_by_page_variant_and_campaign_id()
        test_source_roi_has_ten_dimensions_including_page_variant()
        test_outbound_conversion_stats_reflect_real_conversions()
    finally:
        for lid in _lead_ids:
            repository.delete_outbound_links_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} tracked lead(s), {len(_tokens)} outbound link(s) (cascaded via lead cleanup).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All funnel Source Performance (Funnel Phase 6) tests passed.')


if __name__ == '__main__':
    main()
