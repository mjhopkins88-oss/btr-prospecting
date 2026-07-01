#!/usr/bin/env python
"""
Funnel Phase 7 tests: Overview funnel widgets
(multifamily/funnel/overview_widgets.py — best_inbound_handraiser +
build_funnel_widgets, both consumed by api/routes/multifamily.py's
GET /overview).

Covers: best_inbound_handraiser picks the first real benchmark-form
lead in an already priority-sorted list, skips demo leads and
non-form-sourced real leads (manual/serp), and returns None when there
are no hand-raisers; build_funnel_widgets derives new_forms_by_offer/
top_offer_page/serp_triggers_needing_review/converted_from_outbound/
outbound_links_sent purely from a get_source_performance()-shaped dict
(no DB access of its own).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.intake import build_lead_from_intake
from multifamily.funnel.overview_widgets import best_inbound_handraiser, build_funnel_widgets

_FAILURES = []
_M = '(FUNNELOVERVIEW TEST)'


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _lead(company, source, is_demo=False, **extra):
    payload = {
        'name': 'Overview Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': source,
    }
    payload.update(extra)
    lead, errors = build_lead_from_intake(payload)
    assert errors == [], errors
    lead.is_demo = is_demo
    return lead


def test_picks_the_first_real_benchmark_form_lead():
    manual_lead = _lead('ManualEntry', 'manual')
    serp_lead = _lead('SerpTrigger', 'serp')
    demo_handraiser = _lead('DemoHandraiser', 'benchmark_form', is_demo=True)
    real_handraiser = _lead('RealHandraiser', 'benchmark_form', offerType='acquisition_assumption_review', pageVariant='acquisition')
    another_manual = _lead('AnotherManual', 'manual')

    # Priority-sorted order is the caller's job (pipeline.sort_leads_by_priority) —
    # this list is deliberately pre-ordered to exercise "first match wins".
    leads = [manual_lead, serp_lead, demo_handraiser, real_handraiser, another_manual]
    result = best_inbound_handraiser(leads)
    check('picks the real benchmark_form lead, skipping manual/serp/demo ones before it',
          result is not None and result.id == real_handraiser.id)
    check('picked lead carries its page_variant', result.page_variant == 'acquisition')


def test_skips_demo_even_when_first_in_priority_order():
    demo_handraiser = _lead('DemoFirst', 'benchmark_form', is_demo=True)
    real_handraiser = _lead('RealSecond', 'benchmark_form')
    leads = [demo_handraiser, real_handraiser]
    result = best_inbound_handraiser(leads)
    check('demo hand-raiser is skipped even if first in the list', result is not None and result.id == real_handraiser.id)


def test_returns_none_when_no_handraiser_present():
    manual_lead = _lead('OnlyManual', 'manual')
    serp_lead = _lead('OnlySerp', 'serp')
    result = best_inbound_handraiser([manual_lead, serp_lead])
    check('returns None when no real benchmark_form lead exists', result is None)
    check('returns None on an empty list', best_inbound_handraiser([]) is None)


def test_build_funnel_widgets_derives_from_source_performance_shape():
    fake_perf = {
        'leads_by_page_variant': {'acquisition': 5, 'benchmark': 3, 'none': 2},
        'outbound_conversion_stats': {'total_links_sent': 10, 'total_links_converted': 4, 'by_page_variant': {}},
        'serp': {'review_candidates_pending': 7},
    }
    widgets = build_funnel_widgets(fake_perf)
    check("'none' is excluded from new_forms_by_offer", 'none' not in widgets['new_forms_by_offer'])
    check('new_forms_by_offer keeps the real page-variant counts',
          widgets['new_forms_by_offer'] == {'acquisition': 5, 'benchmark': 3})
    check('top_offer_page picks the highest count (acquisition)', widgets['top_offer_page'] == 'acquisition')
    check('serp_triggers_needing_review reads from perf[serp]', widgets['serp_triggers_needing_review'] == 7)
    check('converted_from_outbound reads total_links_converted', widgets['converted_from_outbound'] == 4)
    check('outbound_links_sent reads total_links_sent', widgets['outbound_links_sent'] == 10)
    check('does NOT include best_inbound_handraiser (caller attaches it)',
          'best_inbound_handraiser' not in widgets)


def test_build_funnel_widgets_handles_empty_source_performance():
    widgets = build_funnel_widgets({})
    check('empty perf -> new_forms_by_offer is empty', widgets['new_forms_by_offer'] == {})
    check('empty perf -> top_offer_page is None', widgets['top_offer_page'] is None)
    check('empty perf -> serp_triggers_needing_review defaults to 0', widgets['serp_triggers_needing_review'] == 0)
    check('empty perf -> converted_from_outbound defaults to 0', widgets['converted_from_outbound'] == 0)
    check('empty perf -> outbound_links_sent defaults to 0', widgets['outbound_links_sent'] == 0)


def main():
    test_picks_the_first_real_benchmark_form_lead()
    test_skips_demo_even_when_first_in_priority_order()
    test_returns_none_when_no_handraiser_present()
    test_build_funnel_widgets_derives_from_source_performance_shape()
    test_build_funnel_widgets_handles_empty_source_performance()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All funnel Overview widgets (Funnel Phase 7) tests passed.')


if __name__ == '__main__':
    main()
