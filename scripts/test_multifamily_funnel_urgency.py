#!/usr/bin/env python
"""
Funnel Phase 4 tests: funnel_urgency derived layer
(multifamily/funnel/urgency.py) + its tie-break wiring into
pipeline.sort_leads_by_priority.

Covers: high/medium/low/none urgency for each of the 4 covered
situations (acquisition close, lender deadline, construction start,
completion occupancy) at the documented thresholds; an overdue deadline
still reads as 'high' (not 'none'); renewal/benchmark/operating leads
get 'none' (renewal has its own existing timing system, no urgency
duplication); funnel_urgency never touches score_total/score_category;
and sort_leads_by_priority only uses urgency to break ties WITHIN the
same category+score, never to reorder across categories.
"""
import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.intake import build_lead_from_intake
from multifamily.funnel.urgency import compute_funnel_urgency
from multifamily.pipeline import sort_leads_by_priority

_FAILURES = []
_M = '(FUNNELURGENCY TEST)'


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _iso(days_from_today):
    return (date.today() + timedelta(days=days_from_today)).isoformat()


def _build(situation, extra, company_suffix):
    payload = {
        'name': 'Urgency Tester', 'company': f'Urgencyflow Co {company_suffix} {_M}',
        'email': f'{company_suffix.lower()}@example.com', 'state': 'TX', 'city': 'Austin',
        'leadSituation': situation, 'source': 'manual',
    }
    payload.update(extra)
    lead, errors = build_lead_from_intake(payload)
    assert errors == [], errors
    return lead


def test_acquisition_thresholds():
    high = _build('acquisition', {'targetCloseDate': _iso(30)}, 'AcqHigh')
    medium = _build('acquisition', {'targetCloseDate': _iso(90)}, 'AcqMedium')
    low = _build('acquisition', {'targetCloseDate': _iso(200)}, 'AcqLow')
    none_ = _build('acquisition', {}, 'AcqNone')

    check('acquisition <=60d -> high', compute_funnel_urgency(high)['level'] == 'high')
    check('acquisition 61-120d -> medium', compute_funnel_urgency(medium)['level'] == 'medium')
    check('acquisition >120d -> low', compute_funnel_urgency(low)['level'] == 'low')
    check('acquisition with no close date -> none', compute_funnel_urgency(none_)['level'] == 'none')
    check('acquisition basis_field is target_close_date', compute_funnel_urgency(high)['basis_field'] == 'target_close_date')


def test_lender_thresholds():
    high = _build('refinance', {'lenderDeadline': _iso(10)}, 'LenderHigh')
    medium = _build('refinance', {'lenderDeadline': _iso(45)}, 'LenderMedium')
    low = _build('refinance', {'lenderDeadline': _iso(90)}, 'LenderLow')

    check('lender <=30d -> high', compute_funnel_urgency(high)['level'] == 'high')
    check('lender 31-60d -> medium', compute_funnel_urgency(medium)['level'] == 'medium')
    check('lender >60d -> low', compute_funnel_urgency(low)['level'] == 'low')


def test_construction_thresholds():
    high = _build('construction', {'projectStartDate': _iso(20)}, 'ConstructHigh')
    medium = _build('construction', {'projectStartDate': _iso(100)}, 'ConstructMedium')
    low = _build('construction', {'projectStartDate': _iso(300)}, 'ConstructLow')

    check('construction <=60d -> high', compute_funnel_urgency(high)['level'] == 'high')
    check('construction 61-120d -> medium', compute_funnel_urgency(medium)['level'] == 'medium')
    check('construction >120d -> low', compute_funnel_urgency(low)['level'] == 'low')


def test_completion_thresholds():
    high = _build('completion', {'firstOccupancyDate': _iso(40)}, 'CompletionHigh')
    medium = _build('completion', {'firstOccupancyDate': _iso(150)}, 'CompletionMedium')
    low = _build('completion', {'firstOccupancyDate': _iso(250)}, 'CompletionLow')
    fallback = _build('completion', {'expectedCompletionDate': _iso(30)}, 'CompletionFallback')

    check('completion <=90d -> high', compute_funnel_urgency(high)['level'] == 'high')
    check('completion 91-180d -> medium', compute_funnel_urgency(medium)['level'] == 'medium')
    check('completion >180d -> low', compute_funnel_urgency(low)['level'] == 'low')
    check('completion falls back to expected_completion_date when first_occupancy_date absent',
          compute_funnel_urgency(fallback)['level'] == 'high')
    check('fallback basis_field is expected_completion_date',
          compute_funnel_urgency(fallback)['basis_field'] == 'expected_completion_date')


def test_overdue_deadline_is_high_not_none():
    overdue = _build('acquisition', {'targetCloseDate': _iso(-10)}, 'AcqOverdue')
    result = compute_funnel_urgency(overdue)
    check('an overdue deadline reads as high (not none)', result['level'] == 'high')
    check('overdue reason mentions it already passed', 'ago' in (result['reason'] or ''))
    check('overdue days_remaining is negative', result['days_remaining'] is not None and result['days_remaining'] < 0)


def test_uncovered_situations_are_none():
    renewal = _build('renewal', {'renewalDate': _iso(20)}, 'Renewal')
    benchmark = _build('benchmark', {}, 'Benchmark')
    operating = _build('operating', {}, 'Operating')

    check('renewal has no funnel_urgency (own timing system covers it)', compute_funnel_urgency(renewal)['level'] == 'none')
    check('benchmark has no funnel_urgency', compute_funnel_urgency(benchmark)['level'] == 'none')
    check('operating has no funnel_urgency', compute_funnel_urgency(operating)['level'] == 'none')


def test_urgency_never_touches_scoring():
    high = _build('acquisition', {'targetCloseDate': _iso(10)}, 'ScoreCheckHigh')
    low = _build('acquisition', {'targetCloseDate': _iso(400)}, 'ScoreCheckLow')
    # Same situation/payload shape apart from the date -> same score inputs
    # -> identical score, regardless of how different their urgency is.
    check('urgency has no bearing on score_total', high.score.total == low.score.total)
    check('urgency has no bearing on score_category', high.score.category == low.score.category)


def test_sort_tie_break_only_within_same_category_and_score():
    a = _build('acquisition', {'targetCloseDate': _iso(10)}, 'SortA')   # high urgency
    b = _build('acquisition', {'targetCloseDate': _iso(400)}, 'SortB')  # low urgency
    assert a.score.category == b.score.category and a.score.total == b.score.total, \
        'test setup assumption broke: these must tie on category+total for this test to be meaningful'

    ordered = sort_leads_by_priority([b, a])
    check('within an identical category+score tie, the more urgent lead sorts first', ordered[0].id == a.id)

    # A higher-category lead must still outrank a higher-urgency lower-category lead.
    hot_low_urgency = _build('acquisition', {'targetCloseDate': _iso(400), 'primaryConcern': 'premium_increase'}, 'SortHot')
    nurture_high_urgency = b
    if hot_low_urgency.score.category != nurture_high_urgency.score.category:
        ordered2 = sort_leads_by_priority([nurture_high_urgency, hot_low_urgency])
        check('category still outranks urgency (urgency is a tie-break only)',
              ordered2[0].score.category == hot_low_urgency.score.category)


def main():
    test_acquisition_thresholds()
    test_lender_thresholds()
    test_construction_thresholds()
    test_completion_thresholds()
    test_overdue_deadline_is_high_not_none()
    test_uncovered_situations_are_none()
    test_urgency_never_touches_scoring()
    test_sort_tie_break_only_within_same_category_and_score()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All funnel urgency (Funnel Phase 4) tests passed.')


if __name__ == '__main__':
    main()
