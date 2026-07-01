#!/usr/bin/env python
"""
Funnel Phase 2 tests: parameterized public offer pages (/mf-review/<slug>).

Covers, for every non-benchmark variant: a payload shaped like what the
new page actually posts (leadSituation fixed to the variant's
lead_situation, offerType/pageVariant/campaignId set, plus the variant's
own conditional fields) builds a lead with the correct signal detail,
resolves the correct NEPQ scenario + rule_applied via the real pipeline
(detect_process_stage -> build_lead_context -> select_strategy), and
persists/reloads cleanly. Also covers the completion-leaseup routing fix
(Bug 1/2: 'completion' is its own lead_situation/signal_type, not reused
from 'construction') and confirms the existing benchmark path is
untouched.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.forms.form_variants import FORM_VARIANTS
from multifamily.intake import build_lead_from_intake
from multifamily.timing.process_stage_detector import detect_process_stage
from multifamily.sales_intelligence.lead_context_builder import build_lead_context
from multifamily.sales_intelligence.conversation_strategy_engine import select_strategy

_FAILURES = []
_M = '(FUNNELOFFERPAGE TEST)'
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _run_variant(slug, extra_payload, expected_scenario, expected_rule):
    variant = FORM_VARIANTS[slug]
    payload = {
        'name': f'{slug} Tester', 'company': f'{slug} Offerflow Co {_M}',
        'email': f'{slug.replace("-", "")}@example.com',
        'state': 'TX', 'city': 'Austin',
        'leadSituation': variant.lead_situation,
        'source': 'benchmark_form',
        'sourcePage': variant.headline,
        'offerType': variant.offer_type,
        'pageVariant': variant.slug,
        'campaignId': f'{slug}-campaign',
    }
    payload.update(extra_payload)

    lead, errors = build_lead_from_intake(payload)
    check(f'{slug}: lead built with no errors', errors == [] and lead is not None)
    check(f'{slug}: offer_type persists', lead.offer_type == variant.offer_type)
    check(f'{slug}: page_variant persists', lead.page_variant == variant.slug)
    check(f'{slug}: campaign_id persists', lead.campaign_id == f'{slug}-campaign')

    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    _lead_ids.append(lead.id)

    reloaded = repository.get_lead_by_id(lead.id)
    check(f'{slug}: reloads from DB with page_variant intact', reloaded.page_variant == variant.slug)

    stage_result = detect_process_stage(reloaded)
    ctx = build_lead_context(reloaded, stage_result)
    check(f'{slug}: resolves expected scenario ({expected_scenario})', ctx.insurance_scenario == expected_scenario)

    strategy = select_strategy(ctx)
    check(f'{slug}: resolves expected rule ({expected_rule})', strategy.rule_applied == expected_rule)

    return lead, ctx, strategy


def test_renewal_pressure_variant():
    # No primaryConcern here on purpose: setting one (e.g. premium_increase)
    # sets a pain_flag, and _infer_scenario checks pain_flags before the
    # self-reported situation — that's an intentional, pre-existing
    # priority (an explicit pain point outranks a generic situation), not
    # something this variant's routing changes.
    _run_variant(
        'renewal-pressure',
        {'renewalDate': '2026-08-01', 'currentPremiumRange': '250k_500k'},
        expected_scenario='renewal_pressure',
        expected_rule='rule_3_renewal_within_120',
    )


def test_acquisition_variant():
    _run_variant(
        'acquisition',
        {'targetCloseDate': '2026-08-15', 'propertyName': f'Test Acquisition Property {_M}', 'relyingOnSellerNumbers': 'no'},
        expected_scenario='acquisition_due_diligence',
        expected_rule='rule_4_acquisition_diligence',
    )


def test_lender_requirement_variant():
    _run_variant(
        'lender-requirement',
        {'lenderDeadline': '2026-07-20', 'issueType': 'deductible'},
        expected_scenario='refinance_or_financing',
        expected_rule='rule_5_refinance_lender',
    )


def test_builders_risk_variant():
    _run_variant(
        'builders-risk',
        {'projectStartDate': '2026-07-10', 'hardCosts': '$12,000,000', 'softCosts': '$2,000,000',
         'controlType': 'owner_controlled', 'constructionStage': 'groundbreaking'},
        expected_scenario='builders_risk',
        expected_rule='rule_6_construction_builders_risk',
    )


def test_completion_leaseup_variant():
    # This is the exact routing fix (Bug 1 + Bug 2): completion-leaseup
    # must resolve as its own 'completion' situation/signal, not fall
    # through to construction (Rule 6) or direct-inbound (Rule 1/11).
    lead, ctx, strategy = _run_variant(
        'completion-leaseup',
        {'expectedCompletionDate': '2026-08-01', 'firstOccupancyDate': '2026-09-01',
         'phasing': 'phased', 'operatingCoveragePlaced': 'no'},
        expected_scenario='completion_or_lease_up',
        expected_rule='rule_7_completion_lease_up',
    )
    completion_signal = next((s for s in lead.signals if s.signal_type == 'completion'), None)
    check('completion-leaseup: emits a distinct "completion" signal (not construction)', completion_signal is not None)
    check('completion-leaseup: signal detail carries expected_completion_date',
          completion_signal and completion_signal.detail.get('expected_completion_date') == '2026-08-01')
    check('completion-leaseup: signal detail carries first_occupancy_date',
          completion_signal and completion_signal.detail.get('first_occupancy_date') == '2026-09-01')
    construction_signal = next((s for s in lead.signals if s.signal_type in ('groundbreaking', 'vertical_construction')), None)
    check('completion-leaseup: does NOT also emit a construction signal', construction_signal is None)


def test_benchmark_variant_still_resolves_just_benchmarking():
    # Confirms the parameterized page's benchmark path is unaffected —
    # same shape as today's live form (leadSituation='benchmark', no
    # offer-specific conditional fields required).
    _run_variant(
        'benchmark',
        {},
        expected_scenario='just_benchmarking',
        expected_rule='rule_1_11_direct_inbound',
    )


def main():
    try:
        test_renewal_pressure_variant()
        test_acquisition_variant()
        test_lender_requirement_variant()
        test_builders_risk_variant()
        test_completion_leaseup_variant()
        test_benchmark_variant_still_resolves_just_benchmarking()
    finally:
        for lid in _lead_ids:
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} tracked lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All funnel offer-page (Funnel Phase 2) tests passed.')


if __name__ == '__main__':
    main()
