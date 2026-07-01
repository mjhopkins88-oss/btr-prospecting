#!/usr/bin/env python
"""
Source ROI + calibration-dataset tests (outcome/snapshot/notification
phase).

Confirms get_source_roi() counts meetings/submissions/quotes/wins/losses
correctly, sums estimated revenue + bound premium without double-
counting, excludes rejected/spam leads from every metric except the
spam-rate denominator, flags duplicate/merged leads via signal_count>1,
reports the same numbers across every one of the 10 dimensions (source,
source_page, offer_type, utm_source, utm_campaign, first_touch_source,
conversion_source, latest_signal_source, page_variant, campaign_id),
and that
get_calibration_dataset() produces well-formed, purely descriptive
(no-ML) groupings. Also confirms demo leads never appear. Each test uses
a unique utm_campaign to isolate its own ROI bucket regardless of other
test data. Inserts marker-tagged leads and cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake import build_lead_from_intake
from multifamily.snapshots import snapshot_lead
from multifamily import matching
from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead

_FAILURES = []
_M = '(ROI TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make(company, campaign, **over):
    payload = {
        'name': 'Roi Tester', 'company': f'{company} {_M}', 'email': f'{company.lower()}@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'benchmark', 'source': 'benchmark_form',
        'utmCampaign': campaign,
    }
    payload.update(over)
    lead, errors = build_lead_from_intake(payload, spam_status=over.get('_spam_status', 'clean'),
                                          spam_reason_codes=over.get('_spam_codes', []))
    assert not errors, errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    snapshot_lead(lead, 'created')
    _ids.append(lead.id)
    return lead


def mk_incoming(company, email, campaign):
    """In-memory lead for exercising the merge engine directly (mirrors
    other _TEST.py files' mk_lead helper)."""
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=f'{company} {_M} Property', state='TX', city='Austin',
                            asset_type='garden', unit_count=120)
    contacts = [MultifamilyContact(id=new_id(), full_name='A Person', email=email)]
    s = MultifamilySignal(id=new_id(), signal_type='renewal_date_known', source='crm')
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=contacts, state='TX', city='Austin',
        primary_signal_type='renewal_date_known', primary_source='crm', is_demo=False,
        utm_campaign=campaign,
    )
    lead.score = score_lead(lead)
    return lead


def test_all_ten_dimensions_present():
    campaign = 'roitest-dims-' + os.urandom(3).hex()
    _make('Dimsflow Partners', campaign, offerType='multifamily_benchmark_review', pageVariant='benchmark')
    roi = repository.get_source_roi()
    expected = {
        'source', 'source_page', 'offer_type', 'utm_source', 'utm_campaign',
        'first_touch_source', 'conversion_source', 'latest_signal_source',
        'page_variant', 'campaign_id',
    }
    check('report has all 10 dimensions', set(roi.keys()) == expected)
    check('utm_campaign bucket exists for this test lead', campaign in roi['utm_campaign'])
    check('source bucket includes benchmark_form', 'benchmark_form' in roi['source'])
    check('page_variant bucket includes benchmark', 'benchmark' in roi['page_variant'])


def test_meetings_submissions_quotes_wins_losses_counted():
    campaign = 'roitest-funnel-' + os.urandom(3).hex()
    a = _make('Funnelflow Alpha', campaign)
    b = _make('Funnelflow Beta', campaign)
    c = _make('Funnelflow Gamma', campaign)
    repository.record_outcome(a.id, 'meeting_booked')
    repository.record_outcome(a.id, 'submission_received')
    repository.record_outcome(a.id, 'quote_started')
    repository.record_outcome(a.id, 'quote_sent')
    repository.record_outcome(a.id, 'won')
    repository.record_outcome(b.id, 'meeting_booked')
    repository.record_outcome(b.id, 'lost')
    # c gets no outcome at all.

    bucket = repository.get_source_roi()['utm_campaign'][campaign]
    check('leads_created counts all three', bucket['leads_created'] == 3)
    check('meetings_booked counts both a and b', bucket['meetings_booked'] == 2)
    check('submissions_received counts a only', bucket['submissions_received'] == 1)
    check('quotes_started counts a only', bucket['quotes_started'] == 1)
    check('quotes_sent counts a only', bucket['quotes_sent'] == 1)
    check('wins counts a only', bucket['wins'] == 1)
    check('losses counts b only', bucket['losses'] == 1)


def test_revenue_and_bound_premium_no_double_counting():
    campaign = 'roitest-revenue-' + os.urandom(3).hex()
    lead = _make('Revenueflow Holdings', campaign)
    # Multiple events over time; estimated_revenue is set twice (an early
    # guess, then a refined higher figure) -> take the MAX, not the sum.
    repository.record_outcome(lead.id, 'quote_started', estimated_revenue=4000.0)
    repository.record_outcome(lead.id, 'quote_sent', estimated_revenue=5000.0)
    repository.record_outcome(lead.id, 'won', bound_premium=42000.0)

    bucket = repository.get_source_roi()['utm_campaign'][campaign]
    check('estimated_revenue takes the max across the history, not the sum', bucket['estimated_revenue'] == 5000.0)
    check('bound_premium recorded correctly', bucket['bound_premium'] == 42000.0)


def test_rejected_leads_excluded_from_roi_but_counted_for_spam_rate():
    campaign = 'roitest-spam-' + os.urandom(3).hex()
    clean = _make('Spamroi Clean', campaign)
    rejected = _make('Spamroi Rejected', campaign, _spam_status='rejected', _spam_codes=['HONEYPOT_FILLED'])
    check('rejected test lead really is rejected (setup sanity)',
          repository.get_lead_row(rejected.id)['spam_status'] == 'rejected')

    bucket = repository.get_source_roi()['utm_campaign'][campaign]
    check('leads_created excludes the rejected lead', bucket['leads_created'] == 1)
    check('spam_rate_pct reflects 1-of-2 rejected', bucket['spam_rate_pct'] == 50.0)


def test_duplicate_merge_rate_via_signal_count():
    campaign = 'roitest-dup-' + os.urandom(3).hex()
    survivor = _make('Duproi Capital', campaign, email='ops@duproi.com')
    incoming = mk_incoming('Duproi Capital', 'ops@duproi.com', campaign)
    result = matching.classify(incoming, repository.get_real_leads())
    check('classify finds the auto survivor', result['auto'] is not None)
    matching.merge_incoming_on_intake(result['auto'].lead, incoming)
    snapshot_lead(result['auto'].lead, 'signal_added')
    solo = _make('Duproi Solo', campaign)

    bucket = repository.get_source_roi()['utm_campaign'][campaign]
    check('leads_created counts survivor + solo (incoming never got its own row)', bucket['leads_created'] == 2)
    check('duplicate_or_merge_rate_pct reflects 1-of-2 leads absorbing a merge', bucket['duplicate_or_merge_rate_pct'] == 50.0)


def test_avg_score_and_timing_confidence_at_creation():
    campaign = 'roitest-avg-' + os.urandom(3).hex()
    lead = _make('Avgflow Group', campaign)
    bucket = repository.get_source_roi()['utm_campaign'][campaign]
    creation = repository.get_creation_snapshot(lead.id)
    check('avg_score_at_creation matches the single lead\'s creation snapshot', bucket['avg_score_at_creation'] == creation['score_total'])
    check('avg_timing_confidence is a 0-1 float', bucket['avg_timing_confidence'] is not None and 0.0 <= bucket['avg_timing_confidence'] <= 1.0)


def test_first_touch_conversion_latest_signal_dimensions():
    campaign = 'roitest-touch-' + os.urandom(3).hex()
    lead = _make('Touchflow Realty', campaign)
    roi = repository.get_source_roi()
    check('first_touch_source dimension has a benchmark_form bucket', 'benchmark_form' in roi['first_touch_source'])
    check('conversion_source dimension has a benchmark_form bucket', 'benchmark_form' in roi['conversion_source'])
    check('latest_signal_source dimension has a benchmark_form bucket', 'benchmark_form' in roi['latest_signal_source'])


def test_demo_leads_never_appear_in_roi():
    from multifamily.pipeline import run_pipeline
    leads, _ = run_pipeline()
    check('demo pipeline produced leads to check', len(leads) > 0)
    roi = repository.get_source_roi()
    total_real_leads_created = sum(b['leads_created'] for b in roi['source'].values())
    # leads_created excludes rejected leads (they only count toward
    # spam_rate_pct's denominator) -> compare against the same
    # non-rejected, non-demo universe get_real_leads() already exposes.
    real_rows = repository.get_real_leads(include_rejected=False)
    check('ROI leads_created total matches persisted non-rejected real leads',
          total_real_leads_created == len(real_rows))


def test_calibration_dataset_shape():
    cal = repository.get_calibration_dataset()
    expected_keys = {
        'score_band_meeting_or_win_rate', 'timing_stage_reply_rate', 'process_stage_win_rate',
        'revenue_by_source', 'disqualifier_code_outcome_mix', 'sample_size',
    }
    check('calibration dataset has all expected top-level keys', expected_keys <= set(cal.keys()))
    check('sample_size is a non-negative int', isinstance(cal['sample_size'], int) and cal['sample_size'] >= 0)
    for band, stats in cal['score_band_meeting_or_win_rate'].items():
        check(f'score band {band} has leads/meetings_or_wins/rate_pct',
              {'leads', 'meetings_or_wins', 'rate_pct'} <= set(stats.keys()))
    for stage, stats in cal['timing_stage_reply_rate'].items():
        check(f'timing stage {stage} has leads/replies/rate_pct', {'leads', 'replies', 'rate_pct'} <= set(stats.keys()))
    check('revenue_by_source values are all numeric', all(isinstance(v, (int, float)) for v in cal['revenue_by_source'].values()))
    check('calibration dataset is purely descriptive (no model/prediction keys)',
          not any(k in cal for k in ('model', 'prediction', 'weights', 'trained')))


def main():
    try:
        test_all_ten_dimensions_present()
        test_meetings_submissions_quotes_wins_losses_counted()
        test_revenue_and_bound_premium_no_double_counting()
        test_rejected_leads_excluded_from_roi_but_counted_for_spam_rate()
        test_duplicate_merge_rate_via_signal_count()
        test_avg_score_and_timing_confidence_at_creation()
        test_first_touch_conversion_latest_signal_dimensions()
        test_demo_leads_never_appear_in_roi()
        test_calibration_dataset_shape()
    finally:
        for lid in _ids:
            repository.delete_notifications_for_lead(lid)
            repository.delete_snapshots_for_lead(lid)
            repository.delete_outcomes_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(ROI TEST)%'")
            conn.commit(); conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All source-ROI/calibration tests passed.')


if __name__ == '__main__':
    main()
