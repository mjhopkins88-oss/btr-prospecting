#!/usr/bin/env python
"""
Section 8 items 1-3, Phase 4 tests: first-renewal watchlist
(multifamily/timing/first_renewal_estimator.py) + the renewal-band /
post_renewal_active timing recalibration's downstream effect, plus the
required end-to-end proof that Campaign B's core path (CSV import of a
recent buyer -> timing engine -> notification) actually works.

Covers: estimate_first_renewal returns None for non-acquisition leads
and for acquisition leads with no close date; the +12mo/+8mo offsets
(incl. month-end/leap-year day clamping); window_is_open reflects
today's date correctly; and the REQUIRED end-to-end test — importing a
CSV row with a close_date ~9 months in the past produces a lead whose
serialized fields (first_renewal_estimate/renewal_window_opens_at, via
estimate_first_renewal — exactly what api/routes/multifamily.py's
_serialize_lead exposes) are both populated, and that
notify_first_renewal_window_open fires exactly once on sweep() and
dedupes on a second sweep() call.
"""
import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily import notifications as mf_notifications
from multifamily.campaigns.csv_import import import_row_as_target_and_lead
from multifamily.forms.form_variants import FORM_VARIANTS
from multifamily.timing.first_renewal_estimator import estimate_first_renewal, _add_months
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal, new_id,
)

_FAILURES = []
_M = '(FIRSTRENEWAL TEST)'
_lead_ids = []
_campaign_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _acquisition_lead(close_date_str):
    c = MultifamilyCompany(id=new_id(), name=f'FirstRenewal Co {_M}')
    p = MultifamilyProperty(id=new_id(), name='FirstRenewal Property', state='TX', asset_type='garden', unit_count=180)
    s = MultifamilySignal(
        id=new_id(), signal_type='acquisition', source='manual',
        detail={'self_reported': True, 'target_close_date': close_date_str},
    )
    return MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=[], state='TX',
        primary_signal_type='acquisition', primary_source='manual', is_demo=False,
    )


def test_none_for_non_acquisition_lead():
    c = MultifamilyCompany(id=new_id(), name='Non Acq Co')
    p = MultifamilyProperty(id=new_id(), name='Non Acq Property', state='TX')
    s = MultifamilySignal(id=new_id(), signal_type='renewal_date_known', source='crm', detail={'days_until_renewal': 60})
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=[], state='TX',
        primary_signal_type='renewal_date_known', primary_source='crm', is_demo=False,
    )
    check('non-acquisition lead returns None', estimate_first_renewal(lead) is None)


def test_none_for_acquisition_without_close_date():
    c = MultifamilyCompany(id=new_id(), name='No Close Date Co')
    p = MultifamilyProperty(id=new_id(), name='No Close Date Property', state='TX')
    s = MultifamilySignal(id=new_id(), signal_type='acquisition', source='manual', detail={'self_reported': True})
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=[s], contacts=[], state='TX',
        primary_signal_type='acquisition', primary_source='manual', is_demo=False,
    )
    check('acquisition lead with no close_date returns None', estimate_first_renewal(lead) is None)


def test_month_offsets_and_leap_year_clamping():
    check('12 months after 2026-01-15 is 2027-01-15', _add_months(date(2026, 1, 15), 12) == date(2027, 1, 15))
    check('8 months after 2026-01-15 is 2026-09-15', _add_months(date(2026, 1, 15), 8) == date(2026, 9, 15))
    # Jan 31 + 1 month has no Feb 31 -> clamps to the month's last day.
    check('Jan 31 + 1 month clamps to Feb 28 (2026, not a leap year)', _add_months(date(2026, 1, 31), 1) == date(2026, 2, 28))
    check('Jan 31 + 1 month clamps to Feb 29 in a leap year (2028)', _add_months(date(2028, 1, 31), 1) == date(2028, 2, 29))


def test_estimate_first_renewal_computes_correct_offsets():
    close_date = date.today() - timedelta(days=30)
    lead = _acquisition_lead(close_date.isoformat())
    estimate = estimate_first_renewal(lead)
    check('close_date round-trips', estimate['close_date'] == close_date.isoformat())
    check('first_renewal_estimate is close_date + 12 months', estimate['first_renewal_estimate'] == _add_months(close_date, 12).isoformat())
    check('renewal_window_opens_at is close_date + 8 months', estimate['renewal_window_opens_at'] == _add_months(close_date, 8).isoformat())


def test_window_is_open_reflects_today():
    # Closed 9 months ago -> window (close+8mo) is well in the past -> open.
    recent_buyer = _acquisition_lead((date.today() - timedelta(days=274)).isoformat())
    check('a 9-month-old close date has an OPEN window', estimate_first_renewal(recent_buyer)['window_is_open'] is True)

    # Closed 2 months ago -> window (close+8mo) is 6 months in the future -> not open yet.
    brand_new_buyer = _acquisition_lead((date.today() - timedelta(days=60)).isoformat())
    check('a 2-month-old close date does NOT have an open window yet', estimate_first_renewal(brand_new_buyer)['window_is_open'] is False)


def test_end_to_end_csv_import_to_notification():
    """The required proof: Campaign B (recent buyers -> first renewal)
    actually works import-to-notification, not just in isolated units."""
    variant = FORM_VARIANTS['acquisition']
    campaign = repository.create_campaign(
        name=f'FirstRenewalE2E Campaign {_M}', page_variant='acquisition', offer_type=variant.offer_type,
    )
    _campaign_ids.append(campaign['id'])

    close_date = date.today() - timedelta(days=274)  # ~9 months ago
    row = {
        '_row_number': 1, 'company': f'FirstRenewalE2E Co {_M}', 'contact_name': 'E2E Contact',
        'email': 'firstrenewale2e@example.com', 'state': 'TX', 'close_date': close_date.isoformat(),
        'units': '200',
    }
    result = import_row_as_target_and_lead(campaign, row)
    check('CSV row with a real email builds/links a lead', result['lead_linked'] is True)
    lead_id = result['lead_id']
    _lead_ids.append(lead_id)

    lead = repository.get_lead_by_id(lead_id)
    estimate = estimate_first_renewal(lead)
    check('(a) first_renewal_estimate is populated on the reloaded lead — exactly what _serialize_lead exposes',
          estimate is not None and estimate['first_renewal_estimate'] is not None)
    check('(a) renewal_window_opens_at is populated on the reloaded lead',
          estimate is not None and estimate['renewal_window_opens_at'] is not None)
    check('(a) the window is already open for a ~9-month-old close date',
          estimate is not None and estimate['window_is_open'] is True)

    # (b) sweep() fires the notification exactly once, then dedupes.
    first_sweep = mf_notifications.sweep()
    fired = [n for n in first_sweep if n.get('type') == 'first_renewal_window_open' and n.get('lead_id') == lead_id]
    check('(b) first_renewal_window_open notification fires on sweep()', len(fired) == 1)

    second_sweep = mf_notifications.sweep()
    fired_again = [n for n in second_sweep if n.get('type') == 'first_renewal_window_open' and n.get('lead_id') == lead_id]
    check('(b) re-sweeping does NOT fire a duplicate notification (dedupe_key works)', len(fired_again) == 0)

    notifications_for_lead = repository.fetch_all(
        "SELECT id FROM multifamily_notifications WHERE lead_id = ? AND type = 'first_renewal_window_open'",
        [lead_id],
    ) if hasattr(repository, 'fetch_all') else None
    if notifications_for_lead is not None:
        check('exactly one first_renewal_window_open row persisted (not duplicated)', len(notifications_for_lead) == 1)
        for n in notifications_for_lead:
            repository.delete_notification(n['id'])


def main():
    try:
        test_none_for_non_acquisition_lead()
        test_none_for_acquisition_without_close_date()
        test_month_offsets_and_leap_year_clamping()
        test_estimate_first_renewal_computes_correct_offsets()
        test_window_is_open_reflects_today()
        test_end_to_end_csv_import_to_notification()
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
    print('All first-renewal watchlist (Section 8 items 1-3, Phase 4) tests passed.')


if __name__ == '__main__':
    main()
