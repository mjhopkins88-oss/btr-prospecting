"""
First-renewal watchlist estimator (Strategy Research §3/§8) — insurance
binds AT closing, so by the time an acquisition close date is known, the
insurance decision has already happened. Rather than treating an
acquisition-origin lead as near-term hot forever, this derives a FUTURE
renewal window from the close date: `first_renewal_estimate` =
close_date + 12 months; `renewal_window_opens_at` = close_date + 8
months (90-120 days before the estimated renewal) — the point at which
outreach should actually start.

Pure, read-only, never persisted — computed fresh from whatever
target_close_date the lead's acquisition signal already carries
(captured at intake by both the public offer-page flow and Pilot
Campaign CSV import), same convention as multifamily/funnel/urgency.py.
Returns None for any lead that isn't acquisition-origin or has no known
close date.
"""
from datetime import date, datetime
from typing import Any, Dict, Optional

from multifamily.types import MultifamilyLead

_FIRST_RENEWAL_MONTHS = 12
_RENEWAL_WINDOW_OPENS_MONTHS = 8

_DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _add_months(d: date, months: int) -> date:
    month_index = d.month - 1 + months
    year = d.year + month_index // 12
    month = month_index % 12 + 1
    max_day = _DAYS_IN_MONTH[month - 1]
    if month == 2 and _is_leap_year(year):
        max_day = 29
    return date(year, month, min(d.day, max_day))


def _acquisition_close_date(lead: MultifamilyLead) -> Optional[date]:
    for signal in lead.signals or []:
        if signal.signal_type == 'acquisition':
            raw = (signal.detail or {}).get('target_close_date')
            if raw:
                try:
                    return datetime.strptime(str(raw)[:10], '%Y-%m-%d').date()
                except (ValueError, TypeError):
                    return None
    return None


def estimate_first_renewal(lead: MultifamilyLead) -> Optional[Dict[str, Any]]:
    """Returns {'close_date', 'first_renewal_estimate',
    'renewal_window_opens_at', 'window_is_open'} for an acquisition-
    origin lead with a known target_close_date, else None."""
    close_date = _acquisition_close_date(lead)
    if close_date is None:
        return None
    first_renewal_estimate = _add_months(close_date, _FIRST_RENEWAL_MONTHS)
    renewal_window_opens_at = _add_months(close_date, _RENEWAL_WINDOW_OPENS_MONTHS)
    return {
        'close_date': close_date.isoformat(),
        'first_renewal_estimate': first_renewal_estimate.isoformat(),
        'renewal_window_opens_at': renewal_window_opens_at.isoformat(),
        'window_is_open': date.today() >= renewal_window_opens_at,
    }
