"""
Funnel urgency (Funnel Phase 4) — a DERIVED, read-only signal for the
Outreach Workbench / Overview: how time-sensitive is THIS lead's own
reported deadline (acquisition close, lender deadline, construction
start, completion occupancy)? Computed fresh from whatever date field
the lead's primary signal already carries — never persisted, and never
read by scoring. This is purely a "how soon should I act" hint layered
on top of the (unchanged) score_total/category, matching the existing
NEPQ/timing convention that signal `detail` is scoring-inert.

Renewal is intentionally NOT covered here — a renewal_date already
drives the existing timing engine's 'renewal_window'/'post_renewal'
process_stage (multifamily/timing/process_stage_detector.py), so a
second urgency signal for the same date would just be redundant.
"""
from datetime import date, datetime
from typing import Any, Dict, Optional, Tuple

from multifamily.types import MultifamilyLead

URGENCY_LEVELS = ['high', 'medium', 'low', 'none']

_NONE_RESULT = {'level': 'none', 'reason': None, 'days_remaining': None, 'basis_field': None}

# (lead_situation, detail_key, high_threshold_days, medium_threshold_days, label)
# Thresholds match the funnel strategy's routing rules: acquisition close
# <=60d, lender deadline <=30d, builders-risk start <=60d, completion
# occupancy <=90d = high urgency. Medium is a softer secondary band so
# urgency degrades gracefully rather than falling straight to 'low'.
_URGENCY_RULES = [
    ('acquisition', 'target_close_date', 60, 120, 'target close date'),
    ('refinance', 'lender_deadline', 30, 60, 'lender deadline'),
    ('construction', 'project_start_date', 60, 120, 'project start date'),
    ('completion', 'first_occupancy_date', 90, 180, 'first occupancy date'),
]


def _days_until(date_str: Optional[str]) -> Optional[int]:
    if not date_str:
        return None
    try:
        target = datetime.strptime(str(date_str)[:10], '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None
    return (target - date.today()).days


def _situation_of(lead: MultifamilyLead) -> str:
    for signal in lead.signals or []:
        if signal.detail and signal.detail.get('lead_situation'):
            return signal.detail['lead_situation']
    return ''


def _find_detail_value(lead: MultifamilyLead, keys) -> Tuple[Optional[str], Any]:
    """The self-reported situation and its date fields ride on DIFFERENT
    signals (the primary benchmark_form_submit signal carries
    lead_situation; a secondary situation-specific signal — e.g.
    signal_type='acquisition' — carries target_close_date). So this
    searches every signal's detail for the first matching key rather
    than assuming one signal carries both."""
    for key in keys:
        for signal in lead.signals or []:
            if signal.detail and signal.detail.get(key) is not None:
                return key, signal.detail[key]
    return None, None


def compute_funnel_urgency(lead: MultifamilyLead) -> Dict[str, Any]:
    """Returns {'level', 'reason', 'days_remaining', 'basis_field'}.
    'level' is one of URGENCY_LEVELS; 'none' when the lead's situation
    has no matching deadline field (e.g. benchmark/operating, or a
    situation whose date field was never filled in)."""
    situation = _situation_of(lead)

    for rule_situation, date_key, high_days, medium_days, label in _URGENCY_RULES:
        if situation != rule_situation:
            continue
        keys = [date_key, 'expected_completion_date'] if rule_situation == 'completion' else [date_key]
        found_key, date_value = _find_detail_value(lead, keys)
        if found_key == 'expected_completion_date':
            label = 'expected completion date'
        days = _days_until(date_value)
        if days is None:
            return dict(_NONE_RESULT)
        if days < 0:
            return {
                'level': 'high',
                'reason': f'{label} was {abs(days)} day(s) ago',
                'days_remaining': days,
                'basis_field': found_key,
            }
        if days <= high_days:
            level = 'high'
        elif days <= medium_days:
            level = 'medium'
        else:
            level = 'low'
        return {
            'level': level,
            'reason': f'{days} day(s) until {label}',
            'days_remaining': days,
            'basis_field': found_key,
        }

    return dict(_NONE_RESULT)
