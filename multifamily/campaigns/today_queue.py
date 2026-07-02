"""
Today Queue (Phase D) — a daily cadence view of which Pilot Campaign
target owes which Section 7 sequence touch today or is overdue, computed
purely from each target's `created_at` plus its touch-step timestamps
(multifamily_campaign_targets). No new tables/columns — pure computation
over the same rows list_campaign_targets() already returns, same
convention as multifamily/campaigns/tracked_link.py and csv_import.py
(this module DOES call into multifamily.repository for the list/lookup
functions, exactly like csv_import.py already does — it just adds no new
persistence of its own).

Distinct from get_campaign_performance()'s scorecard (delivery/reply/
positive/meetings) — that's an aggregate rollup; this is a per-target,
action-oriented worklist ("what do I do right now") plus a lightweight
per-campaign adherence stat.
"""
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional

from multifamily import repository

# The Section 7 sequence cadence (Day 0 email / Day 2 LinkedIn connect /
# Day 5 email 2 / Day 9 call / Day 16 breakup), expressed as an offset in
# days from the target's created_at. Order matters — it's the order the
# cadence runs in, and compute_queue_item() walks it in this order to
# find the first not-yet-done step. 'bounced' (CAMPAIGN_TARGET_TOUCH_STEPS'
# 6th value) is intentionally excluded here — it's a data-quality event,
# not a sequence step a target "owes" on a schedule.
SEQUENCE_DAY_OFFSETS = {
    'touch_1_sent': 0,
    'connected': 2,
    'touch_2_sent': 5,
    'called': 9,
    'breakup_sent': 16,
}

# Terminal statuses — a target here doesn't "owe" anything, regardless
# of how much of the sequence is unmarked (e.g. a target that converted
# on touch 1 never needs a Day-9 call chased down).
_TERMINAL_STATUSES = {'converted', 'not_fit'}

# How much slack a completed touch gets before it's counted as "late"
# rather than "on schedule" in compute_sequence_adherence(). The cadence
# is manually executed by an operator (not automated), so a step landing
# a day or two after its target day is still a reasonable real-world
# outcome, not a process failure — chosen as a sensible default, not
# derived from any hard requirement.
ADHERENCE_TOLERANCE_DAYS = 2


def _parse_date(value: Optional[str]) -> Optional[date]:
    """Parse a timestamp stored via multifamily.types.utc_now_iso()
    (datetime.utcnow().isoformat(), e.g. '2026-07-02T14:23:11.123456' —
    no 'Z'/offset) or a plain 'YYYY-MM-DD'/full ISO string passed by a
    caller backdating a touch. Returns None for missing/unparseable
    input rather than raising, since a target may not have a value yet."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None


def compute_queue_item(target: Dict[str, Any], today: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """Given one campaign target row (dict, list_campaign_targets()-shaped),
    return a Today Queue entry if it owes a touch today or is overdue,
    else None. `today` is injectable for tests; defaults to date.today()."""
    today = today or date.today()

    if target.get('bounced_at'):
        return None
    if target.get('status') in _TERMINAL_STATUSES:
        return None

    created = _parse_date(target.get('created_at'))
    if created is None:
        return None

    next_step = None
    offset_days = None
    for step, offset in SEQUENCE_DAY_OFFSETS.items():
        if not target.get(f'{step}_at'):
            next_step = step
            offset_days = offset
            break
    if next_step is None:
        return None  # every step is marked — sequence complete, nothing owed

    due_date = created + timedelta(days=offset_days)
    days_overdue = (today - due_date).days
    is_overdue = today > due_date
    is_due_today = today == due_date
    if not (is_overdue or is_due_today):
        return None  # due in the future — not part of TODAY's queue

    return {
        'id': target.get('id'),
        'campaign_id': target.get('campaign_id'),
        'company': target.get('company'),
        'contact_name': target.get('contact_name'),
        'email': target.get('email'),
        'phone': target.get('phone'),
        'linkedin_url': target.get('linkedin_url'),
        'lead_id': target.get('lead_id'),
        'status': target.get('status'),
        'next_step': next_step,
        'due_date': due_date.isoformat(),
        'days_overdue': days_overdue if days_overdue > 0 else 0,
        'is_overdue': is_overdue,
        'is_due_today': is_due_today,
    }


def get_today_queue(campaign_id: Optional[str] = None, today: Optional[date] = None) -> List[Dict[str, Any]]:
    """All targets (one campaign, or across every campaign when
    campaign_id is None) that owe a touch today or are overdue, each
    annotated with campaign_name, ordered by urgency (most overdue
    first, due-today items last — every returned item has
    days_overdue >= 0 by construction, so a plain descending sort on
    that single field already produces the right order)."""
    if campaign_id:
        campaigns = [repository.get_campaign(campaign_id)]
        campaigns = [c for c in campaigns if c]
    else:
        campaigns = repository.list_campaigns()

    items: List[Dict[str, Any]] = []
    for campaign in campaigns:
        targets = repository.list_campaign_targets(campaign['id'])
        for target in targets:
            item = compute_queue_item(target, today=today)
            if item is None:
                continue
            item['campaign_name'] = campaign.get('name')
            items.append(item)

    items.sort(key=lambda it: it['days_overdue'], reverse=True)
    return items


def compute_sequence_adherence(campaign_id: str) -> Dict[str, Any]:
    """For one campaign, of the sequence steps actually completed so far
    (any of SEQUENCE_DAY_OFFSETS' *_at columns set), how many landed
    within ADHERENCE_TOLERANCE_DAYS of their expected day offset from
    the target's created_at. Returns 0%/0 counts (never a ZeroDivisionError)
    when nothing has been touched yet."""
    targets = repository.list_campaign_targets(campaign_id)
    completed_count = 0
    on_schedule_count = 0
    for target in targets:
        created = _parse_date(target.get('created_at'))
        if created is None:
            continue
        for step, offset in SEQUENCE_DAY_OFFSETS.items():
            occurred = _parse_date(target.get(f'{step}_at'))
            if occurred is None:
                continue
            completed_count += 1
            actual_offset = (occurred - created).days
            if actual_offset <= offset + ADHERENCE_TOLERANCE_DAYS:
                on_schedule_count += 1

    adherence_pct = round(100.0 * on_schedule_count / completed_count, 1) if completed_count else 0.0
    return {
        'completed_count': completed_count,
        'on_schedule_count': on_schedule_count,
        'adherence_pct': adherence_pct,
    }
