"""
In-app notification infrastructure (outcome/snapshot/notification phase).

Two kinds of notifications:
  - Event-driven: emitted at the moment something happens (a new Call
    Today lead, a benchmark submission, a merge, a fuzzy match needing
    review, a meeting booked, a reply, a spam spike). Callers invoke the
    notify_* helpers at the point of the event (api/routes/multifamily.py).
  - Time-derived: this app has no background scheduler, so "follow-up
    due/overdue" and "hot lead went stale" can't fire on their own clock.
    sweep() computes them on demand — called every time GET /notifications
    is hit — and is safe to call repeatedly because every notification is
    deduped via `dedupe_key` (a UNIQUE column; see repository.
    insert_notification).

Nothing here ever sends anything external (no email/SMS) — purely an
in-app queue. Real leads only; demo leads never generate notifications
(their ids regenerate every pipeline run, so a notification on one would
be orphaned before anyone could read it back).
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from multifamily import repository

SEVERITIES = ['info', 'warning', 'critical']

NOTIFICATION_TYPES = [
    'new_call_today_lead', 'new_benchmark_submission', 'hot_lead_stale',
    'followup_due_today', 'followup_overdue', 'lead_replied', 'meeting_booked',
    'high_confidence_merge', 'fuzzy_match_review', 'spam_spike',
]

# A Hot/Call-Today lead with no logged activity (and no more recent
# merge/signal touch) in this many days is considered "stale".
STALE_DAYS = 3

# Rejected/rate-limited submissions within this window that reach the
# threshold below trigger one spam-spike alert per hour (see
# notify_spam_spike's dedupe_key).
SPAM_SPIKE_WINDOW_MINUTES = 15
SPAM_SPIKE_THRESHOLD = 5


def emit(
    type_: str, *, title: str, message: str, lead_id: Optional[str] = None,
    severity: str = 'info', action_url: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None, dedupe_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Insert one notification, deduped via `dedupe_key` (defaults to
    f'{type_}:{lead_id}'). Returns the inserted row, or None if a
    notification with this dedupe_key already exists — callers should
    treat None as "already notified, nothing new to do"."""
    if severity not in SEVERITIES:
        severity = 'info'
    key = dedupe_key or f'{type_}:{lead_id or "none"}'
    return repository.insert_notification(
        type_, title=title, message=message, lead_id=lead_id, severity=severity,
        action_url=action_url, metadata=metadata, dedupe_key=key,
    )


# ---- Event-driven notifiers -------------------------------------------

def notify_new_call_today_lead(lead_id: str, company_name: str) -> Optional[Dict[str, Any]]:
    return emit(
        'new_call_today_lead', lead_id=lead_id, severity='critical',
        title='New Call Today lead', message=f'{company_name} just became a Call Today lead.',
        action_url=f'/multifamily?lead={lead_id}', metadata={'company': company_name},
    )


def notify_new_benchmark_submission(lead_id: str, company_name: str, signal_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return emit(
        'new_benchmark_submission', lead_id=lead_id, severity='info',
        title='New benchmark form submission', message=f'{company_name} submitted the public benchmark form.',
        action_url=f'/multifamily?lead={lead_id}', metadata={'company': company_name},
        dedupe_key=f'new_benchmark_submission:{signal_id or lead_id}',
    )


def notify_high_confidence_merge(lead_id: str, company_name: str, signal_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return emit(
        'high_confidence_merge', lead_id=lead_id, severity='info',
        title='Leads auto-merged', message=f'A new signal for {company_name} auto-merged into the existing lead.',
        action_url=f'/multifamily?lead={lead_id}', metadata={'company': company_name},
        dedupe_key=f'high_confidence_merge:{signal_id or lead_id}',
    )


def notify_fuzzy_match_review(
    candidate_id: str, incoming_company: str, existing_company: str, existing_lead_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """`existing_lead_id` is the persisted candidate lead (the incoming
    lead may not be its own row) — attached so the notification links
    to/cleans up with a real lead, same as every other notifier."""
    return emit(
        'fuzzy_match_review', lead_id=existing_lead_id, severity='warning',
        title='Possible duplicate needs review',
        message=f'"{incoming_company}" may be a duplicate of "{existing_company}".',
        action_url='/multifamily?tab=admin', metadata={'candidate_id': candidate_id},
        dedupe_key=f'fuzzy_match_review:{candidate_id}',
    )


def notify_meeting_booked(lead_id: str, company_name: str, event_id: str) -> Optional[Dict[str, Any]]:
    return emit(
        'meeting_booked', lead_id=lead_id, severity='info',
        title='Meeting booked', message=f'A meeting was booked with {company_name}.',
        action_url=f'/multifamily?lead={lead_id}', metadata={'company': company_name},
        dedupe_key=f'meeting_booked:{event_id}',
    )


def notify_lead_replied(lead_id: str, company_name: str, activity_id: str) -> Optional[Dict[str, Any]]:
    return emit(
        'lead_replied', lead_id=lead_id, severity='info',
        title='Lead replied', message=f'{company_name} replied.',
        action_url=f'/multifamily?lead={lead_id}', metadata={'company': company_name},
        dedupe_key=f'lead_replied:{activity_id}',
    )


def notify_spam_spike(count: int, window_minutes: int = SPAM_SPIKE_WINDOW_MINUTES) -> Optional[Dict[str, Any]]:
    return emit(
        'spam_spike', severity='critical', title='Spam/rate-limit spike detected',
        message=f'{count} rejected or rate-limited submissions in the last {window_minutes} minutes.',
        action_url='/multifamily?tab=admin', metadata={'count': count, 'window_minutes': window_minutes},
        # One alert per hour, even if the spike continues.
        dedupe_key=f'spam_spike:{datetime.utcnow().strftime("%Y-%m-%dT%H")}',
    )


def check_spam_spike() -> Optional[Dict[str, Any]]:
    """Call after recording a rejected/rate-limited intake event. Counts
    system-wide rejected+rate-limited events in the trailing window and
    fires notify_spam_spike() if the threshold is met."""
    since = (datetime.utcnow() - timedelta(minutes=SPAM_SPIKE_WINDOW_MINUTES)).isoformat()
    count = repository.count_recent_events_global(
        ['rejected_honeypot', 'rejected_garbage', 'rate_limited_ip', 'rate_limited_email'], since,
    )
    if count >= SPAM_SPIKE_THRESHOLD:
        return notify_spam_spike(count)
    return None


# ---- Time-derived sweep -------------------------------------------------

def sweep() -> List[Dict[str, Any]]:
    """Compute time-derived notifications on demand (no background
    scheduler exists in this app — this runs whenever GET /notifications
    is hit). Idempotent: every notification is deduped via `dedupe_key`,
    so repeated sweeps never create duplicates. Returns the notifications
    newly created by this call (empty list on a re-sweep with nothing new)."""
    created: List[Dict[str, Any]] = []
    today_iso = datetime.utcnow().date().isoformat()

    for row in repository.get_followups_due(today_iso):
        due = row.get('next_follow_up_date')
        if not due:
            continue
        activity_id = row['id']
        lead_id = row.get('lead_id')
        company = row.get('company_name') or 'A lead'
        if due < today_iso:
            n = emit(
                'followup_overdue', lead_id=lead_id, severity='warning',
                title='Follow-up overdue', message=f'{company}: follow-up was due {due} and is now overdue.',
                action_url=f'/multifamily?lead={lead_id}', metadata={'activity_id': activity_id, 'due_date': due},
                dedupe_key=f'followup_overdue:{activity_id}',
            )
        else:
            n = emit(
                'followup_due_today', lead_id=lead_id, severity='warning',
                title='Follow-up due today', message=f'{company}: follow-up is due today.',
                action_url=f'/multifamily?lead={lead_id}', metadata={'activity_id': activity_id, 'due_date': due},
                dedupe_key=f'followup_due_today:{activity_id}',
            )
        if n:
            created.append(n)

    # Hot/Call-Today leads with no recent engagement (manual activity, or
    # failing that, last_verified_at as a proxy for "last touched").
    last_activity = repository.last_activity_at_by_lead()
    cutoff = (datetime.utcnow() - timedelta(days=STALE_DAYS)).isoformat()
    for lead in repository.get_real_leads():
        if not lead.score or lead.score.category not in ('hot', 'call_today'):
            continue
        last_at = last_activity.get(lead.id) or lead.last_verified_at
        if last_at and last_at >= cutoff:
            continue
        n = emit(
            'hot_lead_stale', lead_id=lead.id, severity='warning',
            title='Hot lead went stale',
            message=f'{lead.company.name} is {lead.score.category.replace("_", " ")} but has had no activity in {STALE_DAYS}+ days.',
            action_url=f'/multifamily?lead={lead.id}',
            metadata={'category': lead.score.category, 'last_activity_at': last_at},
        )
        if n:
            created.append(n)

    return created
