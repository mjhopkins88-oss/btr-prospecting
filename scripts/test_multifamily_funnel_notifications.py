#!/usr/bin/env python
"""
Funnel Phase 5 tests: per-offer notifications + SLA
(multifamily/notifications.py's notify_new_form_submission /
notify_outbound_conversion, wired into api/routes/multifamily.py's
create_lead — exercised here by replaying the same decision logic the
route uses, since this codebase's test scripts call modules directly
rather than through a Flask test client).

Covers: severity/SLA text driven by the submitted page's own
notification_priority (immediate -> critical, same_day -> warning,
queued -> info); the benchmark page defaults to 'same_day'; dedupe by
signal_id / token so a re-notify doesn't double up; and that an
outbound-link conversion fires notify_outbound_conversion (distinct
type) rather than the generic new_form_submission.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily import notifications as mf_notifications
from multifamily.forms.form_variants import FORM_VARIANTS

_FAILURES = []
_M = '(FUNNELNOTIF TEST)'
_notification_ids = []
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def test_new_form_submission_severity_by_priority():
    cases = [
        ('immediate', 'critical', 'Respond within the hour.'),
        ('same_day', 'warning', 'Respond today.'),
        ('queued', 'info', 'No urgent SLA'),
    ]
    for priority, expected_severity, expected_sla_snippet in cases:
        n = mf_notifications.notify_new_form_submission(
            'fake-lead-id', f'Priorityflow Co {priority} {_M}', 'acquisition',
            'acquisition_assumption_review', priority=priority, signal_id=f'sig-{priority}-{_M}',
        )
        check(f'{priority}: a notification was created', n is not None)
        if n:
            _notification_ids.append(n['id'])
            check(f'{priority}: severity is {expected_severity}', n['severity'] == expected_severity)
            check(f'{priority}: message carries the SLA text', expected_sla_snippet in n['message'])
            check(f'{priority}: type is new_form_submission', n['type'] == 'new_form_submission')


def test_new_form_submission_dedupes_by_signal_id():
    sig_id = f'dedupe-sig-{_M}'
    first = mf_notifications.notify_new_form_submission(
        'fake-lead-id', 'Dedupeflow Co', 'benchmark', 'multifamily_benchmark_review',
        priority='same_day', signal_id=sig_id,
    )
    second = mf_notifications.notify_new_form_submission(
        'fake-lead-id', 'Dedupeflow Co', 'benchmark', 'multifamily_benchmark_review',
        priority='same_day', signal_id=sig_id,
    )
    check('first call creates a notification', first is not None)
    if first:
        _notification_ids.append(first['id'])
    check('second call with the same signal_id is deduped (returns None)', second is None)


def test_benchmark_variant_defaults_to_same_day_priority():
    variant = FORM_VARIANTS['benchmark']
    check("benchmark variant's notification_priority is same_day", variant.notification_priority == 'same_day')


def test_immediate_priority_variants_match_the_funnel_plan():
    # Acquisition + lender-requirement + builders-risk are the "respond
    # right away" offers per the funnel strategy's routing rules.
    for slug in ('acquisition', 'lender-requirement', 'builders-risk'):
        check(f'{slug}: notification_priority is immediate', FORM_VARIANTS[slug].notification_priority == 'immediate')
    for slug in ('renewal-pressure', 'completion-leaseup'):
        check(f'{slug}: notification_priority is same_day', FORM_VARIANTS[slug].notification_priority == 'same_day')


def test_outbound_conversion_is_a_distinct_notification_type():
    token = f'test-token-{_M}'
    n = mf_notifications.notify_outbound_conversion('fake-lead-id', f'Conversionflow Co {_M}', 'acquisition', token)
    check('an outbound conversion notification was created', n is not None)
    if n:
        _notification_ids.append(n['id'])
        check('type is converted_from_outbound (not new_form_submission)', n['type'] == 'converted_from_outbound')
        check('severity is info (a positive/expected event, not urgent)', n['severity'] == 'info')
        check('message mentions the page it converted through', 'acquisition' in n['message'])

    # Re-firing for the SAME token is deduped.
    n2 = mf_notifications.notify_outbound_conversion('fake-lead-id', f'Conversionflow Co {_M}', 'acquisition', token)
    check('re-firing for the same token is deduped', n2 is None)


def test_new_notification_types_are_registered():
    check("'new_form_submission' is a recognized NOTIFICATION_TYPE",
          'new_form_submission' in mf_notifications.NOTIFICATION_TYPES)
    check("'converted_from_outbound' is a recognized NOTIFICATION_TYPE",
          'converted_from_outbound' in mf_notifications.NOTIFICATION_TYPES)


def main():
    try:
        test_new_form_submission_severity_by_priority()
        test_new_form_submission_dedupes_by_signal_id()
        test_benchmark_variant_defaults_to_same_day_priority()
        test_immediate_priority_variants_match_the_funnel_plan()
        test_outbound_conversion_is_a_distinct_notification_type()
        test_new_notification_types_are_registered()
    finally:
        for nid in _notification_ids:
            repository.delete_notification(nid)
        for lid in _lead_ids:
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_notification_ids)} notification(s), {len(_lead_ids)} lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All funnel notifications (Funnel Phase 5) tests passed.')


if __name__ == '__main__':
    main()
