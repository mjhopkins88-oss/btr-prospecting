#!/usr/bin/env python
"""
Tests for manual activity / follow-up tracking (multifamily/repository.py,
Part 7). Inserts activities tagged with a unique lead id and cleans up.
"""
import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.types import ACTIVITY_TYPES

_FAILURES = []
_LEAD = 'activity-test-lead-' + os.urandom(4).hex()


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def main():
    try:
        repository.ensure_schema()

        # Creates an activity with a follow-up due in the past.
        past = (date.today() - timedelta(days=1)).isoformat()
        a = repository.insert_activity(_LEAD, 'called', note='Left a voicemail', next_follow_up_date=past, user_email='op@example.com')
        check('insert_activity returns the created row', a['activity_type'] == 'called' and a['lead_id'] == _LEAD)
        check('all ACTIVITY_TYPES are recognized constants', 'called' in ACTIVITY_TYPES and 'follow_up_due' in ACTIVITY_TYPES)

        repository.insert_activity(_LEAD, 'replied', note='Asked for timing')
        repository.insert_activity(_LEAD, 'meeting_booked')
        repository.insert_activity(_LEAD, 'needs_info')

        acts = repository.get_activities_for_lead(_LEAD)
        check('get_activities_for_lead returns all logged activities', len(acts) == 4)
        check('activities are newest-first', acts[0]['activity_type'] == 'needs_info')

        # Follow-up due dashboard: the past-dated follow-up shows up.
        due = repository.get_followups_due(date.today().isoformat())
        mine = [d for d in due if d['lead_id'] == _LEAD]
        check('manual activity with a past follow-up date appears in follow-ups due', len(mine) == 1)

        # A future follow-up should NOT be due yet.
        future_lead = _LEAD + '-future'
        repository.insert_activity(future_lead, 'follow_up_due', next_follow_up_date=(date.today() + timedelta(days=10)).isoformat())
        due2 = repository.get_followups_due(date.today().isoformat())
        check('a future follow-up is NOT yet due', not any(d['lead_id'] == future_lead for d in due2))

        by_type = repository.get_activities_by_type(['replied', 'meeting_booked'])
        mine_types = {a['activity_type'] for a in by_type if a['lead_id'] == _LEAD}
        check('get_activities_by_type filters correctly', mine_types == {'replied', 'meeting_booked'})

        last = repository.last_activity_at_by_lead()
        check('last_activity_at_by_lead includes the test lead', _LEAD in last)

        repository.delete_activities_for_lead(_LEAD)
        repository.delete_activities_for_lead(future_lead)
        check('cleanup removes the lead activities', len(repository.get_activities_for_lead(_LEAD)) == 0)
    finally:
        repository.delete_activities_for_lead(_LEAD)
        repository.delete_activities_for_lead(_LEAD + '-future')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All activity tests passed.')


if __name__ == '__main__':
    main()
