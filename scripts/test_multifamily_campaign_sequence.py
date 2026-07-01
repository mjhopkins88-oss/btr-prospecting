#!/usr/bin/env python
"""
Section 8 items 1-3, Phase 1 tests: campaign-target sequence-cadence
tracking (touch_1_sent/connected/touch_2_sent/called/breakup_sent),
the 'bounced' data-quality flag, and the coarse renewal_month fallback.

Covers: each CAMPAIGN_TARGET_TOUCH_STEPS value marks its own distinct
column and doesn't clobber the others; re-marking a step is idempotent
(updates the timestamp, doesn't error/duplicate); marking a touch
bumps last_activity_at; 'bounced' is tracked the same mechanical way
but is a wholly separate column from status/disqualification;
set_campaign_target_renewal_month persists and bumps last_activity_at;
the sequence axis is fully independent of `status` (marking touches
never changes status, and vice versa); and the 3 new enums in types.py
are internally consistent.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.types import (
    CAMPAIGN_TARGET_TOUCH_STEPS, DISQUALIFICATION_REASONS, REPLY_SENTIMENTS,
)
from multifamily.forms.form_variants import FORM_VARIANTS

_FAILURES = []
_M = '(CAMPAIGNSEQ TEST)'
_campaign_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_campaign(name_suffix, page_variant='renewal-pressure'):
    variant = FORM_VARIANTS[page_variant]
    campaign = repository.create_campaign(
        name=f'{name_suffix} {_M}', page_variant=page_variant, offer_type=variant.offer_type,
    )
    _campaign_ids.append(campaign['id'])
    return campaign


def test_each_touch_step_marks_its_own_column_only():
    campaign = _make_campaign('TouchStepsCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Touch Steps Co')

    check('all 6 touch/bounce columns start unset', all(
        target.get(col) is None for col in
        ['touch_1_sent_at', 'connected_at', 'touch_2_sent_at', 'called_at', 'breakup_sent_at', 'bounced_at']
    ))

    repository.mark_campaign_target_touch(target['id'], 'touch_1_sent')
    after_touch1 = repository.get_campaign_target(target['id'])
    check('touch_1_sent sets touch_1_sent_at', after_touch1['touch_1_sent_at'] is not None)
    check('touch_1_sent does NOT set connected_at', after_touch1['connected_at'] is None)
    check('touch_1_sent does NOT set touch_2_sent_at', after_touch1['touch_2_sent_at'] is None)
    check('touch_1_sent does NOT set called_at', after_touch1['called_at'] is None)
    check('touch_1_sent does NOT set breakup_sent_at', after_touch1['breakup_sent_at'] is None)
    check('touch_1_sent does NOT set bounced_at', after_touch1['bounced_at'] is None)
    check('marking a touch does not change status', after_touch1['status'] == 'planned')

    repository.mark_campaign_target_touch(target['id'], 'connected')
    repository.mark_campaign_target_touch(target['id'], 'touch_2_sent')
    repository.mark_campaign_target_touch(target['id'], 'called')
    repository.mark_campaign_target_touch(target['id'], 'breakup_sent')
    full = repository.get_campaign_target(target['id'])
    check('all 5 sequence steps are independently set', all(
        full.get(col) is not None for col in
        ['touch_1_sent_at', 'connected_at', 'touch_2_sent_at', 'called_at', 'breakup_sent_at']
    ))
    check('bounced_at is still unset (never marked)', full['bounced_at'] is None)


def test_bounced_is_separate_from_disqualification_and_status():
    campaign = _make_campaign('BounceCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Bounce Test Co')
    repository.mark_campaign_target_touch(target['id'], 'bounced')
    after = repository.get_campaign_target(target['id'])
    check('bounced sets bounced_at', after['bounced_at'] is not None)
    check('bounced does not touch any sequence-step column', all(
        after.get(col) is None for col in
        ['touch_1_sent_at', 'connected_at', 'touch_2_sent_at', 'called_at', 'breakup_sent_at']
    ))
    check('bounced does not change status', after['status'] == 'planned')
    check('bounced does not set converted_at', after['converted_at'] is None)


def test_remarking_a_touch_is_idempotent_not_duplicated():
    campaign = _make_campaign('RemarkCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Remark Co')
    repository.mark_campaign_target_touch(target['id'], 'called')
    first = repository.get_campaign_target(target['id'])['called_at']
    repository.mark_campaign_target_touch(target['id'], 'called', occurred_at='2020-01-01T00:00:00')
    second = repository.get_campaign_target(target['id'])['called_at']
    check('re-marking the same step updates the timestamp (not a duplicate row)', second == '2020-01-01T00:00:00')
    check('the target row count for this campaign is still exactly 1', len(repository.list_campaign_targets(campaign['id'])) == 1)
    check('re-marking changed the value from the first mark', first != second)


def test_marking_a_touch_bumps_last_activity_at():
    campaign = _make_campaign('ActivityBumpCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Activity Bump Co')
    check('last_activity_at starts unset', target['last_activity_at'] is None)
    repository.mark_campaign_target_touch(target['id'], 'touch_1_sent')
    after = repository.get_campaign_target(target['id'])
    check('marking a touch sets last_activity_at', after['last_activity_at'] is not None)


def test_renewal_month_persists_and_bumps_activity():
    campaign = _make_campaign('RenewalMonthCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Renewal Month Co')
    repository.set_campaign_target_renewal_month(target['id'], '2026-06')
    after = repository.get_campaign_target(target['id'])
    check('renewal_month persists', after['renewal_month'] == '2026-06')
    check('setting renewal_month bumps last_activity_at', after['last_activity_at'] is not None)
    check('setting renewal_month does not change status', after['status'] == 'planned')


def test_sequence_axis_independent_of_status():
    campaign = _make_campaign('IndependentAxisCampaign')
    target = repository.create_campaign_target(campaign['id'], company='Independent Axis Co')
    repository.update_campaign_target_status(target['id'], 'contacted')
    repository.mark_campaign_target_touch(target['id'], 'touch_1_sent')
    after = repository.get_campaign_target(target['id'])
    check('status set independently of sequence marks', after['status'] == 'contacted')
    check('touch_1_sent_at still set alongside a coarse status', after['touch_1_sent_at'] is not None)
    check('touch_2_sent_at remains unset (sequence progress is granular)', after['touch_2_sent_at'] is None)


def test_new_enums_are_consistent():
    check('CAMPAIGN_TARGET_TOUCH_STEPS has exactly 6 entries', len(CAMPAIGN_TARGET_TOUCH_STEPS) == 6)
    check("'bounced' is in CAMPAIGN_TARGET_TOUCH_STEPS", 'bounced' in CAMPAIGN_TARGET_TOUCH_STEPS)
    for step in CAMPAIGN_TARGET_TOUCH_STEPS:
        campaign = _make_campaign(f'EnumCheck{step}')
        target = repository.create_campaign_target(campaign['id'], company=f'Enum Check {step} Co')
        repository.mark_campaign_target_touch(target['id'], step)  # must not raise for any real enum value

    check('DISQUALIFICATION_REASONS has the 8 documented reasons', DISQUALIFICATION_REASONS == [
        'too_small', 'institutional', 'incumbent_locked', 'sold_property',
        'wrong_contact', 'no_fit_geo', 'timing_far', 'hostile',
    ])
    check('REPLY_SENTIMENTS has the 4 documented values',
          REPLY_SENTIMENTS == ['positive', 'neutral', 'negative', 'referral'])
    check("DISQUALIFICATION_REASONS and REPLY_SENTIMENTS don't overlap (distinct concepts)",
          not set(DISQUALIFICATION_REASONS) & set(REPLY_SENTIMENTS))


def main():
    try:
        test_each_touch_step_marks_its_own_column_only()
        test_bounced_is_separate_from_disqualification_and_status()
        test_remarking_a_touch_is_idempotent_not_duplicated()
        test_marking_a_touch_bumps_last_activity_at()
        test_renewal_month_persists_and_bumps_activity()
        test_sequence_axis_independent_of_status()
        test_new_enums_are_consistent()
    finally:
        for cid in _campaign_ids:
            try:
                repository.delete_campaign(cid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_campaign_ids)} tracked campaign(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All campaign sequence-cadence (Section 8 items 1-3, Phase 1) tests passed.')


if __name__ == '__main__':
    main()
