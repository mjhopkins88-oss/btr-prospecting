"""
Follow-Up Strategy Engine — picks the right NEXT touch (type + timing)
for a lead that hasn't converted or gone quiet, based on prior activity
and the current conversation strategy. Never recomputes scoring math;
read-only over the same context/activity data the rest of the engine uses.
"""
from multifamily.sales_intelligence.nepq_types import SalesLeadContext, ConversationStrategy, FollowUpStrategy

# Recommended actions whose FIRST touch is a request for specific
# information (SOV, loss runs, program details, renewal date, lender
# items) — the best follow-up on one of these is a short reminder about
# that same specific ask, not a generic "just checking in" touch.
_INFO_REQUEST_ACTIONS = {
    'ask_for_sov', 'ask_for_loss_runs', 'ask_for_current_program_details',
    'ask_for_lender_requirements', 'ask_for_renewal_timing',
}

_CLOSED_OUTCOMES = {'won', 'lost', 'not_a_fit', 'dead'}

_NO_PITCH_RULES = {'rule_9_nurture_watchlist_no_pitch', 'rule_8_permit_news_soft_relevance_check'}


def select_follow_up_strategy(context: SalesLeadContext, strategy: ConversationStrategy) -> FollowUpStrategy:
    # Already engaged — the next touch should move toward confirming a
    # next step, not repeat the original ask.
    if context.replied:
        return FollowUpStrategy(
            follow_up_type='meeting_confirmation_follow_up',
            message_field='meeting_confirmation_note',
            recommended_wait_days=1,
            reasoning='Lead has already replied — the next touch should confirm next steps, not repeat the original ask.',
        )

    # Deal already has a recorded closed outcome — no further outreach.
    if context.current_outcome_type in _CLOSED_OUTCOMES:
        return FollowUpStrategy(
            follow_up_type='no_further_action',
            message_field=None,
            recommended_wait_days=0,
            is_final_attempt=True,
            reasoning=f'Outcome already recorded as "{context.current_outcome_type}" — no further outreach warranted.',
        )

    # Trigger-only / genuinely no active discovery thread — long, soft
    # cadence, never a hard follow-up push.
    if strategy.rule_applied in _NO_PITCH_RULES:
        return FollowUpStrategy(
            follow_up_type='nurture_reconnect',
            message_field='soft_bump',
            recommended_wait_days=45,
            reasoning='No active discovery thread yet — stay visible without pitching again.',
        )

    # The original ask was for specific information — a quick reminder
    # about that same ask lands better than a generic first follow-up,
    # since these are often time-sensitive (lender/acquisition deadlines).
    if strategy.recommended_action in _INFO_REQUEST_ACTIONS and context.activity_count == 0:
        return FollowUpStrategy(
            follow_up_type='info_request_reminder',
            message_field='info_request_note',
            recommended_wait_days=3,
            reasoning='Original ask was for specific information — a short reminder lands better than a generic follow-up.',
        )

    if context.activity_count == 0:
        return FollowUpStrategy(
            follow_up_type='first_follow_up',
            message_field='follow_up_1',
            recommended_wait_days=4,
            reasoning='No outreach logged yet — this would be the first follow-up after the initial touch.',
        )

    if context.activity_count == 1:
        return FollowUpStrategy(
            follow_up_type='second_follow_up',
            message_field='follow_up_2',
            recommended_wait_days=7,
            reasoning='One prior touch with no reply — one more low-pressure follow-up before stepping back.',
        )

    # Two or more touches with no reply — one last soft bump, then let
    # nurture take over rather than continuing to push.
    return FollowUpStrategy(
        follow_up_type='soft_bump',
        message_field='soft_bump',
        recommended_wait_days=21,
        is_final_attempt=True,
        reasoning='Multiple touches with no reply — one last low-pressure note, then step back and let nurture take over.',
    )
