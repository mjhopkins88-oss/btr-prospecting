"""
Question Path Engine — generates a structured, multifamily-insurance-
specific question path (connection -> situation -> problem awareness ->
solution awareness -> consequence -> qualifying -> transition ->
commitment) for a lead.

Every question here is ORIGINAL copy written for this codebase. This
module does not store or reproduce any proprietary source text — only
the general dialogue-based staging (understand the situation, help the
prospect recognize a problem, connect it to a consequence, then qualify
and transition) is used as a reasoning shape.
"""
from typing import Dict, List

from multifamily.sales_intelligence.nepq_types import SalesLeadContext, ConversationStrategy, QuestionPath

_UNIVERSAL_QUESTIONS_TO_AVOID = [
    "what's your budget for insurance",
    "are you the decision maker",
    "can you send me your exact premium right now",
    "would you switch brokers today",
]

# Per-scenario question themes. Each entry supplies the stage-specific
# question lists; connection/transition/commitment/fallback are filled in
# generically per-strategy (below) so they stay consistent with the
# selected NEPQ stage and tone.
_SCENARIO_QUESTIONS: Dict[str, Dict[str, List[str]]] = {
    'renewal_pressure': {
        'situation_questions': [
            "Where are you in the renewal timeline right now — early planning, or already deep into it?",
            "Is the current broker running the market process, or is that still wide open?",
            "Has the property schedule (values, deductibles) been refreshed, or is it carrying last year's numbers?",
        ],
        'problem_awareness_questions': [
            "Has pricing moved in a way that's changed how you're thinking about this renewal?",
            "Is the deductible structure still comfortable, or has that become more of a conversation internally?",
            "Anything from the last cycle — service, communication, surprises at binding — you'd want to avoid repeating?",
        ],
        'solution_awareness_questions': [
            "If the market genuinely had been tested this cycle, would that change anything for you?",
            "What would a cleaner renewal process actually look like for your team?",
        ],
        'consequence_questions': [
            "If pricing keeps trending the way it has, what does that start to do to NOI on this deal?",
            "If the market isn't tested this cycle, is there a risk you're just accepting whatever the incumbent brings back?",
        ],
        'qualifying_questions': [
            "Is there enough runway before renewal to actually pressure test this, or are we past that window?",
            "Who else would need to be involved if a second set of numbers came back stronger?",
        ],
    },
    'premium_increase': {
        'situation_questions': [
            "How much has premium moved over the last cycle or two?",
            "Is that increase specific to this property, or something you're seeing across the portfolio?",
        ],
        'problem_awareness_questions': [
            "Is that increase something ownership has flagged, or still mostly on your radar?",
            "Has anyone pressure tested whether that increase reflects the market, or just the incumbent's renewal number?",
        ],
        'solution_awareness_questions': [
            "Would it help to know whether that number is in line with the market or on the high side?",
        ],
        'consequence_questions': [
            "If that trend continues next cycle, what does it start to do to returns on the deal?",
        ],
        'qualifying_questions': [
            "Is there time before the next renewal to actually get a second read on this?",
        ],
    },
    'deductible_concern': {
        'situation_questions': [
            "What does the current deductible structure look like on this property?",
            "Has that structure been revisited recently, or has it carried forward for a while?",
        ],
        'problem_awareness_questions': [
            "Is the current deductible level still comfortable, or has that become a bigger conversation after a claim or two?",
        ],
        'solution_awareness_questions': [
            "Would a different deductible strategy change how exposed you feel day to day?",
        ],
        'consequence_questions': [
            "If a claim came in tomorrow, is the current deductible something the property could absorb cleanly?",
        ],
        'qualifying_questions': [
            "Is deductible structure something you'd want revisited now, or is that more of a renewal-time conversation?",
        ],
    },
    'lender_requirement': {
        'situation_questions': [
            "Are the lender's insurance requirements already fully cleared, or are a few items still open?",
            "Which pieces are still in motion — property, GL, excess, deductibles, exclusions, or escrow?",
        ],
        'problem_awareness_questions': [
            "Has anything from the lender's requirements been harder to satisfy than expected?",
        ],
        'solution_awareness_questions': [
            "Would it help to have those open items resolved before they become a closing-timeline issue?",
        ],
        'consequence_questions': [
            "If those items aren't cleared in time, what does that do to the closing or draw schedule?",
        ],
        'qualifying_questions': [
            "What's the actual deadline you're working back from on the lender side?",
        ],
    },
    'acquisition_due_diligence': {
        'situation_questions': [
            "Are you underwriting this off the seller's current insurance numbers, or pricing it independently?",
            "What's the timeline to close, and when do you need insurance certainty locked in by?",
        ],
        'problem_awareness_questions': [
            "Has anything in the seller's insurance numbers looked optimistic once you dug in?",
            "Is there a lender requirement shaping how this needs to be structured?",
        ],
        'solution_awareness_questions': [
            "Would an independent read on property, GL, excess, and deductibles change the underwriting at all?",
        ],
        'consequence_questions': [
            "If the seller's numbers turn out to be off, what does that do to the deal economics after close?",
        ],
        'qualifying_questions': [
            "Is there still time before close to get a second set of numbers, or is that window closing?",
        ],
    },
    'refinance_or_financing': {
        'situation_questions': [
            "Are the lender's insurance conditions already cleared, or are some items still open?",
            "Which pieces are still moving — property, GL, excess, deductibles, exclusions, escrow, or carrier rating?",
        ],
        'problem_awareness_questions': [
            "Has anything about the current carrier's rating or the exclusions caused friction with the lender?",
        ],
        'solution_awareness_questions': [
            "Would resolving those open items now make the financing timeline easier to hold to?",
        ],
        'consequence_questions': [
            "If those items aren't resolved in time, what does that do to the closing date?",
        ],
        'qualifying_questions': [
            "What's the actual financing timeline you're working back from?",
        ],
    },
    'builders_risk': {
        'situation_questions': [
            "Has builder's risk already been bound, or is that still a moving piece?",
            "Is that on the GC's policy, or is it owner-controlled?",
            "Is there a lender subjectivity tied to builder's risk on this project?",
        ],
        'problem_awareness_questions': [
            "Has anything about hard costs, soft costs, or delay-in-completion coverage been a gray area so far?",
        ],
        'solution_awareness_questions': [
            "Would it help to have that locked in before the start date instead of scrambling closer to groundbreaking?",
        ],
        'consequence_questions': [
            "If that's still open closer to the start date, what does that do to the construction schedule?",
        ],
        'qualifying_questions': [
            "How close is the actual start or vertical construction date at this point?",
        ],
    },
    'completion_or_lease_up': {
        'situation_questions': [
            "Where are you in the transition from builder's risk to operating property and GL?",
            "Is occupancy happening in phases, or all at once?",
        ],
        'problem_awareness_questions': [
            "Has the timing of that hand-off been mapped out yet, or is it still a loose plan?",
        ],
        'solution_awareness_questions': [
            "Would it help to have the operating program lined up before lease-up actually starts?",
        ],
        'consequence_questions': [
            "If that transition isn't mapped ahead of time, is there a risk of a gap as units come online?",
        ],
        'qualifying_questions': [
            "What's the lease-up timeline you're working against right now?",
        ],
    },
    'gl_excess_concern': {
        'situation_questions': [
            "How is GL/excess structured across the portfolio today?",
        ],
        'problem_awareness_questions': [
            "Has anything about the current liability structure felt thin given the portfolio's exposure?",
        ],
        'solution_awareness_questions': [
            "Would a fresh look at excess layering change how comfortable you feel with the current limits?",
        ],
        'consequence_questions': [
            "If a serious claim hit tomorrow, would the current structure hold up the way you'd want it to?",
        ],
        'qualifying_questions': [
            "Is liability structure something worth revisiting now, or better tied to the next renewal?",
        ],
    },
    'claims_or_service_issue': {
        'situation_questions': [
            "What happened with the claim or service issue, in broad strokes?",
        ],
        'problem_awareness_questions': [
            "Was that more about how it was handled, or the outcome itself?",
        ],
        'solution_awareness_questions': [
            "Would better claims advocacy or responsiveness change how you think about the current relationship?",
        ],
        'consequence_questions': [
            "If something similar happened again, would you want it handled differently?",
        ],
        'qualifying_questions': [
            "Is this something you'd want addressed now, or is it more top-of-mind for the next renewal?",
        ],
    },
    'just_benchmarking': {
        'situation_questions': [
            "What prompted the benchmark request — is there a specific event, or just routine due diligence?",
            "Is there a renewal, acquisition, refinance, or construction project this ties back to?",
        ],
        'problem_awareness_questions': [
            "Is there something specific about the current program that made you want a second read?",
        ],
        'solution_awareness_questions': [
            "Would it be useful to know where the current structure sits against the market either way?",
        ],
        'consequence_questions': [
            "If the numbers come back in line, that's good to know too — is that useful either way?",
        ],
        'qualifying_questions': [
            "Is there a specific timeline this needs to land by?",
        ],
    },
    'unknown': {
        'situation_questions': [
            "What's the current insurance program look like for this property?",
            "Who typically handles the insurance conversation on your side?",
        ],
        'problem_awareness_questions': [
            "Is there anything about the current setup that's been on your mind lately?",
        ],
        'solution_awareness_questions': [
            "Would a quick benchmark against the market be useful, even just as a reference point?",
        ],
        'consequence_questions': [
            "If nothing changes here, is that a fine outcome, or does something eventually need attention?",
        ],
        'qualifying_questions': [
            "Is this something worth a closer look now, or better revisited later?",
        ],
    },
}

_WEBSITE_INTENT_TEMPLATE = {
    'situation_questions': [
        "Is multifamily insurance something your team is actively looking into right now, or just early research?",
        "Is there a renewal, acquisition, or lender requirement this ties back to, if any?",
    ],
    'problem_awareness_questions': [
        "Was there something specific that prompted the search, or just general due diligence?",
    ],
    'solution_awareness_questions': [
        "Would a quick benchmark be useful, or is it too early for that?",
    ],
    'consequence_questions': [
        "If this sits for a while longer, is that fine, or is there a timeline behind it?",
    ],
    'qualifying_questions': [
        "Which bucket is this closest to — renewal, acquisition, lender requirement, or deductible concern — if any?",
    ],
}

_TRIGGER_ONLY_TEMPLATE = {
    'situation_questions': [
        "Is insurance even on the radar yet at this stage of the project, or is it too early?",
    ],
    'problem_awareness_questions': [
        "When it does come up, is that usually handled internally or through a broker relationship already in place?",
    ],
    'solution_awareness_questions': [
        "Would it be useful to have a benchmark ready before that becomes time-sensitive?",
    ],
    'consequence_questions': [
        "Is there a point where this becomes urgent — a start date, a closing, a deadline?",
    ],
    'qualifying_questions': [
        "Roughly when would this become relevant, if at all?",
    ],
}

_NURTURE_TEMPLATE = {
    'situation_questions': [
        "Is there a renewal, acquisition, or project on the horizon this would tie back to eventually?",
    ],
    'problem_awareness_questions': [],
    'solution_awareness_questions': [],
    'consequence_questions': [],
    'qualifying_questions': [
        "Would it be worth reconnecting closer to that timing?",
    ],
}


def _connection_question(context: SalesLeadContext, strategy: ConversationStrategy) -> str:
    if strategy.rule_applied == 'rule_8_permit_news_soft_relevance_check':
        return "Not sure this is even relevant yet, but is insurance something that's crossed your desk for this project?"
    if strategy.rule_applied == 'rule_2_website_intent_soft_curiosity':
        return "Not sure if this is something your team is actively reviewing, but curious what brought you by?"
    if strategy.rule_applied == 'rule_9_nurture_watchlist_no_pitch':
        return "No specific reason for reaching out today — just wanted to stay on your radar for whenever the timing's better."
    return f"Thanks for the note on {context.company_name} — what prompted you to reach out now?"


def _transition_question(context: SalesLeadContext) -> str:
    return (
        "Based on what you've shared, it sounds like there might be a useful checkpoint here — "
        "would it be worth a short conversation to see if there's anything worth acting on?"
    )


def _commitment_question(context: SalesLeadContext, strategy: ConversationStrategy) -> str:
    if strategy.recommended_action == 'ask_for_sov':
        return "Would it be easy enough to send over the current SOV so we can take a first look?"
    if strategy.recommended_action == 'ask_for_loss_runs':
        return "Would it help to start with the last few years of loss runs, or is that not available yet?"
    if strategy.recommended_action in ('ask_for_current_program_details', 'ask_for_renewal_timing'):
        return "Would it make sense to grab 15 minutes to walk through where things stand?"
    if strategy.recommended_action == 'nurture':
        return "No pressure either way — would it be alright if I checked back in when the timing's better?"
    return "Would a short call this week make sense, or is there a better time?"


def _fallback_question(context: SalesLeadContext) -> str:
    return "No worries if this isn't the right moment — is there a better time to check back in?"


def _questions_to_avoid(context: SalesLeadContext, strategy: ConversationStrategy) -> List[str]:
    avoid = list(_UNIVERSAL_QUESTIONS_TO_AVOID)
    if context.resistance_risk == 'high':
        avoid.append("anything that stacks two or three questions into one message")
    if strategy.recommended_action == 'nurture':
        avoid.append("any question that implies they should act now")
    return avoid


def build_question_path(context: SalesLeadContext, strategy: ConversationStrategy) -> QuestionPath:
    if strategy.rule_applied == 'rule_9_nurture_watchlist_no_pitch':
        template = _NURTURE_TEMPLATE
    elif strategy.rule_applied == 'rule_8_permit_news_soft_relevance_check':
        template = _TRIGGER_ONLY_TEMPLATE
    elif strategy.rule_applied == 'rule_2_website_intent_soft_curiosity':
        template = _WEBSITE_INTENT_TEMPLATE
    else:
        template = _SCENARIO_QUESTIONS.get(context.insurance_scenario, _SCENARIO_QUESTIONS['unknown'])

    return QuestionPath(
        connection_question=_connection_question(context, strategy),
        situation_questions=list(template.get('situation_questions', [])),
        problem_awareness_questions=list(template.get('problem_awareness_questions', [])),
        solution_awareness_questions=list(template.get('solution_awareness_questions', [])),
        consequence_questions=list(template.get('consequence_questions', [])),
        qualifying_questions=list(template.get('qualifying_questions', [])),
        transition_question=_transition_question(context),
        commitment_question=_commitment_question(context, strategy),
        fallback_question=_fallback_question(context),
        questions_to_avoid=_questions_to_avoid(context, strategy),
    )
