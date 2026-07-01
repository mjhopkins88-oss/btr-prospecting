"""
Message Strategy Engine — turns a ConversationStrategy + QuestionPath into
actual outreach copy: call opener, first email, LinkedIn note, two
follow-ups, a soft bump, a meeting-confirmation note, and an
info-request note.

Tone (Max): casual but professional, confident but not pushy,
relationship-driven, slightly conversational, not robotic, not cheesy.
Concise. One clear low-pressure question or next step per message. Never
presents the full program before enough situation/problem context
exists (handled upstream by the strategy engine — should_present is
always False for a starting approach).

Every scenario/origin hook below is ORIGINAL copy written for this
codebase — themed on (not copied from) the reasoning brief. `variant`
rotates among a small set of equivalent phrasings so "Regenerate
approach" produces a genuinely different draft, not the same string.
"""
from typing import List, Optional

from multifamily.sales_intelligence.nepq_types import SalesLeadContext, ConversationStrategy, QuestionPath, MessagePackage

# Phrases the generator must never emit, in any message. Checked by
# scripts/test_multifamily_sales_intelligence.py against every generated
# string, and available to callers for their own guardrail checks.
PROHIBITED_PHRASES = [
    "i hope this email finds you well",
    "we are the leading provider",
    "we can save you",
    "i guarantee",
    "you need to",
    "act now",
    "just checking in",
    "touching base",
    "wanted to pick your brain",
    "i saw you visited",
    "i saw that you visited",
    "i noticed you visited",
    "visited our website",
]


def contains_prohibited_phrase(text: str) -> Optional[str]:
    """Return the first prohibited phrase found in `text` (case-insensitive),
    or None if the text is clean."""
    lowered = (text or '').lower()
    for phrase in PROHIBITED_PHRASES:
        if phrase in lowered:
            return phrase
    return None


_SCENARIO_HOOKS = {
    'renewal_pressure': [
        "Renewal season tends to bring one of three things to the surface — pricing pressure, "
        "deductible frustration, or just wanting confirmation the market actually got tested. "
        "Curious which of those is closest for you right now",
        "When groups start looking at their program ahead of renewal, it's usually pricing, "
        "deductibles, or making sure the incumbent actually shopped it. Curious which one's closest on your end",
    ],
    'premium_increase': [
        "Premium movement like that usually raises one question — is this the market, or "
        "specific to the account. Worth a quick gut check either way",
        "When premium jumps that kind of way, it's worth knowing whether that's market-wide "
        "or account-specific. Happy to help sort that out if it's useful",
    ],
    'deductible_concern': [
        "Deductible comfort is one of those things that quietly shifts after a claim or two. "
        "Wondering where that stands for you right now",
        "Curious whether the current deductible structure still feels right, or if that's "
        "become more of a conversation lately",
    ],
    'lender_requirement': [
        "Lender insurance conditions have a way of surfacing late in the process. Wondering if "
        "those are already buttoned up on your end or still a few open items",
        "Curious whether the lender's insurance requirements are fully cleared at this point, "
        "or if a couple pieces are still moving",
    ],
    'acquisition_due_diligence': [
        "On acquisitions, the insurance numbers in underwriting sometimes come straight from "
        "the seller. Curious whether that's the approach here, or if it's being independently checked",
        "Curious how you're handling insurance in underwriting on this one — seller's numbers "
        "as-is, or an independent pressure test before close",
    ],
    'refinance_or_financing': [
        "Refinances tend to surface a handful of open insurance items right before closing. "
        "Wondering where things stand on your end",
        "Curious whether the lender's insurance conditions are already resolved on this one, "
        "or if a few things are still in motion",
    ],
    'builders_risk': [
        "Builder's risk has a way of becoming urgent right before ground breaks. Curious "
        "whether that's locked in yet or still moving",
        "Wondering whether builder's risk is already placed on this project, or if that's "
        "still an open item",
    ],
    'completion_or_lease_up': [
        "The hand-off from builder's risk to an operating program is easy to leave until the "
        "last minute. Curious where that stands for you",
        "Wondering whether the transition off builder's risk into operating coverage has been "
        "mapped out yet as units come online",
    ],
    'gl_excess_concern': [
        "Liability exposure has a way of outgrowing the structure that was in place when the "
        "portfolio was smaller. Curious how that's held up",
        "Wondering whether the current GL/excess layering still matches where the portfolio "
        "sits today",
    ],
    'claims_or_service_issue': [
        "A rough claims experience tends to stick. Curious how that ultimately landed for you",
        "Wondering how that situation ended up getting resolved, and whether it changed how "
        "you think about the current setup",
    ],
    'just_benchmarking': [
        "Curious what got this on your radar — renewal, acquisition, lender requirement, or "
        "just wanting a market reference point",
        "Wondering which bucket this falls into for you — renewal coming up, a deal in the "
        "works, or just checking where things stand",
    ],
    'unknown': [
        "Not sure if this is even on your radar right now, but curious whether the current "
        "program has come up in conversation lately",
        "Wondering whether insurance is something actively being looked at right now, or more "
        "of a someday item",
    ],
}

_WEBSITE_INTENT_HOOKS = [
    "Not sure if this is something your team's actively reviewing, but curious what brought you by",
    "Not sure where this sits on your priority list right now, but curious what got you looking into this",
]

_TRIGGER_ONLY_HOOKS = [
    "Not sure this has even reached the insurance conversation yet, but wanted to check in "
    "given where the project's at",
    "Not sure if this is relevant yet, but figured it was worth a quick check given the project's stage",
]

_NURTURE_HOOKS = [
    "No specific reason for reaching out today — just wanted to stay on your radar for whenever "
    "the timing's better",
    "Nothing urgent here — just keeping the door open for whenever this becomes more relevant",
]


def _pick_hook(context: SalesLeadContext, strategy: ConversationStrategy, variant: int) -> str:
    if strategy.rule_applied == 'rule_9_nurture_watchlist_no_pitch':
        pool = _NURTURE_HOOKS
    elif strategy.rule_applied == 'rule_8_permit_news_soft_relevance_check':
        pool = _TRIGGER_ONLY_HOOKS
    elif strategy.rule_applied == 'rule_2_website_intent_soft_curiosity':
        pool = _WEBSITE_INTENT_HOOKS
    else:
        pool = _SCENARIO_HOOKS.get(context.insurance_scenario, _SCENARIO_HOOKS['unknown'])
    return pool[variant % len(pool)]


def _greeting(context: SalesLeadContext) -> str:
    return f"Hi {context.contact_first_name}" if context.contact_first_name else "Hi there"


def _possessive(name: str) -> str:
    return f"{name}'" if name.endswith('s') else f"{name}'s"


def _info_request_target(strategy: ConversationStrategy) -> str:
    return {
        'ask_for_sov': 'the current SOV',
        'ask_for_loss_runs': 'the last few years of loss runs',
        'ask_for_current_program_details': 'the current program summary or declarations page',
        'ask_for_renewal_timing': 'the renewal date',
    }.get(strategy.recommended_action, 'a bit more context on where things stand')


def build_message_package(
    context: SalesLeadContext, strategy: ConversationStrategy, question_path: QuestionPath, variant: int = 0,
) -> MessagePackage:
    greeting = _greeting(context)
    hook = _pick_hook(context, strategy, variant)
    company = context.company_name
    state_clause = f" in {context.state}" if context.state else ""

    call_opener = (
        f"{greeting} — thanks for grabbing a second. {hook}?"
    )

    first_email_subject = f"Quick one on {_possessive(company)} insurance program"
    first_email_body = (
        f"{greeting},\n\n"
        f"{hook}?\n\n"
        f"No pressure either way — happy to compare notes if it's useful, and if the timing's "
        f"off just let me know.\n\n"
        f"Best,\nMax"
    )

    linkedin_note_manual = f"{greeting} — {hook}? No pitch, just curious."

    follow_up_1 = (
        f"{greeting} — circling back in case this got buried. {question_path.fallback_question} "
        f"Totally fine either way."
    )

    follow_up_2 = (
        f"{greeting} — last note from me on this for now. If it's useful to revisit down the "
        f"line, happy to reconnect. Otherwise I'll leave it with you."
    )

    soft_bump = (
        f"{greeting} — not sure this is even relevant right now, so feel free to ignore. "
        f"If it becomes useful later, just say the word."
    )

    meeting_confirmation_note = (
        f"{greeting} — great, that time works. I'll keep it short and focused on what you "
        f"shared{state_clause} — no formal pitch, just a working conversation."
    )

    info_request_note = (
        f"{greeting} — would it be easy enough to send over {_info_request_target(strategy)}? "
        f"That'd let us give you a real read instead of guessing."
    )

    return MessagePackage(
        call_opener=call_opener,
        first_email_subject=first_email_subject,
        first_email_body=first_email_body,
        linkedin_note_manual=linkedin_note_manual,
        follow_up_1=follow_up_1,
        follow_up_2=follow_up_2,
        soft_bump=soft_bump,
        meeting_confirmation_note=meeting_confirmation_note,
        info_request_note=info_request_note,
    )
