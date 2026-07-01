"""
Objection & Resistance Engine — diagnoses common objections/pushback and
recommends a low-pressure, question-led response instead of a rebuttal.

Every response here asks a resolving or clarifying question rather than
arguing the point — consistent with the dialogue-based approach (self-
discovery over pressure) used across the rest of this engine.
"""
from typing import Dict, List, Optional

from multifamily.sales_intelligence.nepq_types import SalesLeadContext, ObjectionResponse

OBJECTION_KEYS = [
    'already_have_broker', 'not_interested', 'send_me_information', 'we_are_good_for_now',
    'renewal_not_for_a_while', 'just_renewed', 'pricing_not_a_concern', 'too_busy',
    'owner_handles_it', 'risk_manager_handles_it', 'gc_handles_builders_risk',
    'lender_already_approved', 'we_do_not_share_policies', 'no_response_ghosted',
]

_OBJECTION_DEFS: Dict[str, Dict[str, object]] = {
    'already_have_broker': {
        'likely_meaning': "Could be genuine satisfaction, could be default resistance, or the incumbent may simply control the renewal process by default — not necessarily a sign there's no opportunity.",
        'disposition': 'clarify',
        'response': "Makes sense — most groups do. Do you ever benchmark independently, or does the incumbent handle the whole market process?",
        'follow_up_strategy': "If they say they never benchmark, offer to reconnect near the next renewal rather than pushing now. If they're open to it, ask about timing.",
        'what_not_to_say': ["anything critical of the incumbent broker", "claims that we're better without evidence"],
    },
    'not_interested': {
        'likely_meaning': "Could be timing, could be genuine lack of need, could be a reflexive brush-off to a cold touch.",
        'disposition': 'disengage',
        'response': "Totally fair — is it more that the timing's off, or genuinely not something on your radar at all?",
        'follow_up_strategy': "If timing is the issue, offer to check back near a more relevant point (renewal, acquisition, project milestone). If genuinely not relevant, disengage and don't follow up again.",
        'what_not_to_say': ["a rebuttal", "any pressure to reconsider"],
    },
    'send_me_information': {
        'likely_meaning': "Often a polite way to end the conversation, but sometimes a genuine ask — worth a quick clarifying question before sending anything generic.",
        'disposition': 'clarify',
        'response': "Happy to — what would actually be useful? Renewal timing, a market benchmark, or something specific like deductible or lender requirements?",
        'follow_up_strategy': "Send only what's specifically relevant to their answer — never a generic brochure. If they don't specify, send one short, targeted note.",
        'what_not_to_say': ["a generic brochure or slide deck", "a long list of services"],
    },
    'we_are_good_for_now': {
        'likely_meaning': "Could mean the renewal outcome was genuinely fine, or that insurance has quietly become more of a budget line than a strategic conversation.",
        'disposition': 'clarify',
        'response': "Good to hear — was that outcome pretty predictable, or has it started to feel more like a budget number than something you're actively managing?",
        'follow_up_strategy': "If there's no real pain, nurture for the next cycle. If budget frustration surfaces, move into problem-awareness questions.",
        'what_not_to_say': ["an assumption that they must have a problem"],
    },
    'renewal_not_for_a_while': {
        'likely_meaning': "Timing objection, not necessarily disinterest — renewal just isn't front-of-mind yet.",
        'disposition': 'nurture',
        'response': "No problem — when does this typically come back on your radar? Happy to check back around 120 days out.",
        'follow_up_strategy': "Set a soft reminder to reconnect closer to the renewal window; don't push before then.",
        'what_not_to_say': ["urgency language implying they should act now"],
    },
    'just_renewed': {
        'likely_meaning': "Fresh renewal — pushing now would be poorly timed regardless of how it went.",
        'disposition': 'nurture',
        'response': "Good timing to ask, then — did that land cleanly enough that you'd run the same process again next year?",
        'follow_up_strategy': "Nurture for the next cycle; note anything they mention about friction for a future conversation.",
        'what_not_to_say': ["any suggestion to revisit coverage immediately after binding"],
    },
    'pricing_not_a_concern': {
        'likely_meaning': "Pricing may genuinely not be the pain point — deductible, service, or lender issues could still be relevant.",
        'disposition': 'clarify',
        'response': "Fair enough — is it more the deductible structure, the service side, or something else that occasionally comes up?",
        'follow_up_strategy': "Follow whichever thread they name; if none, treat as low-priority nurture.",
        'what_not_to_say': ["insisting pricing must matter"],
    },
    'too_busy': {
        'likely_meaning': "Genuine bandwidth constraint, not necessarily disinterest.",
        'disposition': 'nurture',
        'response': "Totally understand — would a shorter, async version (just send over a renewal date or SOV) work better than a call right now?",
        'follow_up_strategy': "Offer the lowest-effort next step available; if still no response, move to a soft bump and then nurture.",
        'what_not_to_say': ["pressure to make time now"],
    },
    'owner_handles_it': {
        'likely_meaning': "Contact isn't the decision-maker — could still be a useful internal connector.",
        'disposition': 'clarify',
        'response': "Got it — would it make sense to loop them in, or is it easier if I reach out directly?",
        'follow_up_strategy': "Ask for an introduction rather than requesting contact info outright; keep the current contact warm as an internal ally.",
        'what_not_to_say': ["pushing to bypass the current contact"],
    },
    'risk_manager_handles_it': {
        'likely_meaning': "Same as above — a routing signal, not a rejection.",
        'disposition': 'clarify',
        'response': "Makes sense — would it be alright to connect with them directly, or would you rather be the one to loop them in?",
        'follow_up_strategy': "Let them choose the path; follow up with whoever they identify.",
        'what_not_to_say': ["treating this as a dead end"],
    },
    'gc_handles_builders_risk': {
        'likely_meaning': "Common on construction deals — the GC may control the policy, but the owner may still have exposure or a say.",
        'disposition': 'clarify',
        'response': "That's common — is it worth a quick look at whether the GC's policy actually covers the ownership side the way you'd want, or is that already settled?",
        'follow_up_strategy': "If there's uncertainty about ownership-side coverage, that's the opening; if fully settled, nurture toward the next project.",
        'what_not_to_say': ["implying the GC's coverage is inadequate without knowing"],
    },
    'lender_already_approved': {
        'likely_meaning': "Approval doesn't always mean the process was clean — worth a light check.",
        'disposition': 'clarify',
        'response': "Good to hear — did that approval come through cleanly, or were there any deductible, exclusion, or escrow items that came up along the way?",
        'follow_up_strategy': "If friction surfaces, that's the opening for next time; if clean, nurture toward the next transaction.",
        'what_not_to_say': ["second-guessing the lender's approval"],
    },
    'we_do_not_share_policies': {
        'likely_meaning': "A reasonable boundary, not a rejection of the relationship.",
        'disposition': 'clarify',
        'response': "Totally fair — no need for the full policy. Would a general sense of the renewal timing or structure be okay to share instead?",
        'follow_up_strategy': "Respect the boundary; ask for the smallest useful piece of context instead of pushing for documents.",
        'what_not_to_say': ["pushing for the policy after they've declined"],
    },
    'no_response_ghosted': {
        'likely_meaning': "Could be timing, bandwidth, or genuine disinterest — impossible to know without one more low-pressure touch.",
        'disposition': 'nurture',
        'response': "No worries if this isn't the right moment — happy to check back later. Just let me know if now's genuinely not it.",
        'follow_up_strategy': "One short soft bump with an easy out, then move to long-cycle nurture if still no response.",
        'what_not_to_say': ["guilt-tripping language", "repeated asks in short succession", "implying urgency that doesn't exist"],
    },
}


def handle_objection(objection_key: str, context: Optional[SalesLeadContext] = None) -> ObjectionResponse:
    definition = _OBJECTION_DEFS.get(objection_key)
    if not definition:
        return ObjectionResponse(
            objection_key=objection_key,
            likely_meaning='Unrecognized objection — treat cautiously and ask a clarifying question.',
            disposition='clarify',
            response="No problem — is there something specific that would make this more useful to you?",
            follow_up_strategy='Nurture until a clearer signal emerges.',
            what_not_to_say=['any assumption about what they meant'],
        )
    return ObjectionResponse(
        objection_key=objection_key,
        likely_meaning=str(definition['likely_meaning']),
        disposition=str(definition['disposition']),
        response=str(definition['response']),
        follow_up_strategy=str(definition['follow_up_strategy']),
        what_not_to_say=list(definition['what_not_to_say']),
    )


def objection_playbook(context: Optional[SalesLeadContext] = None) -> List[ObjectionResponse]:
    """The full set of objection responses, for the Outreach Workbench's
    'objection/resistance guidance' panel."""
    return [handle_objection(key, context) for key in OBJECTION_KEYS]
