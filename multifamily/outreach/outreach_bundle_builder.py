"""
Outreach Workbench message bundle (Part 6).

For a single lead, produce a full, ready-to-use set of manual outreach
drafts: a call opener, a first email, a LinkedIn note (manual send only),
two follow-ups, a soft "not sure if this is relevant" bump, and a set of
discovery questions — all tuned to the lead's process stage.

Tone rules (strict): neutral, calm, curious, benchmark-oriented, not
pushy, NO exaggerated savings claims, NO fake familiarity (we only use a
first name if we actually have it, and never imply a prior relationship).
This module NEVER sends anything — it only drafts copy for a human.
"""
from typing import Any, Dict, List, Optional

from multifamily.types import MultifamilyLead
from multifamily.outreach.nepq_multifamily_angle_builder import build_angle
from multifamily.timing.process_stage_types import ProcessStageResult
from multifamily.timing.process_stage_detector import detect_process_stage
from multifamily.forms.form_variants import form_variant_for_offer_type, FormVariant

# Stage-specific discovery questions. Falls back to a neutral default set.
_DISCOVERY_QUESTIONS = {
    'renewal_window': [
        "How far ahead of renewal do you usually like to have options in hand?",
        "Is the current broker already running the marketing process, or is that still open?",
        "Is the property schedule (values, deductibles) current, or carrying last year's numbers?",
        "Anything from last renewal — pricing, deductibles, exclusions — you'd want handled differently?",
    ],
    'acquisition_due_diligence': [
        "Are you underwriting off the seller's current insurance numbers, or pricing it independently?",
        "What's the timeline to close, and when do you need insurance certainty by?",
        "Is this going into an existing program, or standing up coverage on its own?",
        "Any lender insurance requirements driving the structure?",
    ],
    'refinance_or_financing': [
        "Are the lender insurance requirements already cleared, or still open?",
        "Which items are still in motion — property, GL, excess, deductibles, exclusions, escrow?",
        "What's the financing timeline you're working back from?",
    ],
    'construction_loan_closing': [
        "Has builder's risk been bound yet, or is that still open?",
        "When does construction actually start, and who owns the builder's risk decision?",
        "Is there a lender requirement shaping the coverage?",
        "Have you mapped the hand-off from builder's risk to operating coverage at completion?",
    ],
    'construction_start': [
        "Has builder's risk been bound yet, or is that still open?",
        "Who owns the builder's risk decision, and is there a lender requirement behind it?",
        "Have you thought about the transition to operating coverage at completion?",
    ],
    'entitlement_or_permit': [
        "How firm is the construction timeline at this point?",
        "Is financing in place yet, or still being arranged?",
        "When would builder's risk realistically need to be locked in?",
    ],
    'completion_or_lease_up': [
        "Where are you in the transition from builder's risk to operating property + GL?",
        "What's the lease-up timeline, and when does the operating program need to be live?",
        "Is GL/excess structured for the occupancy ramp?",
    ],
    'post_renewal': [
        "Did this renewal land cleanly enough that you'd run it the same way next year?",
        "Anything you'd want to handle earlier or differently next cycle?",
    ],
}
_DEFAULT_DISCOVERY_QUESTIONS = [
    "What prompted you to look into this now?",
    "What's working — and not working — with the current program?",
    "When does the current policy renew?",
    "Who else is involved in the insurance decision?",
]


def _first_name(lead: MultifamilyLead) -> Optional[str]:
    contact = lead.contacts[0] if lead.contacts else None
    if contact and contact.full_name:
        token = contact.full_name.strip().split()[0]
        # Skip mock/obvious-non-name tokens but never invent one.
        return token
    return None


def _greeting(lead: MultifamilyLead) -> str:
    name = _first_name(lead)
    return f"Hi {name}" if name else "Hi there"


def _deliverable_for_lead(lead: MultifamilyLead) -> Optional[FormVariant]:
    """Section 8 item 5 — resolve the lead's matched offer deliverable
    (if any) so generated copy can reference a concrete artifact instead
    of speaking generically. Most leads still have no offer_type (e.g.
    older submissions, manual adds) — those keep the prior generic
    phrasing untouched, so this is purely additive."""
    if not lead.offer_type:
        return None
    return form_variant_for_offer_type(lead.offer_type)


def build_outreach_bundle(lead: MultifamilyLead, stage_result: Optional[ProcessStageResult] = None) -> Dict[str, Any]:
    stage_result = stage_result or detect_process_stage(lead)
    angle = stage_result.recommended_message_angle
    hook = build_angle(lead)  # neutral benchmark hook
    greeting = _greeting(lead)
    company = lead.company.name
    state = lead.state or 'your market'
    deliverable = _deliverable_for_lead(lead)

    call_opener = (
        f"{greeting} — thanks for taking a second. I work with multifamily owners and operators "
        f"on insurance benchmarking, and I'm not calling to pitch anything. {angle} "
        f"Would a quick, no-obligation read be useful, or is this bad timing?"
    )

    if deliverable:
        offer_paragraph = (
            f"No obligation either way — if it's useful, I'll put together a {deliverable.deliverable_name} "
            f"so you've got something concrete to look at. If the timing's off, just let me know."
        )
    else:
        offer_paragraph = (
            f"No obligation either way — if it's useful, I'm happy to share what we're seeing across "
            f"comparable {state} multifamily risk this year. If the timing's off, just let me know."
        )

    email_draft = {
        'subject': f"Quick multifamily insurance benchmark — {company}",
        'body': (
            f"{greeting},\n\n"
            f"{hook}\n\n"
            f"{angle}\n\n"
            f"{offer_paragraph}\n\n"
            f"Best,\n[Your name]"
        ),
    }

    linkedin_draft = (
        f"{greeting} — I work with multifamily owners/operators on insurance benchmarking "
        f"(property, GL, excess, deductibles). {angle} No pitch — happy to share what we're seeing "
        f"if it's useful."
    )

    follow_up_1 = (
        f"{greeting} — circling back on this in case it slipped by. {angle} "
        f"Totally fine if now isn't the moment; just let me know either way."
    )

    follow_up_2 = (
        f"{greeting} — last note from me on this for now. If a quick benchmark on the "
        f"{company} program would be useful down the line, I'm around. Otherwise I'll leave it with you."
    )

    soft_bump = (
        f"{greeting} — not sure if this is even relevant to you right now, so feel free to ignore. "
        f"If pressure-testing the current insurance structure is on your radar at all, happy to help; "
        f"if not, no worries at all."
    )

    discovery_questions = list(_DISCOVERY_QUESTIONS.get(stage_result.process_stage, _DEFAULT_DISCOVERY_QUESTIONS))

    offer_deliverable = None
    if deliverable:
        offer_deliverable = {
            'page_variant': deliverable.slug,
            'deliverable_name': deliverable.deliverable_name,
            'deliverable_description': deliverable.deliverable_description,
            'required_inputs': deliverable.required_inputs,
            'artifact_type': deliverable.artifact_type,
            'turnaround_promise': deliverable.turnaround_promise,
        }

    return {
        'process_stage': stage_result.process_stage,
        'recommended_message_angle': angle,
        'call_opener': call_opener,
        'email_draft': email_draft,
        'linkedin_draft': linkedin_draft,
        'follow_up_1': follow_up_1,
        'follow_up_2': follow_up_2,
        'soft_bump': soft_bump,
        'discovery_questions': discovery_questions,
        # Section 8 item 5 — the concrete artifact this lead's copy
        # references, if their offer_type matched a known page variant.
        # None for leads with no offer_type (generic phrasing above).
        'offer_deliverable': offer_deliverable,
    }
