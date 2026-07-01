"""
Tone Guardrails — a dedicated pass over generated outreach copy that
catches language that would sound pushy, robotic, salesy, or creepy
before it reaches a human sender. Runs AFTER message_strategy_engine
generates a MessagePackage; this module never generates or rewrites
copy itself — it only judges it.

Outcomes (worst wins if multiple issues are found):
  - fail:    a hard-rule violation — banned phrase, guaranteed-savings
             claim, incumbent-broker attack, or creepy tracking language.
             Must not be sent as-is.
  - rewrite: robotic/canned phrasing that reads like a mail-merge template.
             Not a policy violation, but should be reworded before sending.
  - warn:    borderline — too long, too many questions at once, or the
             agency name mentioned more than once. Still safe to send.
  - pass:    nothing flagged.
"""
import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List

from multifamily.sales_intelligence.message_strategy_engine import PROHIBITED_PHRASES as _GENERATION_TIME_PHRASES
from multifamily.sales_intelligence.nepq_types import MessagePackage

# Superset of the generation-time banned-phrase list (message_strategy_engine.py),
# extended with phrases specific to this guardrail pass.
PROHIBITED_PHRASES = list(_GENERATION_TIME_PHRASES) + [
    "circle back",
    "your broker probably didn't",
]

_INCUMBENT_ATTACK_PHRASES = [
    "your current broker is", "your broker dropped the ball", "your broker missed",
    "your broker probably didn't", "unlike your broker", "your broker isn't doing",
    "your broker failed",
]

_GUARANTEE_PHRASES = [
    "guarantee", "guaranteed savings", "we will save you", "promise to save",
]

_CREEPY_TRACKING_PHRASES = [
    "i saw you visited", "i saw that you visited", "i noticed you visited",
    "i noticed you were on our site", "our tracking shows", "our analytics show",
    "i can see you looked at", "i can see you've been on our site",
]

_ROBOTIC_PHRASES = [
    "i am writing to inform you", "please do not hesitate to contact me",
    "at your earliest convenience", "per my last email", "as per our conversation",
    "kindly revert", "please find attached",
]

_MAX_WORDS_SOFT = 90
_MAX_QUESTIONS_SOFT = 1


@dataclass
class GuardrailResult:
    status: str  # 'pass' | 'warn' | 'rewrite' | 'fail'
    reasons: List[str] = field(default_factory=list)

    @property
    def ok_to_send(self) -> bool:
        return self.status in ('pass', 'warn')


def check_tone(text: str) -> GuardrailResult:
    """Evaluate a single generated message string. Does not mutate the
    text — callers decide what to do with a 'rewrite'/'fail' result
    (regenerate a variant, block send, surface a warning in the UI)."""
    if not text:
        return GuardrailResult(status='pass')

    lowered = text.lower()
    fail_reasons: List[str] = []
    rewrite_reasons: List[str] = []
    warn_reasons: List[str] = []

    for phrase in PROHIBITED_PHRASES:
        if phrase in lowered:
            fail_reasons.append(f'contains a banned phrase: "{phrase}"')
    for phrase in _INCUMBENT_ATTACK_PHRASES:
        if phrase in lowered:
            fail_reasons.append(f'attacks the incumbent broker: "{phrase}"')
    for phrase in _GUARANTEE_PHRASES:
        if phrase in lowered:
            fail_reasons.append(f'claims a guaranteed outcome: "{phrase}"')
    for phrase in _CREEPY_TRACKING_PHRASES:
        if phrase in lowered:
            fail_reasons.append(f'references website tracking in a creepy way: "{phrase}"')

    if fail_reasons:
        return GuardrailResult(status='fail', reasons=fail_reasons)

    for phrase in _ROBOTIC_PHRASES:
        if phrase in lowered:
            rewrite_reasons.append(f'reads like a canned template: "{phrase}"')

    if rewrite_reasons:
        return GuardrailResult(status='rewrite', reasons=rewrite_reasons)

    word_count = len(text.split())
    if word_count > _MAX_WORDS_SOFT:
        warn_reasons.append(f'message is long ({word_count} words) — consider tightening')

    question_count = text.count('?')
    if question_count > _MAX_QUESTIONS_SOFT:
        warn_reasons.append(f'asks {question_count} questions at once — lead with one')

    if lowered.count('alkeme') > 1:
        warn_reasons.append('mentions the agency name more than once — let the question carry it')

    if warn_reasons:
        return GuardrailResult(status='warn', reasons=warn_reasons)

    return GuardrailResult(status='pass')


def check_message_package(messages: MessagePackage) -> Dict[str, GuardrailResult]:
    """Runs check_tone over every field of a generated MessagePackage,
    keyed by field name."""
    return {
        f.name: check_tone(getattr(messages, f.name))
        for f in dataclasses.fields(messages)
    }


def worst_status(results: Dict[str, GuardrailResult]) -> str:
    """Collapse a per-field result map to a single overall status —
    worst outcome wins (fail > rewrite > warn > pass)."""
    order = {'fail': 3, 'rewrite': 2, 'warn': 1, 'pass': 0}
    if not results:
        return 'pass'
    return max(results.values(), key=lambda r: order[r.status]).status
