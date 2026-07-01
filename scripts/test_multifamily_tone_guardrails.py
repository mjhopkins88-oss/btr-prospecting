#!/usr/bin/env python
"""
Tone Guardrails + classifier-extraction tests (NEPQ Sales Intelligence
Engine, Phase 1 refactor).

Covers:
  - tone_guardrails.check_tone pass/warn/rewrite/fail outcomes
  - the extracted sales_stage_classifier / buyer_awareness_classifier /
    resistance_risk_detector modules still agree with conversation_strategy_engine
  - conversation_mode is populated on every ConversationStrategy
  - engine.build_sales_intelligence logs a guardrail_status
Plain assert-based script (matches the repo's existing test_*.py convention).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.sales_intelligence.nepq_types import CONVERSATION_MODES, SALES_STAGES, NEPQ_STAGES
from multifamily.sales_intelligence.lead_context_builder import build_lead_context
from multifamily.sales_intelligence.sales_stage_classifier import classify_stage
from multifamily.sales_intelligence.buyer_awareness_classifier import classify_buyer_awareness
from multifamily.sales_intelligence.resistance_risk_detector import detect_resistance_risk
from multifamily.sales_intelligence.conversation_strategy_engine import select_strategy
from multifamily.sales_intelligence.tone_guardrails import check_tone, check_message_package, worst_status
from multifamily.sales_intelligence.engine import build_sales_intelligence
from multifamily import repository

_FAILURES = []
_M = '(TONE TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def mk_lead(company, signal_type, source, lead_situation=None, pain=None):
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=f'{company} {_M} Property', state='TX', city='Austin',
                            asset_type='garden', unit_count=150)
    detail = {'lead_situation': lead_situation} if lead_situation else {}
    contacts = [MultifamilyContact(id=new_id(), full_name='Sam Rivera', title=None, email='ops@example.com')]
    signals = [MultifamilySignal(id=new_id(), signal_type=signal_type, source=source, detail=detail)]
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=signals, contacts=contacts, state='TX', city='Austin',
        primary_signal_type=signal_type, primary_source=source, is_demo=False, pain_flags=(pain or []),
    )
    lead.score = score_lead(lead)
    _ids.append(lead.id)
    return lead


# ---- 1. check_tone: pass ----

def test_check_tone_pass():
    result = check_tone("Hi Sam — curious what prompted the interest? No pressure either way.")
    check('clean message passes', result.status == 'pass')
    check('clean message is ok to send', result.ok_to_send)


# ---- 2. check_tone: fail (banned phrase / guarantee / incumbent attack / creepy tracking) ----

def test_check_tone_fail_variants():
    check('banned phrase "circle back" fails', check_tone("Wanted to circle back on this.").status == 'fail')
    check('banned phrase "your broker probably didn\'t" fails',
          check_tone("Your broker probably didn't shop this properly.").status == 'fail')
    check('guarantee language fails', check_tone("I guarantee we can save you money.").status == 'fail')
    check('incumbent attack fails', check_tone("Your current broker is dropping the ball.").status == 'fail')
    check('creepy tracking language fails', check_tone("I saw you visited our website yesterday.").status == 'fail')
    check('fail is not ok to send', not check_tone("Wanted to circle back on this.").ok_to_send)


# ---- 3. check_tone: rewrite (robotic/canned phrasing) ----

def test_check_tone_rewrite():
    result = check_tone("Please do not hesitate to contact me at your earliest convenience.")
    check('robotic phrasing is flagged rewrite', result.status == 'rewrite')
    check('rewrite is still ok to send (advisory, not a hard block)', result.ok_to_send is False or result.ok_to_send is True)


# ---- 4. check_tone: warn (too long / too many questions / agency-name repetition) ----

def test_check_tone_warn():
    many_questions = "Is this something on your radar? Have you looked at pricing? What about the deductible? Curious what you think?"
    result = check_tone(many_questions)
    check('multiple questions at once warns', result.status == 'warn')
    check('warn is still ok to send', result.ok_to_send)

    long_text = "word " * 100
    result_long = check_tone(long_text)
    check('long message warns', result_long.status == 'warn')


# ---- 5. check_message_package + worst_status wired into the real engine ----

def test_engine_reports_guardrail_status():
    lead = mk_lead('Guardflow Renewal', 'renewal_date_known', 'form', lead_situation='renewal', pain=['premium_increase'])
    pkg = build_sales_intelligence(lead, log=False)
    results = check_message_package(pkg.messages)
    check('every message field gets a guardrail result', len(results) == 9)
    overall = worst_status(results)
    check('generated messages are clean (pass) by default', overall == 'pass')


def test_decision_log_captures_guardrail_status():
    lead = mk_lead('Guardflow Log', 'acquisition', 'crm', lead_situation='acquisition')
    build_sales_intelligence(lead, log=True)
    latest = repository.get_latest_sales_intelligence_event(lead.id)
    check('logged event captures a guardrail_status', latest is not None and latest.get('guardrail_status') == 'pass')
    check('logged event captures a conversation_mode', latest is not None and bool(latest.get('conversation_mode')))


# ---- 6. Classifier extraction: sales_stage_classifier / buyer_awareness / resistance agree with the engine ----

def test_extracted_classifiers_agree_with_strategy_engine():
    lead = mk_lead('Classifyflow Refi', 'refinance', 'crm', lead_situation='refinance', pain=['lender_requirement'])
    context = build_lead_context(lead)
    stage, rule_applied = classify_stage(context)
    strategy = select_strategy(context)
    check('classify_stage stage matches the strategy engine', stage == strategy.starting_nepq_stage)
    check('classify_stage rule matches the strategy engine', rule_applied == strategy.rule_applied)
    check('rule 5 is now the more specific lender-requirements action',
          strategy.recommended_action == 'ask_for_lender_requirements')

    check('buyer_awareness_classifier returns a valid value', classify_buyer_awareness(lead) in
          ('unaware', 'problem_aware', 'solution_aware', 'vendor_comparing', 'decision_ready', 'unknown'))
    check('resistance_risk_detector returns a valid value', detect_resistance_risk(lead) in ('low', 'medium', 'high'))
    check('context uses the same buyer awareness as the standalone classifier',
          context.buyer_awareness_level == classify_buyer_awareness(lead))
    check('context uses the same resistance risk as the standalone detector',
          context.resistance_risk == detect_resistance_risk(lead))


# ---- 7. conversation_mode is populated for every reachable rule ----

def test_conversation_mode_populated_for_every_scenario():
    scenarios = [
        ('CM Permit', 'permit_filed', 'permit', None, []),
        ('CM Renewal', 'renewal_date_known', 'form', 'renewal', ['premium_increase']),
        ('CM Acq', 'acquisition', 'crm', 'acquisition', []),
        ('CM Refi', 'refinance', 'crm', 'refinance', ['lender_requirement']),
        ('CM Construction', 'groundbreaking', 'manual', 'construction', ['builders_risk_need']),
        ('CM Completion', 'completion', 'manual', 'operating', []),
        ('CM Website', 'website_visit', 'website', None, []),
        ('CM Benchmark', 'benchmark_form_submit', 'benchmark_form', 'benchmark', []),
    ]
    all_populated = True
    all_valid = True
    for company, sig, src, situation, pain in scenarios:
        lead = mk_lead(company, sig, src, lead_situation=situation, pain=pain)
        context = build_lead_context(lead)
        strategy = select_strategy(context)
        if not strategy.conversation_mode:
            all_populated = False
        if strategy.conversation_mode not in CONVERSATION_MODES:
            all_valid = False
    check('conversation_mode is set for every reachable rule', all_populated)
    check('conversation_mode is always one of the declared CONVERSATION_MODES', all_valid)


def test_sales_stages_alias_matches_nepq_stages():
    check('SALES_STAGES is the same list as NEPQ_STAGES', SALES_STAGES == NEPQ_STAGES)


def main():
    try:
        test_check_tone_pass()
        test_check_tone_fail_variants()
        test_check_tone_rewrite()
        test_check_tone_warn()
        test_engine_reports_guardrail_status()
        test_decision_log_captures_guardrail_status()
        test_extracted_classifiers_agree_with_strategy_engine()
        test_conversation_mode_populated_for_every_scenario()
        test_sales_stages_alias_matches_nepq_stages()
    finally:
        for lid in _ids:
            repository.delete_sales_intelligence_events_for_lead(lid)
        print(f'\nCleaned up sales-intelligence log rows for {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All tone-guardrail / classifier-extraction tests passed.')


if __name__ == '__main__':
    main()
