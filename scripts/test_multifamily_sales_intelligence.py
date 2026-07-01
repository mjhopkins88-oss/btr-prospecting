#!/usr/bin/env python
"""
NEPQ-based Sales Intelligence Engine tests.

Covers strategy selection per scenario (renewal/acquisition/refinance/
construction/completion/permit-news/nurture), resistance softening,
objection responses (question-led, not rebuttals/brochure-dumps),
prohibited-phrase guardrails, and reasoning-explainer completeness.
Plain assert-based script (matches the repo's existing test_*.py
convention) — no pytest dependency, no Flask import needed (this exercises
the sales_intelligence package directly, mirroring how other
scripts/test_multifamily_*.py scripts avoid importing api/routes).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.types import (
    MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, MultifamilyLead, new_id,
)
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.sales_intelligence.nepq_types import SalesLeadContext
from multifamily.sales_intelligence.lead_context_builder import build_lead_context
from multifamily.sales_intelligence.conversation_strategy_engine import select_strategy, _apply_resistance_softening
from multifamily.sales_intelligence.question_path_engine import build_question_path
from multifamily.sales_intelligence.message_strategy_engine import build_message_package, contains_prohibited_phrase
from multifamily.sales_intelligence.objection_strategy_engine import handle_objection, objection_playbook
from multifamily.sales_intelligence.reasoning_explainer import build_reasoning
from multifamily.sales_intelligence.engine import build_sales_intelligence
from multifamily import repository

_FAILURES = []
_M = '(NEPQ TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def mk_lead(company, signal_type, source, lead_situation=None, pain=None, contact_title=None,
           email='ops@example.com', renewal_days=None, state='TX', city='Austin'):
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=f'{company} {_M} Property', state=state, city=city,
                            asset_type='garden', unit_count=150)
    detail = {}
    if lead_situation:
        detail['lead_situation'] = lead_situation
    if renewal_days is not None:
        detail['days_until_renewal'] = renewal_days
        detail['self_reported'] = True
    contacts = [MultifamilyContact(id=new_id(), full_name='Sam Rivera', title=contact_title, email=email)]
    signals = [MultifamilySignal(id=new_id(), signal_type=signal_type, source=source, detail=detail)]
    lead = MultifamilyLead(
        id=new_id(), company=c, property=p, signals=signals, contacts=contacts, state=state, city=city,
        primary_signal_type=signal_type, primary_source=source, is_demo=False, pain_flags=(pain or []),
    )
    lead.score = score_lead(lead)
    return lead


def build_pkg(lead, **kwargs):
    return build_sales_intelligence(lead, log=False, **kwargs)


# ---- 1. Inbound benchmark lead -> connection, then situation/problem awareness ----

def test_inbound_benchmark_selects_connection_then_discovery():
    lead = mk_lead('Benchflow Partners', 'benchmark_form_submit', 'benchmark_form', lead_situation='benchmark')
    pkg = build_pkg(lead)
    check('starts in connection stage', pkg.strategy.starting_nepq_stage == 'connection')
    check('question path includes situation questions', len(pkg.question_path.situation_questions) > 0)
    check('question path includes problem-awareness questions', len(pkg.question_path.problem_awareness_questions) > 0)
    check('does not present up front', pkg.strategy.should_present is False)


# ---- 2. Renewal within 120 days -> renewal pressure strategy ----

def test_renewal_within_120_selects_renewal_pressure():
    lead = mk_lead('Renewflow Group', 'renewal_date_known', 'form', lead_situation='renewal', renewal_days=45,
                  pain=['premium_increase'])
    pkg = build_pkg(lead)
    check('rule applied is renewal-within-120', pkg.reasoning.selected_strategy == 'Renewal-window pressure')
    check('starting stage is situation', pkg.strategy.starting_nepq_stage == 'situation')
    check('scenario reflects renewal/premium pressure', pkg.context.insurance_scenario in ('renewal_pressure', 'premium_increase'))
    all_questions = pkg.question_path.situation_questions + pkg.question_path.problem_awareness_questions
    check('question path covers renewal/premium/market themes',
          any(kw in q.lower() for q in all_questions for kw in ('renewal', 'market', 'premium')))


# ---- 3. Acquisition lead -> underwriting/insurance assumption strategy ----

def test_acquisition_selects_underwriting_strategy():
    lead = mk_lead('Acqflow Capital', 'acquisition', 'crm', lead_situation='acquisition')
    pkg = build_pkg(lead)
    check('rule applied is acquisition diligence', pkg.reasoning.selected_strategy == 'Acquisition due-diligence validation')
    check('starting stage is situation', pkg.strategy.starting_nepq_stage == 'situation')
    check('recommended action asks for program details', pkg.strategy.recommended_action in ('ask_for_current_program_details', 'call_now'))
    check('question path references seller/underwriting assumptions',
          any('seller' in q.lower() or 'underwrit' in q.lower() for q in pkg.question_path.situation_questions))


# ---- 4. Refinance/lender lead -> lender compliance strategy ----

def test_refinance_selects_lender_compliance_strategy():
    lead = mk_lead('Refiflow Holdings', 'refinance', 'crm', lead_situation='refinance', pain=['lender_requirement'])
    pkg = build_pkg(lead)
    check('rule applied is refinance/lender', pkg.reasoning.selected_strategy == 'Refinance / lender-condition check')
    check('starting stage is situation', pkg.strategy.starting_nepq_stage == 'situation')
    check('question path references lender conditions',
          any('lender' in q.lower() for q in pkg.question_path.situation_questions))


# ---- 5. Construction/builder's risk lead -> builder's risk strategy ----

def test_construction_selects_builders_risk_strategy():
    lead = mk_lead('Constructflow LLC', 'groundbreaking', 'manual', lead_situation='construction',
                   pain=['builders_risk_need'])
    pkg = build_pkg(lead)
    check('rule applied is construction/builders risk', pkg.reasoning.selected_strategy == "Construction / builder's risk placement")
    check('starting stage is situation', pkg.strategy.starting_nepq_stage == 'situation')
    check("question path references builder's risk placement",
          any("builder's risk" in q.lower() or 'bound' in q.lower() for q in pkg.question_path.situation_questions))


# ---- 6. Completion/lease-up lead -> transition strategy ----

def test_completion_selects_transition_strategy():
    lead = mk_lead('Compflow Estates', 'completion', 'manual', lead_situation='operating')
    pkg = build_pkg(lead)
    check('rule applied is completion/lease-up', pkg.reasoning.selected_strategy == 'Completion / lease-up transition')
    check('starting stage is situation', pkg.strategy.starting_nepq_stage == 'situation')
    check('question path references transition/lease-up',
          any('transition' in q.lower() or 'lease-up' in q.lower() for q in pkg.question_path.situation_questions))


# ---- 7. Permit/news-only lead -> soft relevance check, not aggressive pitch ----

def test_permit_news_only_gets_soft_relevance_check():
    lead = mk_lead('Permitflow Development', 'permit_filed', 'permit')
    pkg = build_pkg(lead)
    check('rule applied is trigger-only soft relevance check', pkg.reasoning.selected_strategy == 'Trigger-only — soft relevance check')
    check('recommended action is nurture, not a pitch', pkg.strategy.recommended_action == 'nurture')
    check('does not present', pkg.strategy.should_present is False)
    check('does not call now', pkg.strategy.call_now is False)
    check('resistance risk is high', pkg.context.resistance_risk == 'high')
    check('do-not list warns against assuming they need help',
          any('assume' in d.lower() for d in pkg.strategy.do_not))


# ---- 8. Nurture/watchlist lead -> low-pressure timing follow-up ----

def test_nurture_lead_gets_low_pressure_followup():
    # portfolio_growth/manual with no lead_situation/pain flags -> scenario
    # stays 'unknown' and origin stays 'manual' (not website_intent), so
    # this genuinely has no active discovery thread — the case rule 9 is
    # actually for, as opposed to a low-scoring-but-identifiable scenario.
    lead = mk_lead('Watchflow Realty', 'portfolio_growth', 'manual')
    lead.score.category = 'watchlist'  # force nurture bucket regardless of raw score
    pkg = build_pkg(lead)
    check('rule applied is nurture/watchlist', pkg.reasoning.selected_strategy == 'Nurture / watchlist — no pitch')
    check('recommended action is nurture', pkg.strategy.recommended_action == 'nurture')
    check('does not move toward next step', pkg.strategy.move_toward_next_step is False)
    check('commitment question is low-pressure (permission-based)',
          'no pressure' in pkg.question_path.commitment_question.lower())


# ---- 9. High resistance-risk lead -> shorter/softer language ----

def test_high_resistance_softens_language():
    ctx = SalesLeadContext(lead_id='x', company_name='Test Co', is_demo=False,
                           lead_temperature='call_today', lead_origin='benchmark_request',
                           insurance_scenario='renewal_pressure', buyer_awareness_level='solution_aware',
                           resistance_risk='high')
    strategy = select_strategy(ctx)
    check('high resistance forces call_now off', strategy.call_now is False)
    check('high resistance forces action away from call_now', strategy.recommended_action != 'call_now')
    check('tone mentions keeping it short', 'short' in strategy.recommended_tone.lower())
    check('do-not list gets high-resistance additions', any('one question' in d.lower() for d in strategy.do_not))


# ---- 10. Already-have-broker objection -> question-led, not a rebuttal ----

def test_already_have_broker_is_question_led():
    resp = handle_objection('already_have_broker')
    check('disposition is clarify (not disengage/argue)', resp.disposition == 'clarify')
    check('response asks a question, not a rebuttal', resp.response.strip().endswith('?'))
    check('does not criticize the incumbent broker', 'bad' not in resp.response.lower() and 'worse' not in resp.response.lower())
    check('what_not_to_say warns against criticizing the incumbent',
          any('incumbent' in w.lower() or 'broker' in w.lower() for w in resp.what_not_to_say))


# ---- 11. Send-me-info objection -> clarifying, not a brochure dump ----

def test_send_me_info_is_clarifying_not_brochure():
    resp = handle_objection('send_me_information')
    check('disposition is clarify', resp.disposition == 'clarify')
    check('response asks what would be useful (not a data dump)', resp.response.strip().endswith('?'))
    check('what_not_to_say warns against a generic brochure', any('brochure' in w.lower() for w in resp.what_not_to_say))


def test_objection_playbook_covers_all_keys():
    playbook = objection_playbook()
    check('playbook covers all 14 objection keys', len(playbook) == 14)
    check('every objection has a disposition and response', all(o.disposition and o.response for o in playbook))


# ---- 12. Message generator avoids prohibited phrases / aggressive claims ----

def test_messages_avoid_prohibited_phrases():
    scenarios = [
        ('Prohibflow Renewal', 'renewal_date_known', 'form', 'renewal', ['premium_increase'], 30),
        ('Prohibflow Acq', 'acquisition', 'crm', 'acquisition', [], None),
        ('Prohibflow Refi', 'refinance', 'crm', 'refinance', ['lender_requirement'], None),
        ('Prohibflow Construction', 'groundbreaking', 'manual', 'construction', ['builders_risk_need'], None),
        ('Prohibflow Completion', 'completion', 'manual', 'operating', [], None),
        ('Prohibflow Permit', 'permit_filed', 'permit', None, [], None),
    ]
    all_clean = True
    for company, sig, src, situation, pain, renewal_days in scenarios:
        lead = mk_lead(company, sig, src, lead_situation=situation, pain=pain, renewal_days=renewal_days)
        for variant in (0, 1):
            pkg = build_pkg(lead, variant=variant)
            fields = [
                pkg.messages.call_opener, pkg.messages.first_email_subject, pkg.messages.first_email_body,
                pkg.messages.linkedin_note_manual, pkg.messages.follow_up_1, pkg.messages.follow_up_2,
                pkg.messages.soft_bump, pkg.messages.meeting_confirmation_note, pkg.messages.info_request_note,
            ]
            for f in fields:
                hit = contains_prohibited_phrase(f)
                if hit:
                    all_clean = False
                    print(f'    -> prohibited phrase "{hit}" found in: {f}')
    check('no generated message contains a prohibited phrase, across scenarios/variants', all_clean)

    # Also check objection responses.
    all_obj_clean = all(contains_prohibited_phrase(o.response) is None for o in objection_playbook())
    check('objection responses contain no prohibited phrases', all_obj_clean)


def test_regenerate_produces_a_different_variant():
    lead = mk_lead('Variantflow Group', 'benchmark_form_submit', 'benchmark_form', lead_situation='benchmark')
    pkg0 = build_pkg(lead, variant=0)
    pkg1 = build_pkg(lead, variant=1)
    check('variant 1 produces different message text than variant 0', pkg0.messages.call_opener != pkg1.messages.call_opener)
    check('strategy/stage stay consistent across variants (only copy rotates)',
          pkg0.strategy.starting_nepq_stage == pkg1.strategy.starting_nepq_stage)


# ---- 13. Reasoning explainer completeness ----

def test_reasoning_explainer_completeness():
    lead = mk_lead('Reasonflow Partners', 'renewal_date_known', 'form', lead_situation='renewal', renewal_days=60,
                   pain=['deductible_concern'], contact_title='VP of Risk')
    pkg = build_pkg(lead)
    r = pkg.reasoning
    check('has selected_strategy', bool(r.selected_strategy))
    check('has selected_nepq_stage', bool(r.selected_nepq_stage))
    check('has why_this_stage', bool(r.why_this_stage))
    check('has why_this_message', bool(r.why_this_message))
    check('has key_lead_signals_used', len(r.key_lead_signals_used) > 0)
    check('has assumed_pain_points', len(r.assumed_pain_points) > 0)
    check('has missing_information', len(r.missing_information) > 0)
    check('has what_to_avoid', len(r.what_to_avoid) > 0)
    check('confidence_score is a float in [0,1]', isinstance(r.confidence_score, float) and 0.0 <= r.confidence_score <= 1.0)
    check('has recommended_next_step', bool(r.recommended_next_step))
    check('decision-maker title reflected in signals or context', pkg.context.likely_decision_maker_type is not None)


# ---- Persistence: decision log dedup + explicit regenerate ----

def test_decision_log_dedup_and_regenerate():
    lead = mk_lead('Logflow Partners', 'benchmark_form_submit', 'benchmark_form', lead_situation='benchmark')
    _ids.append(lead.id)
    pkg1 = build_sales_intelligence(lead)  # log=True by default
    hist1 = repository.get_sales_intelligence_history(lead.id)
    check('first computation logs one event', len(hist1) == 1)

    pkg2 = build_sales_intelligence(lead)  # identical context -> should NOT log again
    hist2 = repository.get_sales_intelligence_history(lead.id)
    check('identical re-computation does not duplicate the log', len(hist2) == 1)

    pkg3 = build_sales_intelligence(lead, variant=1)  # explicit regenerate -> logs again
    hist3 = repository.get_sales_intelligence_history(lead.id)
    check('explicit regenerate (variant>0) logs a new event', len(hist3) == 2)


def test_demo_leads_never_logged():
    from multifamily.pipeline import run_pipeline
    leads, _ = run_pipeline()
    demo = next(l for l in leads if l.is_demo)
    pkg = build_sales_intelligence(demo)
    check('demo lead still gets a full package', pkg.strategy is not None and pkg.messages is not None)
    check('demo lead never gets a decision logged', repository.get_sales_intelligence_history(demo.id) == [])


def main():
    try:
        test_inbound_benchmark_selects_connection_then_discovery()
        test_renewal_within_120_selects_renewal_pressure()
        test_acquisition_selects_underwriting_strategy()
        test_refinance_selects_lender_compliance_strategy()
        test_construction_selects_builders_risk_strategy()
        test_completion_selects_transition_strategy()
        test_permit_news_only_gets_soft_relevance_check()
        test_nurture_lead_gets_low_pressure_followup()
        test_high_resistance_softens_language()
        test_already_have_broker_is_question_led()
        test_send_me_info_is_clarifying_not_brochure()
        test_objection_playbook_covers_all_keys()
        test_messages_avoid_prohibited_phrases()
        test_regenerate_produces_a_different_variant()
        test_reasoning_explainer_completeness()
        test_decision_log_dedup_and_regenerate()
        test_demo_leads_never_logged()
    finally:
        for lid in _ids:
            repository.delete_sales_intelligence_events_for_lead(lid)
        print(f'\nCleaned up sales-intelligence log rows for {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All NEPQ sales-intelligence tests passed.')


if __name__ == '__main__':
    main()
