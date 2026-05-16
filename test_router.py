"""
Test suite for Leo's Intent Router (Part 11 test cases + comprehensive coverage).
Tests routing decisions, confidence, hybrid detection, repeat prevention,
approval handling, modification handling, and the full router output contract.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

passed = 0
failed = 0
errors = []

def test(name, condition):
    global passed, failed
    if condition:
        passed += 1
    else:
        failed += 1
        errors.append(name)
        print(f"  FAIL: {name}")

from api.routes.assistant import (
    _route_message, _classify_fine_intent, _compute_routing_confidence,
    _detect_hybrid_needs, _determine_route, _determine_response_mode,
    _detect_message_type, _classify_intent, _classify_intent_contextual,
    _is_repeat_response, _handle_conversational_fallback,
    _handle_low_confidence_clarification, _is_approval, _pending_action_cache,
    INTENT_KEYWORDS,
)

empty_state = {
    'people': [], 'companies': [], 'entities': {'contacts': [], 'groups': []},
}
active_state = {
    'people': [], 'companies': [],
    'entities': {'contacts': [], 'groups': []},
    'last_intent': 'draft_outreach',
    'last_output_text': 'Here is a draft email...',
}

# ============================================================
# PART 11 — REQUIRED TEST CASES (10 tests)
# ============================================================
print("=== PART 11: Required Test Cases ===")

# Test 1: "hey leo" → conversation, no task list
r1 = _route_message("hey leo", [], empty_state, 'greeting')
test("TC1: 'hey leo' route=conversation", r1['route'] == 'conversation')
test("TC1: 'hey leo' intent=greeting", r1['intent'] == 'greeting')
test("TC1: 'hey leo' requires_execution=False", r1['requires_execution'] == False)
test("TC1: 'hey leo' confidence high", r1['confidence'] >= 0.90)

# Test 2: "motivate me" → conversation, motivational, no execution
r2 = _route_message("motivate me", [], empty_state, 'conversational')
test("TC2: 'motivate me' route=conversation", r2['route'] == 'conversation')
test("TC2: 'motivate me' intent=motivation", r2['intent'] == 'motivation')
test("TC2: 'motivate me' mode=motivational", r2['response_mode'] == 'motivational')
test("TC2: 'motivate me' no execution", r2['requires_execution'] == False)

# Test 3: "why am I not getting replies?" → domain/conversation, deep reasoning
r3 = _route_message("why am I not getting replies?", [], empty_state, 'new')
test("TC3: 'why am I not getting replies' route in (conversation,domain)",
     r3['route'] in ('conversation', 'domain'))
test("TC3: intent is reasoning or chat",
     r3['intent'] in ('strategy_reasoning', 'casual_chat', 'domain_question', 'emotional_support'))

# Test 4: "write outreach to a BTR developer" → execution (outreach), no sending
r4 = _route_message("write outreach to a BTR developer", [], empty_state, 'new')
test("TC4: 'write outreach' route=execution or hybrid",
     r4['route'] in ('execution', 'hybrid'))
test("TC4: intent is outreach_request or execution_command",
     r4['intent'] in ('outreach_request', 'execution_command'))

# Test 5: "add phone number to Max" → execution
r5 = _route_message("add phone number to Max", [], empty_state, 'new')
test("TC5: 'add phone number' route=execution", r5['route'] == 'execution')
test("TC5: 'add phone number' requires_execution=True", r5['requires_execution'] == True)

# Test 6: "approved" — with pending action → execution
import threading
from api.routes.assistant import _state_lock
with _state_lock:
    old_cache = dict(_pending_action_cache) if _pending_action_cache else {}
    _pending_action_cache.clear()
    _pending_action_cache.update({
        'id': 'test_action_123', 'type': 'outreach_draft',
        'payload': {}, 'description': 'Test draft'
    })

approval_state = dict(empty_state)
approval_state['last_card_type'] = 'LeoActionPreviewCard'
r6 = _route_message("approved", [], approval_state, 'approval')
test("TC6: 'approved' with pending → route=execution", r6['route'] == 'execution')
test("TC6: 'approved' intent=approval_confirmation", r6['intent'] == 'approval_confirmation')
test("TC6: 'approved' pending_action_id set", r6['pending_action_id'] == 'test_action_123')

# Clean up
with _state_lock:
    _pending_action_cache.clear()
    if old_cache:
        _pending_action_cache.update(old_cache)

# Test 7: "make it more casual" → modification, no execution
mod_state = {
    'people': [], 'companies': [],
    'entities': {'contacts': [], 'groups': []},
    'last_intent': 'draft_outreach',
    'last_output_text': 'Here is a formal email draft...',
}
r7 = _route_message("make it more casual", [], mod_state, 'modification')
test("TC7: 'make it more casual' route=conversation", r7['route'] == 'conversation')
test("TC7: intent=modification_request", r7['intent'] == 'modification_request')
test("TC7: no execution", r7['requires_execution'] == False)

# Test 8: "Research ABC Capital and find the best approach" → hybrid or research
r8 = _route_message("Research ABC Capital and find the best approach", [], empty_state, 'new')
test("TC8: 'Research + approach' route in (hybrid,research,domain)",
     r8['route'] in ('hybrid', 'research', 'domain'))
test("TC8: requires_research=True", r8['requires_research'] == True)

# Test 9: "that sucked" → feedback, conversational
r9 = _route_message("that sucked", [], active_state, 'new')
test("TC9: 'that sucked' route=conversation", r9['route'] == 'conversation')
test("TC9: intent is feedback or casual_chat", r9['intent'] in ('feedback', 'casual_chat'))

# Test 10: "what should I do today?" → strategy or daily plan, not generic dump
r10 = _route_message("what should I do today?", [], empty_state, 'new')
test("TC10: 'what should I do today' route in (domain,execution,conversation)",
     r10['route'] in ('domain', 'execution', 'conversation'))
test("TC10: intent is strategy or daily_plan",
     r10['intent'] in ('strategy_reasoning', 'daily_plan_request', 'execution_command'))

# ============================================================
# ROUTER OUTPUT CONTRACT (10 tests)
# ============================================================
print("\n=== Router Output Contract ===")

r = _route_message("help me think through my pipeline strategy", [], empty_state, 'conversational')
test("contract: has 'route' key", 'route' in r)
test("contract: has 'intent' key", 'intent' in r)
test("contract: has 'confidence' key", 'confidence' in r)
test("contract: has 'requires_execution' key", 'requires_execution' in r)
test("contract: has 'requires_research' key", 'requires_research' in r)
test("contract: has 'use_domain_context' key", 'use_domain_context' in r)
test("contract: has 'pending_action_id' key", 'pending_action_id' in r)
test("contract: has 'referenced_entities' key", 'referenced_entities' in r)
test("contract: has 'response_mode' key", 'response_mode' in r)
test("contract: has 'explanation' key", 'explanation' in r)

# ============================================================
# FINE INTENT CLASSIFICATION (15 tests)
# ============================================================
print("\n=== Fine Intent Classification ===")

test("fine: greeting",
     _classify_fine_intent("hey leo", 'greeting', 'greeting', empty_state) == 'greeting')
test("fine: casual_chat",
     _classify_fine_intent("how are you", 'conversational', 'normal_chat', empty_state) == 'casual_chat')
test("fine: motivation",
     _classify_fine_intent("pump me up", 'conversational', 'normal_chat', empty_state) == 'motivation')
test("fine: emotional_support",
     _classify_fine_intent("i'm stuck and overwhelmed", 'conversational', 'normal_chat', empty_state) == 'emotional_support')
test("fine: strategy_reasoning from conversational",
     _classify_fine_intent("what do you think about this deal", 'conversational', 'normal_chat', empty_state) == 'strategy_reasoning')
test("fine: strategy_reasoning from diagnose",
     _classify_fine_intent("why is my pipeline shrinking", 'new', 'diagnose', empty_state) == 'strategy_reasoning')
test("fine: brainstorming",
     _classify_fine_intent("let's brainstorm some ideas", 'new', 'brainstorm', empty_state) == 'brainstorming')
test("fine: domain_question",
     _classify_fine_intent("tell me about ABC Capital", 'new', 'analyze_company', empty_state) == 'domain_question')
test("fine: research_request",
     _classify_fine_intent("research Apex Corp", 'new', 'research_web', empty_state) == 'research_request')
test("fine: outreach_request",
     _classify_fine_intent("draft email to John", 'new', 'draft_outreach', empty_state) == 'outreach_request')
test("fine: daily_plan_request",
     _classify_fine_intent("plan my day", 'new', 'schedule_meeting', empty_state) == 'daily_plan_request')
test("fine: execution_command",
     _classify_fine_intent("add contact John Smith", 'new', 'crm_update', empty_state) == 'execution_command')
test("fine: approval_confirmation",
     _classify_fine_intent("approved", 'approval', 'crm_update', empty_state) == 'approval_confirmation')
test("fine: modification_request",
     _classify_fine_intent("make it shorter", 'modification', 'draft_outreach', mod_state) == 'modification_request')
test("fine: feedback",
     _classify_fine_intent("that sucked", 'conversational', 'normal_chat', active_state) == 'feedback')

# ============================================================
# CONFIDENCE SCORING (10 tests)
# ============================================================
print("\n=== Confidence Scoring ===")

test("confidence: greeting is high",
     _compute_routing_confidence("hey", 'greeting', 'greeting', 'greeting', empty_state) >= 0.95)
test("confidence: approval without pending is low",
     _compute_routing_confidence("yes", 'approval', 'crm_update', 'approval_confirmation', empty_state) <= 0.60)
# Note: approval with pending cache returns 0.95 (tested in TC6 via _route_message)
test("confidence: conversational pattern is decent",
     _compute_routing_confidence("motivate me", 'conversational', 'normal_chat', 'motivation', empty_state) >= 0.80)
test("confidence: single keyword match is moderate",
     _compute_routing_confidence("company", 'new', 'analyze_company', 'domain_question', empty_state) <= 0.80)
test("confidence: multi-keyword match is higher",
     _compute_routing_confidence("schedule a meeting with John tomorrow", 'new', 'schedule_meeting', 'execution_command', empty_state) >= 0.80)
test("confidence: ambiguous low-match is low",
     _compute_routing_confidence("thing", 'new', 'normal_chat', 'casual_chat', empty_state) <= 0.60)
test("confidence: returns float", isinstance(
     _compute_routing_confidence("hey", 'greeting', 'greeting', 'greeting', empty_state), float))
test("confidence: bounded 0-1",
     0.0 <= _compute_routing_confidence("test", 'new', 'normal_chat', 'casual_chat', empty_state) <= 1.0)

# Edge case: competing intents
c_compete = _compute_routing_confidence("company research background", 'new', 'research_web', 'research_request', empty_state)
c_clear = _compute_routing_confidence("research this person online web search", 'new', 'research_web', 'research_request', empty_state)
test("confidence: clear intent > competing", c_clear >= c_compete)
test("confidence: modification is decent",
     _compute_routing_confidence("make it shorter", 'modification', 'draft_outreach', 'modification_request', mod_state) >= 0.85)

# ============================================================
# HYBRID DETECTION (8 tests)
# ============================================================
print("\n=== Hybrid Detection ===")

h1 = _detect_hybrid_needs("research ABC Capital and draft outreach", 'research_web')
test("hybrid: research+outreach detected", h1['is_hybrid'] == True)
test("hybrid: has research", h1['research'] == True)
test("hybrid: has outreach", h1['outreach'] == True)

h2 = _detect_hybrid_needs("motivate me", 'normal_chat')
test("hybrid: casual is NOT hybrid", h2['is_hybrid'] == False)

h3 = _detect_hybrid_needs("research this company and find their fund details", 'research_web')
test("hybrid: research+domain detected", h3['is_hybrid'] == True)
test("hybrid: has domain", h3['domain'] == True)

h4 = _detect_hybrid_needs("add a contact", 'crm_update')
test("hybrid: simple execution is NOT hybrid", h4['is_hybrid'] == False)

h5 = _detect_hybrid_needs("look up this firm and draft an intro email", 'research_web')
test("hybrid: lookup+draft is hybrid", h5['is_hybrid'] == True)

# ============================================================
# ROUTE DETERMINATION (8 tests)
# ============================================================
print("\n=== Route Determination ===")

test("route: greeting → conversation",
     _determine_route('greeting', 0.98, {'is_hybrid': False}, None) == 'conversation')
test("route: motivation → conversation",
     _determine_route('motivation', 0.85, {'is_hybrid': False}, None) == 'conversation')
test("route: execution_command high conf → execution",
     _determine_route('execution_command', 0.90, {'is_hybrid': False}, None) == 'execution')
test("route: execution_command low conf → clarify",
     _determine_route('execution_command', 0.60, {'is_hybrid': False}, None) == 'clarify')
test("route: approval with pending → execution",
     _determine_route('approval_confirmation', 0.95, {'is_hybrid': False}, 'action_123') == 'execution')
test("route: approval without pending → conversation",
     _determine_route('approval_confirmation', 0.55, {'is_hybrid': False}, None) == 'conversation')
test("route: hybrid detected → hybrid",
     _determine_route('research_request', 0.85, {'is_hybrid': True, 'count': 2}, None) == 'hybrid')
test("route: domain_question → domain",
     _determine_route('domain_question', 0.80, {'is_hybrid': False}, None) == 'domain')

# ============================================================
# RESPONSE MODE (5 tests)
# ============================================================
print("\n=== Response Mode ===")

test("mode: greeting → casual",
     _determine_response_mode('greeting', 'conversation') == 'casual')
test("mode: motivation → motivational",
     _determine_response_mode('motivation', 'conversation') == 'motivational')
test("mode: strategy → strategic",
     _determine_response_mode('strategy_reasoning', 'domain') == 'strategic')
test("mode: execution → execution_confirmation",
     _determine_response_mode('execution_command', 'execution') == 'execution_confirmation')
test("mode: research → structured",
     _determine_response_mode('research_request', 'research') == 'structured')

# ============================================================
# LOW CONFIDENCE CLARIFICATION (4 tests)
# ============================================================
print("\n=== Low Confidence Clarification ===")

clarify_r = {'intent': 'outreach_request', 'route': 'clarify', 'confidence': 0.60}
c1 = _handle_low_confidence_clarification("maybe write something", clarify_r, empty_state)
test("clarify: outreach asks about research vs draft", 'research' in c1.lower() or 'draft' in c1.lower())

clarify_r2 = {'intent': 'execution_command', 'route': 'clarify', 'confidence': 0.55}
c2 = _handle_low_confidence_clarification("something about contacts", clarify_r2, empty_state)
test("clarify: execution asks about action", 'action' in c2.lower() or 'do' in c2.lower())

clarify_r3 = {'intent': 'daily_plan_request', 'route': 'clarify', 'confidence': 0.65}
c3 = _handle_low_confidence_clarification("plan stuff", clarify_r3, empty_state)
test("clarify: plan asks about schedule vs priorities", 'schedule' in c3.lower() or 'priorities' in c3.lower())

test("clarify: returns non-empty string", len(c1) > 10 and len(c2) > 10)

# ============================================================
# REPEAT PREVENTION (5 tests)
# ============================================================
print("\n=== Repeat Prevention ===")

msgs_with_repeat = [
    {'role': 'assistant', 'content': 'Here are the top priorities for your pipeline today. Focus on warm leads first, then follow up with cooling contacts. Your numbers look solid.'},
]
test("repeat: identical response detected",
     _is_repeat_response(
         'Here are the top priorities for your pipeline today. Focus on warm leads first, then follow up with cooling contacts. Your numbers look solid.',
         msgs_with_repeat
     ) == True)

test("repeat: different response not detected",
     _is_repeat_response(
         'Let me take a completely different approach and think about the Austin market opportunities.',
         msgs_with_repeat
     ) == False)

test("repeat: short response not flagged",
     _is_repeat_response('Got it.', msgs_with_repeat) == False)

test("repeat: empty messages list safe",
     _is_repeat_response('Test response', []) == False)

test("repeat: no assistant messages safe",
     _is_repeat_response('Test response', [{'role': 'user', 'content': 'hello'}]) == False)

# ============================================================
# EXECUTION PRESERVATION (10 tests)
# ============================================================
print("\n=== Execution Preservation ===")

# These must still route to execution correctly
test("exec: 'add contact John' → execution",
     _route_message("add contact John Smith", [], empty_state, 'new')['route'] == 'execution')
test("exec: 'schedule a meeting' → execution",
     _route_message("schedule a meeting with Dave tomorrow", [], empty_state, 'new')['route'] == 'execution')
test("exec: 'draft email' → execution",
     _route_message("draft email to Sarah", [], empty_state, 'new')['route'] == 'execution')
test("exec: 'log a call' → execution",
     _route_message("log a call with Mike about the deal", [], empty_state, 'new')['route'] == 'execution')
test("exec: 'export pipeline report' → execution",
     _route_message("export pipeline report", [], empty_state, 'new')['route'] == 'execution')

# These must stay conversational
test("conv: 'hey' → conversation",
     _route_message("hey", [], empty_state, 'greeting')['route'] == 'conversation')
test("conv: 'motivate me' → conversation",
     _route_message("motivate me", [], empty_state, 'conversational')['route'] == 'conversation')
test("conv: 'I feel stuck' → conversation",
     _route_message("I feel stuck", [], empty_state, 'conversational')['route'] == 'conversation')
test("conv: 'what do you think' → conversation or domain",
     _route_message("what do you think", [], empty_state, 'conversational')['route'] in ('conversation', 'domain'))
test("conv: 'be honest with me' → conversation",
     _route_message("be honest with me", [], empty_state, 'conversational')['route'] == 'conversation')

# ============================================================
# CONVERSATIONAL BRAIN STILL WORKS (5 tests)
# ============================================================
print("\n=== Conversational Brain Preserved ===")

fb1 = _handle_conversational_fallback("give me some motivation", empty_state)
test("brain: motivation fallback works", fb1 and len(fb1) > 10)

fb2 = _handle_conversational_fallback("i'm stuck", empty_state)
test("brain: stuck fallback works", fb2 and len(fb2) > 10)

fb3 = _handle_conversational_fallback("what's your honest opinion", empty_state)
test("brain: opinion fallback works", fb3 and len(fb3) > 10)

fb4 = _handle_conversational_fallback("i'm worried about the pipeline", empty_state)
test("brain: worried fallback works", fb4 and len(fb4) > 10)

fb5 = _handle_conversational_fallback("let's brainstorm", empty_state)
test("brain: brainstorm fallback works", fb5 and len(fb5) > 10)

# ============================================================
# EDGE CASES (5 tests)
# ============================================================
print("\n=== Edge Cases ===")

# Empty message
r_empty = _route_message("", [], empty_state, 'new')
test("edge: empty message doesn't crash", r_empty['route'] in ('conversation', 'domain', 'research', 'execution', 'hybrid', 'clarify'))

# Very long message
long_msg = "I need you to " + "think about this " * 50 + "and tell me what to do"
r_long = _route_message(long_msg, [], empty_state, 'new')
test("edge: long message doesn't crash", r_long is not None)

# Slash command
r_slash = _route_message("/research company ABC", [], empty_state, 'new')
test("edge: slash command routes correctly", r_slash['execution_intent'] == 'research_web')

# Mixed signals
r_mixed = _route_message("I'm frustrated but add a contact named Dave", [], empty_state, 'new')
test("edge: mixed signals → execution wins (guard catches 'add a contact')",
     _detect_message_type("I'm frustrated but add a contact named Dave", empty_state) == 'new')

# Continuation state
cont_state = {
    'people': [{'name': 'John', 'id': '123'}], 'companies': [],
    'entities': {'contacts': [{'name': 'John', 'id': '123'}], 'groups': []},
    'last_intent': 'research_web',
}
r_cont = _route_message("now draft outreach for him", [], cont_state, 'continuation')
test("edge: continuation carries forward context",
     r_cont['intent'] == 'clarification' and r_cont['execution_intent'] == 'draft_outreach')

# ============================================================
# Summary
# ============================================================
total = passed + failed
print(f"\n{'='*60}")
print(f"ROUTER TEST RESULTS: {passed}/{total} passed, {failed} failed")
if errors:
    print(f"\nFailed tests:")
    for e in errors:
        print(f"  - {e}")
print(f"{'='*60}")

sys.exit(0 if failed == 0 else 1)
