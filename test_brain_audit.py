"""
Test suite for Leo's 4-brain architecture audit (Task C).
75 tests covering: casual chat, motivation, strategy, outreach, research,
add contact, approve action, ambiguous requests, intent classification,
message type detection, conversational fallback, and cross-brain coordination.
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

# Import the functions we need
from api.routes.assistant import (
    _is_approval, _detect_message_type, _classify_intent,
    _handle_conversational_fallback
)

# ============================================================
# 1. Approval Detection (10 tests)
# ============================================================
print("--- Approval Detection ---")
test("approve: 'yes'", _is_approval("yes"))
test("approve: 'approved'", _is_approval("approved"))
test("approve: 'go ahead'", _is_approval("go ahead"))
test("approve: 'sure'", _is_approval("sure"))
test("approve: 'ok'", _is_approval("ok"))
test("approve: 'yep'", _is_approval("yep"))
test("approve: 'works for me'", _is_approval("works for me"))
test("approve: 'that works'", _is_approval("that works"))
test("not approve: 'yes but change the name'", not _is_approval("yes but change the name"))
test("not approve: 'actually wait'", not _is_approval("actually wait"))

# ============================================================
# 2. Message Type Detection (20 tests)
# ============================================================
print("--- Message Type Detection ---")
empty_state = {}
active_state = {'last_intent': 'draft_outreach', 'last_output_text': 'Here is a draft...'}

# Greetings
test("type: 'hey' → greeting", _detect_message_type("hey", empty_state) == 'greeting')
test("type: 'good morning' → greeting", _detect_message_type("good morning", empty_state) == 'greeting')
test("type: 'hi leo' → greeting", _detect_message_type("hi leo", empty_state) == 'greeting')

# Conversational
test("type: 'motivate me' → conversational", _detect_message_type("motivate me", empty_state) == 'conversational')
test("type: 'i'm stuck' → conversational", _detect_message_type("i'm stuck", empty_state) == 'conversational')
test("type: 'what do you think' → conversational", _detect_message_type("what do you think", empty_state) == 'conversational')
test("type: 'i am frustrated' → conversational", _detect_message_type("i am frustrated", empty_state) == 'conversational')
test("type: 'im frustrated' → conversational", _detect_message_type("im frustrated", empty_state) == 'conversational')
test("type: 'i am worried' → conversational", _detect_message_type("i am worried", empty_state) == 'conversational')
test("type: 'i am confused' → conversational", _detect_message_type("i am confused", empty_state) == 'conversational')
test("type: 'give me advice' → conversational", _detect_message_type("give me advice", empty_state) == 'conversational')
test("type: 'be honest' → conversational", _detect_message_type("be honest", empty_state) == 'conversational')
test("type: 'what would you do' → conversational", _detect_message_type("what would you do", empty_state) == 'conversational')
test("type: 'level with me' → conversational", _detect_message_type("level with me", empty_state) == 'conversational')

# Execution (should NOT be conversational)
test("type: 'add contact John' → new", _detect_message_type("add contact John Smith", empty_state) == 'new')
test("type: 'draft email to Sarah' → new", _detect_message_type("draft email to Sarah", empty_state) == 'new')
test("type: 'schedule a meeting' → new", _detect_message_type("schedule a meeting with Dave", empty_state) == 'new')
test("type: 'research Apex Corp' → new", _detect_message_type("research Apex Corp", empty_state) == 'new')
test("type: 'reply to this email' → new", _detect_message_type("reply to this email", empty_state) == 'new')
test("type: 'write outreach for' → new", _detect_message_type("write outreach for new leads", empty_state) == 'new')

# ============================================================
# 3. Intent Classification (25 tests)
# ============================================================
print("--- Intent Classification ---")

# Action intents (should trigger at score >= 1)
test("intent: 'schedule a meeting with John' → schedule_meeting",
     _classify_intent("schedule a meeting with John") == 'schedule_meeting')
test("intent: 'draft an email to Sarah' → draft_outreach",
     _classify_intent("draft an email to Sarah") == 'draft_outreach')
test("intent: 'research Apex Corp online' → research_web",
     _classify_intent("research Apex Corp online") == 'research_web')
test("intent: 'add a contact named John' → crm_update",
     _classify_intent("add a contact named John") == 'crm_update')
test("intent: 'log a call with Dave' → log_update_crm",
     _classify_intent("log a call with Dave") == 'log_update_crm')
test("intent: 'export pipeline report' → export_report",
     _classify_intent("export pipeline report") == 'export_report')
test("intent: 'look up market data for Austin' → research_web",
     _classify_intent("look up market data for Austin") == 'research_web')

# Non-action intents (need score >= 2)
test("intent: 'how should I approach this deal' → normal_chat (score 1)",
     _classify_intent("how should I approach this deal") == 'normal_chat')
test("intent: 'tell me about yourself' → normal_chat",
     _classify_intent("tell me about yourself") == 'normal_chat')

# Tiebreaker tests (action intents preferred on tie)
test("intent: 'create a company named Apex Development' → crm_update (tiebreaker)",
     _classify_intent("create a company named Apex Development") == 'crm_update')
test("intent: 'dig into this company background' prefers action",
     _classify_intent("dig into this company background") in ('research_web', 'analyze_company'))

# Slash commands
test("intent: '/draft' → draft_outreach", _classify_intent("/draft email") == 'draft_outreach')
test("intent: '/research' → research_web", _classify_intent("/research company") == 'research_web')
test("intent: '/meeting' → schedule_meeting", _classify_intent("/meeting tomorrow") == 'schedule_meeting')
test("intent: '/log' → log_update_crm", _classify_intent("/log a call") == 'log_update_crm')
test("intent: '/export' → export_report", _classify_intent("/export report") == 'export_report')

# Conversational intents (normal_chat)
test("intent: 'how are you' → normal_chat", _classify_intent("how are you") == 'normal_chat')
test("intent: 'motivate me' → normal_chat", _classify_intent("motivate me") == 'normal_chat')
test("intent: 'what do you think about this' → normal_chat",
     _classify_intent("what do you think about this") == 'normal_chat')
test("intent: 'i'm feeling stuck' → normal_chat", _classify_intent("i'm feeling stuck") == 'normal_chat')

# Edge cases
test("intent: 'send a linkedin message to Mark' → draft_outreach or push_forward",
     _classify_intent("send a linkedin message to Mark") in ('draft_outreach', 'push_forward', 'market_intel'))
test("intent: 'cold email for prospecting' → draft_outreach",
     _classify_intent("cold email for prospecting") == 'draft_outreach')

# Performance-related
test("intent: '/squats 5x5 225' → update_performance",
     _classify_intent("/squats 5x5 225") == 'update_performance')
test("intent: '/workout bench press' → update_performance",
     _classify_intent("/workout bench press") == 'update_performance')
test("intent: '/perf focus=deep' → update_performance",
     _classify_intent("/perf focus=deep") == 'update_performance')

# ============================================================
# 4. Conversational Fallback (10 tests)
# ============================================================
print("--- Conversational Fallback ---")
fb_state = {'entities': {'contacts': [], 'groups': []}}

fb1 = _handle_conversational_fallback("I need some motivation right now", fb_state)
test("fallback: motivation returns text", fb1 and len(fb1) > 10)

fb2 = _handle_conversational_fallback("I'm stuck and don't know what to do", fb_state)
test("fallback: stuck returns text", fb2 and len(fb2) > 10)

fb3 = _handle_conversational_fallback("what do you think about my approach", fb_state)
test("fallback: opinion returns text", fb3 and len(fb3) > 10)

fb4 = _handle_conversational_fallback("let's brainstorm some ideas", fb_state)
test("fallback: strategy returns text", fb4 and len(fb4) > 10)

fb5 = _handle_conversational_fallback("i'm worried about my pipeline", fb_state)
test("fallback: worried returns text", fb5 and len(fb5) > 10)

fb6 = _handle_conversational_fallback("what does BTR mean exactly", fb_state)
test("fallback: explain returns text", fb6 and len(fb6) > 10)

fb7 = _handle_conversational_fallback("just chatting", fb_state)
test("fallback: general returns text", fb7 and len(fb7) > 10)

# Check no JSON in fallback
test("fallback: no JSON in motivation", '{' not in fb1 and '[' not in fb1)
test("fallback: no JSON in opinion", '{' not in fb3 and '[' not in fb3)
test("fallback: no JSON in worried", '{' not in fb5 and '[' not in fb5)

# ============================================================
# 5. Cross-Brain Coordination (10 tests)
# ============================================================
print("--- Cross-Brain Coordination ---")

# Execution guards should prevent conversational capture
test("guard: 'help me draft a cold email' → new (not conversational)",
     _detect_message_type("help me draft a cold email", empty_state) == 'new')
test("guard: 'i need help adding a contact' → new (not conversational)",
     _detect_message_type("i need help adding a contact", empty_state) == 'new')
test("guard: 'talk me through creating a company' → new (not conversational)",
     _detect_message_type("talk me through creating a company", empty_state) == 'new')

# Pure conversational should NOT be hijacked by execution
test("coord: 'help me think through my approach' → conversational",
     _detect_message_type("help me think through my approach", empty_state) == 'conversational')

# Verify conversational patterns don't contain execution keywords
test("coord: 'i feel like researching is pointless' → new (has 'research')",
     _detect_message_type("i feel like researching is pointless", empty_state) == 'new')

# Approval flow
from api.routes.assistant import _pending_action_cache
test("coord: 'sure' with no pending action → not approval",
     _detect_message_type("sure", empty_state) != 'approval')

# Intent + message type coordination
test("coord: greeting gets greeting not normal_chat",
     _detect_message_type("hey", empty_state) == 'greeting')
test("coord: execution gets new not conversational",
     _detect_message_type("add a contact named Smith", empty_state) == 'new')

# Classify intent for action-like messages
ci = _classify_intent("create a group called Top Prospects")
test("coord: 'create a group' → crm_update", ci == 'crm_update')

ci2 = _classify_intent("write an email to the CFO")
test("coord: 'write an email' → draft_outreach", ci2 == 'draft_outreach')

# ============================================================
# Summary
# ============================================================
print(f"\n{'='*50}")
print(f"RESULTS: {passed}/{passed+failed} passed, {failed} failed")
if errors:
    print(f"\nFailed tests:")
    for e in errors:
        print(f"  - {e}")
print(f"{'='*50}")

sys.exit(0 if failed == 0 else 1)
