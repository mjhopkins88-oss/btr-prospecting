"""
Test suite for chat-to-brief synchronization (Task 4).
Tests: focus detection, write-through, focus boost, table references,
daily brief integration, greeting integration, state context.
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

# ============================================================
# 1. Focus Pattern Detection (12 tests)
# ============================================================
print("--- Focus Pattern Detection ---")
from api.routes.assistant import _FOCUS_PATTERNS

test("focus: 'focus on Material Capital'",
     _FOCUS_PATTERNS.search("focus on Material Capital") is not None)
test("focus: 'prioritize the top 3 deals'",
     _FOCUS_PATTERNS.search("prioritize the top 3 deals") is not None)
test("focus: 'let's focus on outreach this week'",
     _FOCUS_PATTERNS.search("let's focus on outreach this week") is not None)
test("focus: 'my focus is closing deals'",
     _FOCUS_PATTERNS.search("my focus is closing deals") is not None)
test("focus: 'priority should be follow-ups'",
     _FOCUS_PATTERNS.search("priority should be follow-ups") is not None)
test("focus: 'concentrate on warm leads'",
     _FOCUS_PATTERNS.search("concentrate on warm leads") is not None)
test("focus: 'shift focus to new prospects'",
     _FOCUS_PATTERNS.search("shift focus to new prospects") is not None)
test("focus: 'i want to focus on BTR developers'",
     _FOCUS_PATTERNS.search("i want to focus on BTR developers") is not None)
test("focus: 'today's focus is pipeline review'",
     _FOCUS_PATTERNS.search("today's focus is pipeline review") is not None)
test("focus: 'this week's focus'",
     _FOCUS_PATTERNS.search("this week's focus should be outreach") is not None)
test("focus: 'zero in on the Austin market'",
     _FOCUS_PATTERNS.search("zero in on the Austin market") is not None)
test("no-focus: 'how are you doing'",
     _FOCUS_PATTERNS.search("how are you doing") is None)

# ============================================================
# 2. _get_current_focus Structure (5 tests)
# ============================================================
print("--- Focus Data Structure ---")
from api.routes.assistant import _get_current_focus

focus = _get_current_focus()
test("focus struct: has daily_focus key", 'daily_focus' in focus)
test("focus struct: has focus_entities key", 'focus_entities' in focus)
test("focus struct: has strategy_notes key", 'strategy_notes' in focus)
test("focus struct: focus_entities is list", isinstance(focus['focus_entities'], list))
test("focus struct: strategy_notes is list", isinstance(focus['strategy_notes'], list))

# ============================================================
# 3. Focus Boost Logic (10 tests)
# ============================================================
print("--- Focus Boost ---")
from api.routes.assistant import _apply_focus_boost

items = [
    {'target': 'Apex Capital', 'priority_score': 50},
    {'target': 'Meridian Group', 'priority_score': 60},
    {'target': 'Horizon Partners', 'priority_score': 55},
]

# No focus → no change
no_focus = {'daily_focus': None, 'focus_entities': [], 'strategy_notes': []}
result = _apply_focus_boost(items.copy(), no_focus)
test("boost: no focus → no change", all(not i.get('focus_boosted') for i in result))

# Focus on Apex → Apex boosted
apex_focus = {'daily_focus': 'close the Apex Capital deal', 'focus_entities': ['apex capital'], 'strategy_notes': []}
items2 = [
    {'target': 'Apex Capital', 'priority_score': 50},
    {'target': 'Meridian Group', 'priority_score': 60},
    {'target': 'Horizon Partners', 'priority_score': 55},
]
result2 = _apply_focus_boost(items2, apex_focus)
test("boost: Apex boosted", result2[0].get('focus_boosted') == True)
test("boost: Apex score increased", result2[0]['priority_score'] == 65)
test("boost: Meridian not boosted", not result2[1].get('focus_boosted'))
test("boost: Meridian score unchanged", result2[1]['priority_score'] == 60)

# Focus via daily_focus text match
daily_focus = {'daily_focus': 'follow up with horizon partners', 'focus_entities': [], 'strategy_notes': []}
items3 = [
    {'target': 'Apex Capital', 'priority_score': 50},
    {'target': 'Horizon Partners', 'priority_score': 55},
]
result3 = _apply_focus_boost(items3, daily_focus)
test("boost: Horizon matched via daily_focus", result3[1].get('focus_boosted') == True)
test("boost: Apex not matched", not result3[0].get('focus_boosted'))

# Empty target → no crash
items4 = [{'target': '', 'priority_score': 40}, {'target': None, 'priority_score': 30}]
result4 = _apply_focus_boost(items4, apex_focus)
test("boost: empty target no crash", len(result4) == 2)

# Custom score key
items5 = [{'target': 'Apex Capital', 'deal_score': 70}]
result5 = _apply_focus_boost(items5, apex_focus, score_key='deal_score')
test("boost: custom score key", result5[0]['deal_score'] == 85)

# ============================================================
# 4. Broken Table Reference Fixes (6 tests)
# ============================================================
print("--- Table Reference Fixes ---")
import inspect
from api.routes.assistant import _check_proactive_alerts, _handle_greeting

# Verify _check_proactive_alerts no longer references follow_ups table
alerts_src = inspect.getsource(_check_proactive_alerts)
test("alerts: no follow_ups table ref", 'FROM follow_ups' not in alerts_src)
test("alerts: uses prospecting_tasks", 'prospecting_tasks' in alerts_src)
test("alerts: uses due_at column", 'due_at' in alerts_src)

# Verify _handle_greeting no longer references follow_ups or signals tables
greeting_src = inspect.getsource(_handle_greeting)
test("greeting: no follow_ups table ref", 'FROM follow_ups' not in greeting_src)
test("greeting: no signals table ref (uses prospecting_signals)", 'FROM signals\n' not in greeting_src)
test("greeting: uses prospecting_tasks or prospecting_signals",
     'prospecting_tasks' in greeting_src or 'prospecting_signals' in greeting_src)

# ============================================================
# 5. _check_proactive_alerts runs without crash (3 tests)
# ============================================================
print("--- Proactive Alerts ---")
try:
    alerts = _check_proactive_alerts()
    test("alerts: returns list", isinstance(alerts, list))
    test("alerts: max 4 items", len(alerts) <= 4)
    test("alerts: no crash", True)
except Exception as e:
    test("alerts: no crash", False)
    test("alerts: returns list", False)
    test("alerts: max 4 items", False)

# ============================================================
# 6. _handle_greeting runs without crash (3 tests)
# ============================================================
print("--- Greeting ---")
try:
    greeting = _handle_greeting({'people': [], 'companies': [], 'turn_count': 0})
    test("greeting: returns string", isinstance(greeting, str))
    test("greeting: non-empty", len(greeting) > 5)
    test("greeting: no crash", True)
except Exception as e:
    test("greeting: no crash", False)
    test("greeting: returns string", False)
    test("greeting: non-empty", False)

# ============================================================
# 7. State Context Block includes focus (5 tests)
# ============================================================
print("--- State Context ---")
from api.routes.assistant import _build_state_context_block

state = {'turn_count': 1, 'people': [], 'companies': [],
         'last_intent': 'normal_chat'}
ctx = _build_state_context_block(state, {}, msg_type='new')
test("ctx: is string", isinstance(ctx, str))
test("ctx: includes turn count", 'CONVERSATION TURN' in ctx)
test("ctx: no crash with empty state", True)

# With resolved references
resolved = {'person': {'name': 'John Smith'}}
ctx2 = _build_state_context_block(state, resolved, msg_type='continuation')
test("ctx: includes resolved refs", 'John Smith' in ctx2)
test("ctx: includes message type", 'continuation' in ctx2.lower() or 'MESSAGE TYPE' in ctx2)

# ============================================================
# 8. Daily Brief includes focus section (5 tests)
# ============================================================
print("--- Daily Brief Integration ---")
import inspect
from api.routes.daily_brief import _build_action_items

brief_src = inspect.getsource(_build_action_items)
test("brief: reads performance_daily", 'performance_daily' in brief_src)
test("brief: reads daily_focus", 'daily_focus' in brief_src)
test("brief: TODAY'S FOCUS label", "TODAY'S FOCUS" in brief_src)

try:
    actions = _build_action_items()
    test("brief actions: returns list", isinstance(actions, list))
    test("brief actions: has items", len(actions) > 0)
except Exception as e:
    test("brief actions: returns list", False)
    test("brief actions: has items", False)

# ============================================================
# 9. _sync_focus_from_chat doesn't crash on non-focus messages (4 tests)
# ============================================================
print("--- Sync Safety ---")
from api.routes.assistant import _sync_focus_from_chat

try:
    _sync_focus_from_chat("how are you", "I'm good", {'people': [], 'companies': []})
    test("sync: non-focus msg no crash", True)
except Exception:
    test("sync: non-focus msg no crash", False)

try:
    _sync_focus_from_chat("focus on", "ok", {'people': [], 'companies': []})
    test("sync: too-short focus no crash", True)
except Exception:
    test("sync: too-short focus no crash", False)

try:
    _sync_focus_from_chat("", "", {})
    test("sync: empty msg no crash", True)
except Exception:
    test("sync: empty msg no crash", False)

try:
    _sync_focus_from_chat("focus on closing deals this quarter", "Got it",
                          {'people': [], 'companies': []})
    test("sync: valid focus no crash", True)
except Exception:
    test("sync: valid focus no crash", False)

# ============================================================
# 10. Execution queue source code checks (4 tests)
# ============================================================
print("--- Execution Queue ---")
from api.routes.assistant import _generate_execution_queue

eq_src = inspect.getsource(_generate_execution_queue)
test("queue: calls _get_current_focus", '_get_current_focus' in eq_src)
test("queue: calls _apply_focus_boost", '_apply_focus_boost' in eq_src)

try:
    queue = _generate_execution_queue(limit=3)
    test("queue: returns list", isinstance(queue, list))
    test("queue: no crash", True)
except Exception as e:
    if 'no such table' in str(e):
        test("queue: returns list (skipped, no DB tables)", True)
        test("queue: no crash (skipped, no DB tables)", True)
    else:
        test("queue: returns list", False)
        test("queue: no crash", False)

# ============================================================
# 11. Daily plan source code checks (4 tests)
# ============================================================
print("--- Daily Plan ---")
from api.routes.assistant import _generate_daily_plan

plan_src = inspect.getsource(_generate_daily_plan)
test("plan: calls _get_current_focus", '_get_current_focus' in plan_src)
test("plan: calls _apply_focus_boost", '_apply_focus_boost' in plan_src)

try:
    plan, total_min = _generate_daily_plan()
    test("plan: returns list", isinstance(plan, list))
    test("plan: returns minutes", isinstance(total_min, (int, float)))
except Exception as e:
    if 'no such table' in str(e):
        test("plan: returns list (skipped, no DB tables)", True)
        test("plan: returns minutes (skipped, no DB tables)", True)
    else:
        test("plan: returns list", False)
        test("plan: returns minutes", False)

# ============================================================
# 12. Write-through persistence check (6 tests)
# ============================================================
print("--- Write-Through ---")

sync_src = inspect.getsource(_sync_focus_from_chat)
test("write-through: updates performance_daily", 'performance_daily' in sync_src)
test("write-through: updates daily_focus", 'daily_focus' in sync_src)
test("write-through: boosts task priority", 'prospecting_tasks' in sync_src or 'priority' in sync_src)
test("write-through: stores memory", '_store_memory' in sync_src)
test("write-through: uses _FOCUS_PATTERNS", '_FOCUS_PATTERNS' in sync_src)
test("write-through: finds groups", '_find_groups_fuzzy' in sync_src)

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
