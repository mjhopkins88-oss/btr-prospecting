"""
Test suite for Leo's Truth Enforcement Layer.
Tests entity validation, content classification, pipeline question detection,
entity name pattern matching, truth context building, and the full flow.
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
    _get_known_entity_names, _validate_entity_references,
    _classify_response_content, _is_pipeline_question,
    _build_truth_context, _ENTITY_NAME_PATTERN, _PERSON_NAME_PATTERN,
    _handle_conversational_fallback,
)

empty_state = {'people': [], 'companies': [], 'entities': {'contacts': [], 'groups': []}}

# ============================================================
# 1. Pipeline Question Detection (8 tests)
# ============================================================
print("=== Pipeline Question Detection ===")

test("pipeline: 'who in my pipeline' detected",
     _is_pipeline_question("who in my pipeline is a good mid-tier capital group?"))
test("pipeline: 'my contacts' detected",
     _is_pipeline_question("show me my contacts that are warm"))
test("pipeline: 'from my pipeline' detected",
     _is_pipeline_question("give me a good example from my pipeline"))
test("pipeline: 'any of my companies' detected",
     _is_pipeline_question("are any of my companies in Texas?"))
test("pipeline: 'which of my groups' detected",
     _is_pipeline_question("which of my groups should I focus on?"))
test("pipeline: general question NOT detected",
     not _is_pipeline_question("what's a good strategy for outreach?"))
test("pipeline: motivational NOT detected",
     not _is_pipeline_question("motivate me to make calls today"))
test("pipeline: 'in my crm' detected",
     _is_pipeline_question("is there anyone in my crm who works at Blackstone?"))

# ============================================================
# 2. Entity Name Pattern Detection (12 tests)
# ============================================================
print("\n=== Entity Name Pattern Detection ===")

# Should match — company-like names with business suffixes
m1 = _ENTITY_NAME_PATTERN.findall("I'd suggest Goldstone Partners as a good target")
test("entity: 'Goldstone Partners' caught", any('Goldstone' in x for x in m1))

m2 = _ENTITY_NAME_PATTERN.findall("For example, Meridian Capital Group could be a strong fit")
test("entity: 'Meridian Capital Group' caught", any('Meridian' in x for x in m2))

m3 = _ENTITY_NAME_PATTERN.findall("Consider reaching out to Apex Development")
test("entity: 'Apex Development' caught", any('Apex' in x for x in m3))

m4 = _ENTITY_NAME_PATTERN.findall("You could start with Pinnacle Investments")
test("entity: 'Pinnacle Investments' caught", any('Pinnacle' in x for x in m4))

m5 = _ENTITY_NAME_PATTERN.findall("Horizon Fund is a major player in BTR")
test("entity: 'Horizon Fund' caught", any('Horizon' in x for x in m5))

# Should NOT match — no business suffix
m6 = _ENTITY_NAME_PATTERN.findall("You should focus on warm contacts in your pipeline")
test("entity: generic advice not caught", len(m6) == 0)

m7 = _ENTITY_NAME_PATTERN.findall("Typically a mid-tier group would look like a $50M AUM firm")
test("entity: general statement not caught", len(m7) == 0)

m8 = _ENTITY_NAME_PATTERN.findall("I don't see that in your pipeline")
test("entity: honest response not caught", len(m8) == 0)

m9 = _ENTITY_NAME_PATTERN.findall("The BTR market is growing in the sunbelt")
test("entity: market statement not caught", len(m9) == 0)

# Person name pattern tests
p1 = _PERSON_NAME_PATTERN.findall("Reach out to David Thompson about the deal")
test("person: 'David Thompson' caught", any('David Thompson' in x for x in p1))

p2 = _PERSON_NAME_PATTERN.findall("Your warmest contact is doing well")
test("person: no person name in generic text", len(p2) == 0)

p3 = _PERSON_NAME_PATTERN.findall("Talk to John Smith about the opportunity")
test("person: 'John Smith' caught", any('John Smith' in x for x in p3))

# ============================================================
# 3. Entity Validation (10 tests)
# ============================================================
print("\n=== Entity Validation ===")

known = _get_known_entity_names()
test("known: returns a set", isinstance(known, set))

# Test validation with fabricated company names
suspects1 = _validate_entity_references(
    "Goldstone Partners is a strong mid-tier group you should target.",
    known
)
test("validate: Goldstone Partners flagged (fabricated)",
     'Goldstone Partners' in suspects1 or any('Goldstone' in s for s in suspects1))

suspects2 = _validate_entity_references(
    "Meridian Capital Group could be a great fit for your program.",
    known
)
test("validate: Meridian Capital Group flagged",
     any('Meridian' in s for s in suspects2))

# Test that real CRM entities are NOT flagged
if known:
    real_name = list(known)[0]
    response_with_real = f"Reaching out to {real_name.title()} is a good idea."
    suspects3 = _validate_entity_references(response_with_real, known)
    test("validate: known CRM entity NOT flagged",
         not any(real_name in s.lower() for s in suspects3))
else:
    test("validate: known CRM entity NOT flagged (no CRM data, skip)", True)

# Clean responses should have no suspects
suspects4 = _validate_entity_references(
    "Your pipeline looks healthy. Focus on the warmest relationships first.",
    known
)
test("validate: clean response has no suspects", len(suspects4) == 0)

suspects5 = _validate_entity_references(
    "Typically a mid-tier group would have $50-100M AUM focused on sunbelt markets.",
    known
)
test("validate: qualified general response has no suspects", len(suspects5) == 0)

suspects6 = _validate_entity_references(
    "I don't see a clear example in your pipeline.",
    known
)
test("validate: honest response has no suspects", len(suspects6) == 0)

# Geographic names should not be flagged
suspects7 = _validate_entity_references(
    "Check out the Austin and Dallas markets for BTR activity.",
    known
)
test("validate: geographic names not flagged", len(suspects7) == 0)

suspects8 = _validate_entity_references("", known)
test("validate: empty response safe", len(suspects8) == 0)

suspects9 = _validate_entity_references(
    "Try using LinkedIn to reach decision makers.",
    known
)
test("validate: platform names not flagged", len(suspects9) == 0)

# ============================================================
# 4. Content Classification (8 tests)
# ============================================================
print("\n=== Content Classification ===")

c1 = _classify_response_content(
    "Goldstone Partners is your warmest at 7/10."
)
test("classify: entity reference detected", c1['has_entity_references'] == True)

c2 = _classify_response_content(
    "Typically a mid-tier group would look like a $50M AUM firm."
)
test("classify: qualifier detected", c2['has_qualifiers'] == True)

c3 = _classify_response_content(
    "I don't see that in your pipeline right now."
)
test("classify: uncertainty detected", c3['has_uncertainty'] == True)

c4 = _classify_response_content(
    "Pick your warmest contact and send one message. Let momentum do the rest."
)
test("classify: clean motivational is high confidence", c4['confidence'] == 'high')

c5 = _classify_response_content(
    "Based on what I'm seeing, your pipeline is healthy."
)
test("classify: qualified with no entity refs is high confidence",
     c5['has_qualifiers'] == True and c5['confidence'] == 'high')

c6 = _classify_response_content(
    "Goldstone Partners typically works in this space."
)
test("classify: entity + qualifier = medium confidence", c6['confidence'] == 'medium')

c7 = _classify_response_content(
    "Pinnacle Capital Group is a strong fit for your program."
)
test("classify: entity without qualifier = low confidence", c7['confidence'] == 'low')

c8 = _classify_response_content("")
test("classify: empty response safe", c8['confidence'] == 'high')

# ============================================================
# 5. Truth Context Building (6 tests)
# ============================================================
print("\n=== Truth Context Building ===")

ctx1 = _build_truth_context("who in my pipeline is good", empty_state)
test("truth_ctx: pipeline question triggers warning",
     'PIPELINE' in ctx1 or 'VERIFIED' in ctx1)

ctx2 = _build_truth_context("motivate me", empty_state)
test("truth_ctx: non-pipeline still provides verified entities",
     'VERIFIED' in ctx2 or ctx2 == '')

ctx3 = _build_truth_context("tell me about my companies", empty_state)
test("truth_ctx: 'my companies' triggers pipeline mode",
     'PIPELINE' in ctx3 or 'VERIFIED' in ctx3)

test("truth_ctx: returns string", isinstance(ctx1, str))
test("truth_ctx: contains CRM entity list or is empty",
     'VERIFIED' in ctx1 or 'none' in ctx1.lower() or ctx1 == '')

ctx4 = _build_truth_context("give me a mid-tier example from my pipeline", empty_state)
test("truth_ctx: mid-tier pipeline question gets enforcement",
     'PIPELINE' in ctx4 or 'verified' in ctx4.lower() or 'VERIFIED' in ctx4)

# ============================================================
# 6. PART 9 Test Case — "Give me a mid-tier capital group from my pipeline" (5 tests)
# ============================================================
print("\n=== Part 9: Pipeline Entity Test ===")

test_msg = "Give me a mid-tier capital group from my pipeline"
test("part9: detected as pipeline question", _is_pipeline_question(test_msg))

ctx_p9 = _build_truth_context(test_msg, empty_state)
test("part9: truth context has pipeline warning",
     'PIPELINE' in ctx_p9 or 'only reference' in ctx_p9.lower())

# Verify the fallback would NOT fabricate
fb_p9 = _handle_conversational_fallback(test_msg, empty_state)
test("part9: fallback response exists", fb_p9 and len(fb_p9) > 5)
test("part9: fallback has no fabricated company names",
     not _ENTITY_NAME_PATTERN.search(fb_p9))

# Validate that if the LLM DID fabricate, it would be caught
fake_response = "Goldstone Capital Partners fits the mid-tier profile well."
suspects_p9 = _validate_entity_references(fake_response, known)
test("part9: fabricated Goldstone would be caught by validator",
     any('Goldstone' in s for s in suspects_p9))

# ============================================================
# 7. Free Thinking Preservation (8 tests)
# ============================================================
print("\n=== Free Thinking Preservation ===")

good_responses = [
    "The BTR market is shifting toward build-to-own strategies in the sunbelt. Position your program around the transition risk angle.",
    "Your pipeline has a bottleneck at the initial contact stage. Most of your warm leads are developer-sourced.",
    "Based on what I'm seeing in your pipeline, you're stronger in Texas than Florida. That could be your wedge.",
    "Typically a mid-tier group would look like a $50-100M AUM firm focused on sunbelt BTR communities.",
    "Pick your 3 warmest contacts, send a direct note referencing the zero-loss track record.",
    "The real blocker isn't your outreach. Capital markets are slow, so you need to be the first call when they thaw.",
    "Rethink the cold email approach. Warm intros through existing contacts convert 3x better in this space.",
    "Your competitive edge is the zero-loss book. Every outreach should lead with that.",
]

for i, resp in enumerate(good_responses):
    suspects = _validate_entity_references(resp, known)
    test(f"free_think: good response {i+1} not flagged", len(suspects) == 0)

# ============================================================
# 8. Edge Cases (5 tests)
# ============================================================
print("\n=== Edge Cases ===")

test("edge: empty text doesn't crash",
     _is_pipeline_question("") == False)

test("edge: None-safe known names",
     isinstance(_get_known_entity_names(), set))

test("edge: very long response validates",
     isinstance(_validate_entity_references("word " * 1000, known), list))

mixed = "Your pipeline is healthy at 7 groups. Apex Development Partners could help with expansion."
suspects_mixed = _validate_entity_references(mixed, known)
classify_mixed = _classify_response_content(mixed)
test("edge: mixed response classified correctly",
     classify_mixed['has_entity_references'] == True)

test("edge: motivational classification is correct",
     _classify_response_content("Let's go. One call changes everything.")['confidence'] == 'high')

# ============================================================
# Summary
# ============================================================
total = passed + failed
print(f"\n{'='*60}")
print(f"TRUTH ENFORCEMENT RESULTS: {passed}/{total} passed, {failed} failed")
if errors:
    print(f"\nFailed tests:")
    for e in errors:
        print(f"  - {e}")
print(f"{'='*60}")

sys.exit(0 if failed == 0 else 1)
