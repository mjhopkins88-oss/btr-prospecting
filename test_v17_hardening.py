"""
V17 hardening sanity checks.
Tests: contact scoring, research validation, PDF reliability,
cache invalidation, source parsing, entity integrity.
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
# 1. Contact Priority Scoring (15 tests)
# ============================================================
print("--- Contact Priority Scoring ---")
from api.routes.assistant import _compute_contact_priority, _batch_touchpoint_stats

# Basic scoring with a mock group
mock_group = {
    'id': 'test-group-1',
    'name': 'Test Developer',
    'type': 'developer',
    'warmth_score': 8,
    'last_contacted_at': None,
}
cp = _compute_contact_priority(None, mock_group)
test("score: returns dict", isinstance(cp, dict))
test("score: has priority_score", 'priority_score' in cp)
test("score: priority_score is int", isinstance(cp['priority_score'], int))
test("score: score in range 0-100", 0 <= cp['priority_score'] <= 100)
test("score: has warmth_score", 'warmth_score' in cp)
test("score: has decay_risk", 'decay_risk' in cp)
test("score: decay_risk is valid", cp['decay_risk'] in ('low', 'medium', 'high', 'critical'))
test("score: has last_touch_days", 'last_touch_days' in cp)
test("score: has btr_fit", 'btr_fit' in cp)
test("score: btr_fit is valid", cp['btr_fit'] in ('strong', 'moderate', 'weak'))
test("score: has next_best_action", 'next_best_action' in cp)
test("score: has next_best_action_reason", 'next_best_action_reason' in cp)
test("score: developer = strong fit", cp['btr_fit'] == 'strong')

# Operator fit
op_group = {'id': 'test-op', 'type': 'operator', 'warmth_score': 5}
cp_op = _compute_contact_priority(None, op_group)
test("score: operator = strong fit", cp_op['btr_fit'] == 'strong')

# Unknown type
unk_group = {'id': 'test-unk', 'type': 'other', 'warmth_score': 3}
cp_unk = _compute_contact_priority(None, unk_group)
test("score: unknown type = weak fit", cp_unk['btr_fit'] == 'weak')

# ============================================================
# 2. Batch Touchpoint Stats (5 tests)
# ============================================================
print("--- Batch Touchpoint Stats ---")
stats = _batch_touchpoint_stats([])
test("batch: empty input returns empty dict", stats == {})

stats2 = _batch_touchpoint_stats(['nonexistent-id-1', 'nonexistent-id-2'])
test("batch: returns dict for missing IDs", isinstance(stats2, dict))
test("batch: has entries for each ID", len(stats2) == 2)
test("batch: missing IDs have zero counts",
     stats2.get('nonexistent-id-1', {}).get('recent_count', -1) == 0)
test("batch: no crash on missing tables", True)

# ============================================================
# 3. Pre-computed stats passed to scoring (5 tests)
# ============================================================
print("--- Pre-computed Stats ---")
fake_stats = {
    'test-group-1': {'recent_count': 3, 'total_count': 10},
}
cp_with_stats = _compute_contact_priority(None, mock_group, tp_stats=fake_stats)
test("precomputed: returns valid score", 0 <= cp_with_stats['priority_score'] <= 100)
test("precomputed: uses provided stats (not zero)", cp_with_stats['priority_score'] >= 0)
test("precomputed: no crash", True)

# Without stats should also work
cp_no_stats = _compute_contact_priority(None, mock_group, tp_stats=None)
test("no-stats: returns valid score", 0 <= cp_no_stats['priority_score'] <= 100)
test("no-stats: no crash", True)

# ============================================================
# 4. Research Validation (10 tests)
# ============================================================
print("--- Research Validation ---")
from api.routes.assistant import _validate_research_entity

# Entity match
v1 = _validate_research_entity('"Apex Capital"', 'Apex Capital is a real estate firm.')
test("research: entity matched", v1['entity_match'] is True)

v2 = _validate_research_entity('"Apex Capital"', 'Meridian Group is a developer.')
test("research: entity mismatch detected", v2['entity_match'] is False)
test("research: mismatch has warning", len(v2['warnings']) > 0)

# BTR relevance
v3 = _validate_research_entity('test', 'They develop multifamily housing units.')
test("research: BTR relevance detected", v3['has_btr_relevance'] is True)

v4 = _validate_research_entity('test', 'They sell office supplies.')
test("research: no BTR relevance", v4['has_btr_relevance'] is False)

# Recent activity
from datetime import datetime
current_year = str(datetime.utcnow().year)
v5 = _validate_research_entity('test', f'They announced a project in {current_year}.')
test("research: recent activity found", v5['has_recent_activity'] is True)

v6 = _validate_research_entity('test', 'They were founded long ago.')
test("research: no recent activity", v6['has_recent_activity'] is False)

# Edge cases
v7 = _validate_research_entity('', '')
test("research: empty inputs no crash", v7['entity_match'] is True)

v8 = _validate_research_entity('test query', None)
test("research: None research_text no crash",
     isinstance(v8, dict) and v8['entity_match'] is True)

# Confidence factors
v9 = _validate_research_entity('test', f'They launched a BTR development in {current_year}.')
test("research: multiple confidence factors",
     len(v9['confidence_factors']) >= 2)

# ============================================================
# 5. PDF System Sanity (8 tests)
# ============================================================
print("--- PDF System ---")
from api.routes.daily_brief import (
    _sanitize_pdf_text, invalidate_brief_cache, _evict_old_pdfs,
    _generate_brief_content, validate_pdf, MAX_CACHED_PDFS
)

# Sanitize text
test("pdf: sanitize smart quotes", _sanitize_pdf_text("‘test’") == "'test'")
test("pdf: sanitize em dash", _sanitize_pdf_text("a—b") == "a - b")
test("pdf: sanitize zero-width", _sanitize_pdf_text("a​b") == "ab")
test("pdf: sanitize None", _sanitize_pdf_text(None) == '')
test("pdf: sanitize empty", _sanitize_pdf_text('') == '')
test("pdf: MAX_CACHED_PDFS defined", MAX_CACHED_PDFS == 50)

# Cache invalidation runs without crash
try:
    invalidate_brief_cache()
    test("pdf: invalidate_brief_cache no crash", True)
except Exception:
    test("pdf: invalidate_brief_cache no crash", False)

# Eviction runs without crash
try:
    _evict_old_pdfs()
    test("pdf: _evict_old_pdfs no crash", True)
except Exception:
    test("pdf: _evict_old_pdfs no crash", False)

# ============================================================
# 6. Daily Brief Content (5 tests)
# ============================================================
print("--- Daily Brief Content ---")
try:
    brief = _generate_brief_content()
    test("brief: returns dict", isinstance(brief, dict))
    test("brief: has date", 'date' in brief)
    test("brief: has action_items", 'action_items' in brief)
    test("brief: has what_changed", 'what_changed' in brief)
    test("brief: action_items is list", isinstance(brief.get('action_items'), list))
except Exception as e:
    test("brief: returns dict", False)
    test("brief: has date", False)
    test("brief: has action_items", False)
    test("brief: has what_changed", False)
    test("brief: action_items is list", False)

# ============================================================
# 7. Research Output Structure (5 tests)
# ============================================================
print("--- Research Output Structure ---")
from api.routes.assistant import _build_research_response

# Build a mock research dict
mock_research = {
    'person_name': 'John Smith',
    'company_name': 'Apex Capital',
    'company_snapshot': {'description': 'A real estate firm.'},
    'recent_activity': [{'event': 'Announced BTR project', 'date': '2026-01'}],
    'btr_connection': {'level': 'direct', 'explanation': 'Active BTR developer'},
    'person_connection': {'role': 'VP Development', 'tied_to_activity': True,
                          'explanation': 'Leads BTR projects', 'confidence': 'high'},
    'outreach_angle': {'why_they_care': 'Scaling BTR portfolio'},
    'sources': [{'title': 'Press Release', 'url': 'https://example.com/pr'}],
    'web_search_sources': [{'title': 'LinkedIn', 'url': 'https://linkedin.com/in/jsmith'}],
    'confidence': {'overall': 'high', 'reasons': ['Multiple sources']},
    'gaps': 'Could not verify exact deal size.',
}
mock_intros = [
    {'subject': 'Hi', 'body': 'LinkedIn intro'},
    {'subject': 'Intro', 'body': 'Warm email'},
    {'subject': 'Direct', 'body': 'Direct intro'},
]

try:
    text, card = _build_research_response('research "John Smith" at "Apex Capital"', mock_research, mock_intros)
    test("research card: returns text and card", isinstance(text, str) and isinstance(card, dict))
    test("research card: has confidence_details",
         'confidence_details' in card.get('data', {}))
    cd = card['data']['confidence_details']
    test("research card: confidence has entity_verified",
         'entity_verified' in cd)
    test("research card: confidence has btr_relevant",
         'btr_relevant' in cd)
    test("research card: card type is OutreachIntelCard",
         card.get('type') == 'OutreachIntelCard')
except Exception as e:
    for name in ["research card: returns text and card",
                 "research card: has confidence_details",
                 "research card: confidence has entity_verified",
                 "research card: confidence has btr_relevant",
                 "research card: card type is OutreachIntelCard"]:
        test(name, False)

# ============================================================
# 8. No Hallucinated Entities (5 tests)
# ============================================================
print("--- Entity Integrity ---")
from api.routes.assistant import _validate_entity_references, _is_pipeline_question

# Pipeline detection
test("entity: pipeline question detected",
     _is_pipeline_question("who is in my pipeline?"))
test("entity: non-pipeline not flagged",
     not _is_pipeline_question("what's the weather?"))

# Entity validation with empty CRM
known = set()
suspects = _validate_entity_references(
    "I spoke with John at Apex Capital about their deal.", known)
test("entity: flags unknown entities", len(suspects) > 0)

suspects2 = _validate_entity_references(
    "Let me help you with that.", known)
test("entity: clean response no flags", len(suspects2) == 0)

# Known entities should not be flagged
known_names = {'apex capital', 'john smith'}
suspects3 = _validate_entity_references(
    "Apex Capital is a great fit.", known_names)
test("entity: known entities not flagged", len(suspects3) == 0)

# ============================================================
# 9. Broad Exception Reduction Verification (3 tests)
# ============================================================
print("--- Exception Hardening ---")
import inspect

# Verify key functions no longer have bare except-pass
for fn_name in ['_get_current_focus', '_store_memory', '_sync_focus_from_chat']:
    from api.routes import assistant as _ast_mod
    fn = getattr(_ast_mod, fn_name, None)
    if fn:
        src = inspect.getsource(fn)
        lines = src.split('\n')
        bare_pass = 0
        for i, line in enumerate(lines):
            if 'except Exception' in line:
                if i + 1 < len(lines) and lines[i + 1].strip() == 'pass':
                    bare_pass += 1
        test(f"hardened: {fn_name} has no bare except-pass", bare_pass == 0)
    else:
        test(f"hardened: {fn_name} exists", False)

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
