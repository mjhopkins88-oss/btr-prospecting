"""
Civil Engineering Filing Detection Collector.
Detects development signals from engineering plan submissions,
site plans, grading plans, and drainage studies.

Signal types:
  SITE_PLAN_SUBMISSION
  GRADING_PLAN
  DRAINAGE_REPORT
  ENGINEERING_REVIEW
"""
import json
import uuid
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

try:
    import anthropic
except ImportError:
    anthropic = None

from db import get_db
from shared.config import SERPAPI_KEY, ANTHROPIC_API_KEY, AI_MODEL, TARGET_CITIES


CIVIL_ENGINEERING_SIGNAL_SCORES = {
    'SITE_PLAN_SUBMISSION': 25,
    'GRADING_PLAN': 20,
    'DRAINAGE_REPORT': 15,
    'ENGINEERING_REVIEW': 20,
}


def _search_engineering_filings(city, state, num=10):
    """Search for civil engineering plan submissions and reviews."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} site plan submission residential development engineering',
        f'{city} {state} grading plan drainage study multifamily development',
        f'{city} {state} civil engineering review portal development application',
    ]
    results = []
    for q in queries:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q, 'num': num, 'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('organic_results', []))
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[CivilEngineeringCollector] Search error: {e}")
    return results


def _extract_engineering_signals(documents, city, state):
    """Use Claude to extract civil engineering filing signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about civil engineering filings in {city}, {state}.
Extract any site plan submissions, grading plans, drainage reports, or engineering reviews
related to residential or multifamily development.

Sources may include city engineering departments, site plan submission portals,
grading plan submissions, drainage study filings, and civil engineering review portals.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": one of "SITE_PLAN_SUBMISSION", "GRADING_PLAN", "DRAINAGE_REPORT", "ENGINEERING_REVIEW"
- "project_name": project or development name, or null
- "engineering_firm": engineering firm name, or null
- "developer_entity": developer or applicant name, or null
- "parcel_reference": parcel ID or reference, or null
- "submission_date": date of submission if mentioned, or null
- "latitude": latitude if available, or null
- "longitude": longitude if available, or null
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include real engineering filings related to development, not general infrastructure.
Return ONLY the JSON array."""

    try:
        resp = client.messages.create(
            model=AI_MODEL, max_tokens=3000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[CivilEngineeringCollector] AI extraction error: {e}")
        return []


def _store_engineering_signals(signals, city, state):
    """Store civil engineering signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        developer = (sig.get('developer_entity') or '').strip()
        eng_firm = (sig.get('engineering_firm') or '').strip()
        if not developer and not eng_firm and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'SITE_PLAN_SUBMISSION')
        if signal_type not in CIVIL_ENGINEERING_SIGNAL_SCORES:
            signal_type = 'SITE_PLAN_SUBMISSION'
        metadata = dict(sig)
        metadata['source_collector'] = 'civil_engineering_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, parcel_id, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'civil_engineering',
                developer or eng_firm or None, None,
                city, state, sig.get('parcel_reference'),
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        if developer:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'developer', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), developer, developer.upper().strip()))
            except Exception:
                pass
        if eng_firm:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'engineering_firm', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), eng_firm, eng_firm.upper().strip()))
            except Exception:
                pass
    conn.commit()
    conn.close()
    return stored


def collect_civil_engineering(cities=None):
    """Main entry point: collect civil engineering filing signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[CivilEngineeringCollector] Scanning {city}, {state}...")
        documents = _search_engineering_filings(city, state)
        count = 0
        if documents:
            signals = _extract_engineering_signals(documents, city, state)
            count = _store_engineering_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} civil engineering signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='CIVIL_ENGINEERING',
                        title=f"Civil engineering filings detected — {city}, {state}",
                        description=f"{count} engineering filing signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[CivilEngineeringCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[CivilEngineeringCollector] Done. {total} total signals collected.")
    return total
