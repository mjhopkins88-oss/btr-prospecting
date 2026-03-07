"""
Utility Connection Intelligence Collector.
Detects early development signals from utility service requests,
capacity expansions, and new service applications.

Signal types:
  UTILITY_CONNECTION_REQUEST
  UTILITY_CAPACITY_EXPANSION
  NEW_SERVICE_APPLICATION
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


UTILITY_SIGNAL_SCORES = {
    'UTILITY_CONNECTION_REQUEST': 25,
    'UTILITY_CAPACITY_EXPANSION': 30,
    'NEW_SERVICE_APPLICATION': 20,
}


def _search_utility_connections(city, state, num=10):
    """Search for utility connection requests and service applications."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} utility connection request residential development water sewer',
        f'{city} {state} water authority meeting minutes new service application',
        f'{city} {state} electric utility infrastructure filing capacity expansion',
        f'{city} {state} sewer district permit new development connection',
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
            print(f"[UtilityConnectionCollector] Search error: {e}")
    return results


def _extract_utility_signals(documents, city, state):
    """Use Claude to extract utility connection signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about utility connections and service requests in {city}, {state}.
Extract any utility connection requests, capacity expansions, or new service applications
related to residential or multifamily development.

Sources may include city utility board agendas, water authority meeting minutes,
electric utility infrastructure filings, and sewer district permit logs.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": one of "UTILITY_CONNECTION_REQUEST", "UTILITY_CAPACITY_EXPANSION", "NEW_SERVICE_APPLICATION"
- "project_name": project or development name, or null
- "applicant_entity": applicant or developer name, or null
- "utility_type": type of utility (water, sewer, electric, gas), or null
- "service_address": service address or location, or null
- "request_date": date of request if mentioned, or null
- "latitude": latitude if available, or null
- "longitude": longitude if available, or null
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include real utility service requests related to development, not routine maintenance.
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
        print(f"[UtilityConnectionCollector] AI extraction error: {e}")
        return []


def _store_utility_signals(signals, city, state):
    """Store utility connection signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        applicant = (sig.get('applicant_entity') or '').strip()
        if not applicant and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'UTILITY_CONNECTION_REQUEST')
        if signal_type not in UTILITY_SIGNAL_SCORES:
            signal_type = 'UTILITY_CONNECTION_REQUEST'
        metadata = dict(sig)
        metadata['source_collector'] = 'utility_connection_collector'
        metadata['utility_type'] = sig.get('utility_type')
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'utility_connection',
                applicant or None, sig.get('service_address'),
                city, state, json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        if applicant:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'developer', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), applicant, applicant.upper().strip()))
            except Exception:
                pass
    conn.commit()
    conn.close()
    return stored


def collect_utility_connections_intel(cities=None):
    """Main entry point: collect utility connection intelligence signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[UtilityConnectionCollector] Scanning {city}, {state}...")
        documents = _search_utility_connections(city, state)
        count = 0
        if documents:
            signals = _extract_utility_signals(documents, city, state)
            count = _store_utility_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} utility connection signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='UTILITY_CONNECTION',
                        title=f"Utility connection signals detected — {city}, {state}",
                        description=f"{count} utility connection signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[UtilityConnectionCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[UtilityConnectionCollector] Done. {total} total signals collected.")
    return total
