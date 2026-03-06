"""
Utility Connection Collector (Construction Supply Chain).
Detects utility connection requests, water/sewer tap applications,
and electrical service requests that precede construction.
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


def _search_utility_activity(city, state, num=8):
    """Search for utility connection and infrastructure requests."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'utility connection request {city} {state} new residential development',
        f'water sewer tap application {city} {state} multifamily apartment',
        f'electrical service request new construction {city} {state}',
    ]
    results = []
    for q in queries[:2]:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q, 'tbm': 'nws', 'num': num, 'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[UtilityCollector] Search error: {e}")
    return results


def _extract_signals(articles, city, state):
    """Extract utility connection signals using Claude."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(articles[:10], indent=2, default=str)

    prompt = f"""Analyze these articles about utility and infrastructure activity in {city}, {state}.
Extract signals about utility connection requests, water/sewer taps, electrical service
requests, or infrastructure work for new residential/multifamily development.

Articles:
{text}

Return a JSON array where each element has:
- "utility_type": "water", "sewer", "electric", "gas", or "combined"
- "developer": developer name if mentioned, or null
- "project_name": project name if mentioned, or null
- "address": address/location if mentioned, or null
- "signal_type": "UTILITY_CONNECTION_REQUEST"
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include items about real utility requests for development, not general infrastructure.
Return ONLY the JSON array."""

    try:
        resp = client.messages.create(
            model=AI_MODEL, max_tokens=2000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[UtilityCollector] AI error: {e}")
        return []


def _store_signals(signals, city, state):
    """Store utility connection signals into property_signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        entity = (sig.get('developer') or sig.get('utility_type') or 'unknown').strip()
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), 'UTILITY_CONNECTION_REQUEST',
                'construction_supply_chain', entity,
                sig.get('address'), city, state,
                json.dumps(sig, default=str),
            ))
            stored += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return stored


def collect_utility_connections(cities=None):
    """Main entry point: collect utility connection signals."""
    cities = cities or TARGET_CITIES
    total = 0
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[UtilityCollector] Scanning {city}, {state}...")
        articles = _search_utility_activity(city, state)
        if articles:
            signals = _extract_signals(articles, city, state)
            count = _store_signals(signals, city, state)
            total += count
            if count:
                print(f"  → {count} utility connection signals")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='SUPPLY_CHAIN',
                        title=f"Utility connection requests detected — {city}, {state}",
                        description=f"{count} utility connection signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
    print(f"[UtilityCollector] Done. {total} signals collected.")
    return total
