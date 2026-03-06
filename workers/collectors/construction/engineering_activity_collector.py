"""
Engineering Activity Collector (Construction Supply Chain).
Detects civil engineering plans and design activity that precedes construction.
Searches for engineering firm filings, site design submissions,
and civil engineering permits across target markets.
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


# Engineering firms known in BTR/multifamily development
KNOWN_FIRMS = [
    'Kimley-Horn', 'Bohler Engineering', 'Stantec', 'AECOM',
    'Terracon', 'Halff Associates', 'Pacheco Koch', 'Dunaway',
    'Freese and Nichols', 'S&ME', 'Withers Ravenel', 'LJA Engineering',
    'Woolpert', 'Atwell', 'ESP Associates', 'McAdams',
    'Foresite Group', 'Land Design', 'Bowman Consulting',
]


def _search_engineering_plans(city, state, num=8):
    """Search for civil engineering plan filings and submissions."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'civil engineering plan filed {city} {state} residential development',
        f'site design engineering {city} {state} multifamily apartment',
        f'engineering firm hired {city} {state} new residential project',
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
            print(f"[EngActivityCollector] Search error: {e}")
    return results


def _extract_signals(articles, city, state):
    """Extract civil engineering signals using Claude."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(articles[:10], indent=2, default=str)

    prompt = f"""Analyze these articles about engineering activity in {city}, {state}.
Extract signals about civil engineering plans, site design work, or engineering firms
engaged for residential/multifamily/BTR development projects.

Articles:
{text}

Return a JSON array where each element has:
- "engineering_firm": engineering/design firm name
- "developer": developer name if mentioned, or null
- "project_name": project name if mentioned, or null
- "address": address/location if mentioned, or null
- "signal_type": "CIVIL_ENGINEERING_PLAN"
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include items about real engineering engagement, not general news.
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
        print(f"[EngActivityCollector] AI error: {e}")
        return []


def _store_signals(signals, city, state):
    """Store engineering activity signals into property_signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        firm = (sig.get('engineering_firm') or '').strip()
        if not firm:
            continue
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), 'CIVIL_ENGINEERING_PLAN',
                'construction_supply_chain', firm,
                sig.get('address'), city, state,
                json.dumps(sig, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Track entity
        try:
            cur.execute('''
                INSERT OR IGNORE INTO entities
                (id, entity_name, normalized_name, entity_type, created_at)
                VALUES (?, ?, ?, 'engineer', CURRENT_TIMESTAMP)
            ''', (str(uuid.uuid4()), firm, firm.upper().strip()))
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


def collect_engineering_plans(cities=None):
    """Main entry point: collect civil engineering plan signals."""
    cities = cities or TARGET_CITIES
    total = 0
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[EngActivityCollector] Scanning {city}, {state}...")
        articles = _search_engineering_plans(city, state)
        if articles:
            signals = _extract_signals(articles, city, state)
            count = _store_signals(signals, city, state)
            total += count
            if count:
                print(f"  → {count} engineering plan signals")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='SUPPLY_CHAIN',
                        title=f"Civil engineering plans detected — {city}, {state}",
                        description=f"{count} engineering plan signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
    print(f"[EngActivityCollector] Done. {total} signals collected.")
    return total
