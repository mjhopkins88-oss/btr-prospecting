"""
Engineering / Contractor Signal Tracker.
Detects engineering firm filings, civil engineering permits,
site surveys, and utility planning documents.
Inserts ENGINEERING_ENGAGEMENT signals into property_signals.
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


# Known engineering firms active in BTR/multifamily
KNOWN_ENGINEERING_FIRMS = [
    'Kimley-Horn', 'Kimley Horn',
    'Bohler Engineering', 'Bohler',
    'Stantec',
    'AECOM',
    'Terracon',
    'Halff Associates', 'Halff',
    'Pacheco Koch',
    'Dunaway Associates',
    'Freese and Nichols',
    'Lockwood Andrews Newnam',
    'S&ME',
    'Terracon Consultants',
    'Withers Ravenel',
    'LJA Engineering',
    'Woolpert',
]


def _search_engineering_activity(city, state, num=10):
    """Search for engineering firm activity via SerpAPI."""
    if not SERPAPI_KEY or not requests:
        return []

    queries = [
        f'civil engineering site plan {city} {state} residential development',
        f'engineering firm multifamily project {city} {state}',
        f'site survey filed {city} {state} residential',
    ]
    results = []
    for q in queries:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q,
                'tbm': 'nws',
                'num': num,
                'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[EngineeringActivity] Search error: {e}")
    return results


def _extract_engineering_signals(articles, city, state):
    """Use Claude to extract engineering engagement signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    articles_text = json.dumps(articles[:8], indent=2, default=str)

    prompt = f"""Analyze these articles about engineering and development activity in {city}, {state}.
Extract any signals about engineering firms working on residential/multifamily projects,
site surveys being filed, civil engineering permits, or utility planning.

Articles:
{articles_text}

Return a JSON array where each element has:
- "engineering_firm": name of the engineering/survey firm
- "project_name": project name if mentioned
- "developer": developer name if mentioned
- "address": project address if mentioned
- "signal_type": one of "ENGINEERING_ENGAGEMENT", "UTILITY_APPLICATION", "SITE_PLAN_SUBMISSION"
- "description": brief description of the activity
- "confidence": float 0.0-1.0
- "url": source URL

Return ONLY the JSON array."""

    try:
        resp = client.messages.create(
            model=AI_MODEL,
            max_tokens=2000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[EngineeringActivity] AI extraction error: {e}")
        return []


def _store_engineering_signals(signals, city, state):
    """Store engineering engagement signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for sig in signals:
        eng_firm = sig.get('engineering_firm', '').strip()
        if not eng_firm:
            continue

        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'ENGINEERING_ENGAGEMENT')

        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'engineering_search',
                eng_firm, sig.get('address'),
                city, state,
                json.dumps(sig, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Track the engineering firm as an entity
        try:
            cur.execute('''
                INSERT OR IGNORE INTO entities
                (id, entity_name, normalized_name, entity_type, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), eng_firm,
                eng_firm.upper().strip(), 'engineer',
            ))
        except Exception:
            pass

        # If developer is mentioned, create relationship
        developer = sig.get('developer', '').strip()
        if developer and eng_firm:
            try:
                cur.execute('''
                    SELECT id FROM entity_relationships
                    WHERE entity_a = ? AND entity_b = ?
                    AND relationship_type = 'ENGINEER_FOR_DEVELOPER'
                    LIMIT 1
                ''', (eng_firm, developer))
                if not cur.fetchone():
                    cur.execute('''
                        INSERT INTO entity_relationships
                        (id, entity_a, entity_a_type, entity_b, entity_b_type,
                         relationship_type, source, confidence, created_at)
                        VALUES (?, ?, 'engineer', ?, 'developer',
                                'ENGINEER_FOR_DEVELOPER', 'engineering_search', ?,
                                CURRENT_TIMESTAMP)
                    ''', (
                        str(uuid.uuid4()), eng_firm, developer,
                        int(float(sig.get('confidence', 0.5)) * 100),
                    ))
            except Exception:
                pass

    conn.commit()
    conn.close()
    return stored


def collect_engineering_activity(cities=None):
    """Main entry point: collect engineering engagement signals."""
    cities = cities or TARGET_CITIES
    total = 0

    for market in cities:
        city, state = market['city'], market['state']
        print(f"[EngineeringActivity] Scanning {city}, {state}...")

        articles = _search_engineering_activity(city, state, num=5)
        if articles:
            signals = _extract_engineering_signals(articles, city, state)
            count = _store_engineering_signals(signals, city, state)
            total += count
            print(f"  → {count} engineering signals stored")

            if count >= 2:
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='ENGINEERING_SIGNAL',
                        title=f"Engineering engagement detected — {city}, {state}",
                        description=f"{count} engineering activity signals found",
                        city=city,
                        state=state,
                    )
                except Exception:
                    pass

    print(f"[EngineeringActivity] Done. {total} total signals collected.")
    return total
