"""
Secretary of State Entity Watcher.
Monitors state business registration portals for new LLC formations,
developer expansions, and registered agent relationships.
Inserts results into property_signals with LLC_FORMATION or DEVELOPER_EXPANSION type.
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


# Known SOS search portals (free web interfaces)
SOS_SEARCH_QUERIES = {
    'TX': 'site:sos.state.tx.us new LLC formation real estate development',
    'AZ': 'site:azcc.gov new LLC formation real estate development',
    'NC': 'site:sosnc.gov new LLC formation real estate development',
    'GA': 'site:sos.ga.gov new LLC formation real estate development',
    'FL': 'site:dos.myflorida.com new LLC formation real estate development',
    'TN': 'site:sos.tn.gov new LLC formation real estate development',
    'CO': 'site:sos.state.co.us new LLC formation real estate development',
}

# Keywords that indicate development-related LLC formations
DEV_KEYWORDS = [
    'development', 'residential', 'land', 'property', 'properties',
    'homes', 'housing', 'realty', 'builders', 'construction',
    'capital', 'invest', 'holdings', 'ventures', 'communities',
    'btr', 'rental', 'multifamily', 'apartments',
]


def _search_sos_filings(state, city=None, num=10):
    """Search for recent LLC formations via SerpAPI (free tier)."""
    if not SERPAPI_KEY or not requests:
        return []

    base_query = SOS_SEARCH_QUERIES.get(state, '')
    if city:
        query = f"{city} {state} new LLC formation real estate development"
    elif base_query:
        query = base_query
    else:
        query = f"{state} secretary of state new LLC real estate development"

    try:
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': query,
            'num': num,
            'api_key': SERPAPI_KEY,
        }, timeout=30)
        data = resp.json()
        return data.get('organic_results', []) + data.get('news_results', [])
    except Exception as e:
        print(f"[EntityWatcher] Search error for {state}: {e}")
        return []


def _extract_entities_with_ai(results, city, state):
    """Use Claude to extract LLC formation signals from search results."""
    if not ANTHROPIC_API_KEY or not anthropic or not results:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(results[:10], indent=2, default=str)

    prompt = f"""Analyze these search results about business filings in {city}, {state}.
Extract any LLC formations, business registrations, or entity changes
that appear related to real estate development, land acquisition, or construction.

Results:
{text}

Return a JSON array where each element has:
- "entity_name": the LLC or company name
- "signal_type": "LLC_FORMATION" or "DEVELOPER_EXPANSION"
- "registered_agent": registered agent name if found, or null
- "city": city if mentioned, or "{city}"
- "state": "{state}"
- "formation_date": date if found, or null
- "related_developer": parent developer if identifiable, or null
- "address": registered address if found, or null
- "confidence": float 0.0-1.0

Only include entities that appear related to real estate/development.
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
        print(f"[EntityWatcher] AI extraction error: {e}")
        return []


def _is_dev_related(name):
    """Quick heuristic: does the entity name suggest development activity?"""
    lower = (name or '').lower()
    return any(kw in lower for kw in DEV_KEYWORDS)


def _store_entity_signals(entities, city, state):
    """Store entity signals into property_signals and entities tables."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for ent in entities:
        entity_name = ent.get('entity_name', '').strip()
        if not entity_name:
            continue

        sig_id = str(uuid.uuid4())
        signal_type = ent.get('signal_type', 'LLC_FORMATION')
        ent_city = ent.get('city') or city
        ent_state = ent.get('state') or state

        # Insert into property_signals
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'secretary_of_state',
                entity_name, ent.get('address'),
                ent_city, ent_state,
                json.dumps(ent, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Also insert/update entities table
        try:
            ent_id = str(uuid.uuid4())
            normalized = entity_name.upper().strip()
            parent = ent.get('related_developer')
            cur.execute('''
                INSERT OR IGNORE INTO entities
                (id, entity_name, normalized_name, entity_type,
                 parent_entity, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                ent_id, entity_name, normalized,
                'llc', parent,
                json.dumps(ent, default=str),
            ))
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


def watch_entities(cities=None):
    """
    Main entry point: scan for new entity formations across target markets.
    """
    cities = cities or TARGET_CITIES
    total = 0

    for market in cities:
        city, state = market['city'], market['state']
        print(f"[EntityWatcher] Scanning {city}, {state}...")

        results = _search_sos_filings(state, city, num=10)
        if results:
            entities = _extract_entities_with_ai(results, city, state)
            count = _store_entity_signals(entities, city, state)
            total += count
            print(f"  → {count} entity signals stored")

            # Emit intelligence event for significant findings
            if count >= 3:
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='ENTITY_FORMATION',
                        title=f"New LLC formations detected — {city}, {state}",
                        description=f"{count} development-related entities found",
                        city=city,
                        state=state,
                    )
                except Exception:
                    pass

    print(f"[EntityWatcher] Done. {total} total entity signals collected.")
    return total
