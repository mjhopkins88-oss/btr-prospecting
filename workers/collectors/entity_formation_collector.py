"""
Development Entity Formation Detection Collector.
Detects new real estate development entities formed before land acquisition.

Signal types:
  DEVELOPMENT_ENTITY_FORMATION
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


ENTITY_FORMATION_SIGNAL_SCORES = {
    'DEVELOPMENT_ENTITY_FORMATION': 20,
}

DEVELOPMENT_KEYWORDS = [
    'development', 'homes', 'construction', 'capital',
    'residential', 'holdings', 'builders', 'communities',
]


def _search_entity_formations(city, state, num=10):
    """Search for new development entity formations."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{state} secretary of state new business filing development homes construction',
        f'{state} new LLC formation residential development builders communities',
        f'{city} {state} new development company formation real estate',
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
            print(f"[EntityFormationCollector] Search error: {e}")
    return results


def _search_opencorporates(state, num=10):
    """Search OpenCorporates for new development entities."""
    if not requests:
        return []
    results = []
    for keyword in ['development', 'homes', 'builders', 'residential']:
        try:
            resp = requests.get('https://api.opencorporates.com/v0.4/companies/search', params={
                'q': keyword,
                'jurisdiction_code': f'us_{state.lower()}',
                'order': 'incorporation_date',
                'per_page': num,
            }, timeout=30)
            data = resp.json()
            companies = data.get('results', {}).get('companies', [])
            for c in companies:
                co = c.get('company', {})
                results.append({
                    'title': co.get('name', ''),
                    'snippet': f"Incorporated {co.get('incorporation_date', '')} in {co.get('jurisdiction_code', '')}",
                    'link': co.get('opencorporates_url', ''),
                    'registered_agent': co.get('agent_name', ''),
                    'incorporation_date': co.get('incorporation_date', ''),
                    'registered_address': co.get('registered_address_in_full', ''),
                })
        except Exception as e:
            print(f"[EntityFormationCollector] OpenCorporates error: {e}")
    return results


def _extract_entity_signals(documents, city, state):
    """Use Claude to extract development entity formation signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:15], indent=2, default=str)

    keywords_str = ', '.join(DEVELOPMENT_KEYWORDS)
    prompt = f"""Analyze these search results about new business entity formations in {state}.
Extract any newly formed entities that appear to be real estate development companies.

Look for entities containing keywords: {keywords_str}

Sources may include Secretary of State business filings, OpenCorporates,
and state corporation databases.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": "DEVELOPMENT_ENTITY_FORMATION"
- "entity_name": the full legal name of the entity
- "registered_agent": registered agent name, or null
- "formation_date": date of formation if mentioned, or null
- "state": state of formation
- "business_address": registered business address, or null
- "description": brief description of why this appears development-related
- "confidence": float 0.0-1.0
- "url": source URL

Only include entities that appear to be real estate development companies.
Filter out general contractors, property management, and unrelated businesses.
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
        print(f"[EntityFormationCollector] AI extraction error: {e}")
        return []


def _store_entity_signals(signals, city, state):
    """Store entity formation signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        entity_name = (sig.get('entity_name') or '').strip()
        if not entity_name:
            continue
        sig_id = str(uuid.uuid4())
        metadata = dict(sig)
        metadata['source_collector'] = 'entity_formation_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, 'DEVELOPMENT_ENTITY_FORMATION', 'entity_formation',
                entity_name, sig.get('business_address'),
                city, sig.get('state', state),
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        # Store entity for future linking to land purchases and signals
        try:
            cur.execute('''
                INSERT OR IGNORE INTO entities
                (id, entity_name, normalized_name, entity_type, created_at)
                VALUES (?, ?, ?, 'development_entity', CURRENT_TIMESTAMP)
            ''', (str(uuid.uuid4()), entity_name, entity_name.upper().strip()))
        except Exception:
            pass
        registered_agent = (sig.get('registered_agent') or '').strip()
        if registered_agent:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'registered_agent', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), registered_agent, registered_agent.upper().strip()))
            except Exception:
                pass
    conn.commit()
    conn.close()
    return stored


def collect_entity_formations(cities=None):
    """Main entry point: collect development entity formation signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    # Deduplicate states to avoid redundant searches
    seen_states = set()
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[EntityFormationCollector] Scanning {city}, {state}...")
        documents = _search_entity_formations(city, state)
        # Add OpenCorporates results if state not yet searched
        if state not in seen_states:
            documents.extend(_search_opencorporates(state))
            seen_states.add(state)
        count = 0
        if documents:
            signals = _extract_entity_signals(documents, city, state)
            count = _store_entity_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} entity formation signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='ENTITY_FORMATION',
                        title=f"Development entity formations detected — {state}",
                        description=f"{count} new development entities found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[EntityFormationCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[EntityFormationCollector] Done. {total} total signals collected.")
    return total
