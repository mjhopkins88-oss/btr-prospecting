"""
Contractor Bid Collector (Construction Supply Chain).
Detects contractor bids, earthwork contracts, concrete supply signals,
and infrastructure bids that indicate imminent construction.
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


def _search_contractor_bids(city, state, num=8):
    """Search for contractor bids and construction contract activity."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'contractor bid residential construction {city} {state}',
        f'earthwork contract awarded {city} {state} development',
        f'concrete supply bid multifamily {city} {state}',
        f'infrastructure bid residential {city} {state}',
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
            print(f"[ContractorBidCollector] Search error: {e}")
    return results


def _extract_signals(articles, city, state):
    """Extract contractor bid signals using Claude."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(articles[:10], indent=2, default=str)

    prompt = f"""Analyze these articles about contractor and construction activity in {city}, {state}.
Extract signals about contractor bids, earthwork contracts, concrete supply,
infrastructure bids, or construction contract awards for residential/multifamily projects.

Articles:
{text}

Return a JSON array where each element has:
- "contractor": contractor/company name
- "bid_type": "earthwork", "concrete", "infrastructure", "general", or "other"
- "developer": developer name if mentioned, or null
- "project_name": project name if mentioned, or null
- "address": address/location if mentioned, or null
- "signal_type": one of "EARTHWORK_CONTRACTOR", "CONCRETE_SUPPLY_SIGNAL", "INFRASTRUCTURE_BID"
- "description": brief description
- "estimated_value": contract value if mentioned, or null
- "confidence": float 0.0-1.0
- "url": source URL

Only include items about real construction bids/contracts for development.
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
        print(f"[ContractorBidCollector] AI error: {e}")
        return []


def _store_signals(signals, city, state):
    """Store contractor bid signals into property_signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        contractor = (sig.get('contractor') or '').strip()
        if not contractor:
            continue
        signal_type = sig.get('signal_type', 'INFRASTRUCTURE_BID')
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), signal_type,
                'construction_supply_chain', contractor,
                sig.get('address'), city, state,
                json.dumps(sig, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Track contractor entity
        try:
            cur.execute('''
                INSERT OR IGNORE INTO entities
                (id, entity_name, normalized_name, entity_type, created_at)
                VALUES (?, ?, ?, 'contractor', CURRENT_TIMESTAMP)
            ''', (str(uuid.uuid4()), contractor, contractor.upper().strip()))
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


def collect_contractor_bids(cities=None):
    """Main entry point: collect contractor bid signals."""
    cities = cities or TARGET_CITIES
    total = 0
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[ContractorBidCollector] Scanning {city}, {state}...")
        articles = _search_contractor_bids(city, state)
        if articles:
            signals = _extract_signals(articles, city, state)
            count = _store_signals(signals, city, state)
            total += count
            if count:
                print(f"  → {count} contractor bid signals")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='SUPPLY_CHAIN',
                        title=f"Contractor bid activity detected — {city}, {state}",
                        description=f"{count} contractor/infrastructure bid signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
    print(f"[ContractorBidCollector] Done. {total} signals collected.")
    return total
