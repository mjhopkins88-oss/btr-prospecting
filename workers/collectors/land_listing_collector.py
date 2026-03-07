"""
Development Land Listing Collector.
Detects large land listings likely intended for development.

Signal types:
  DEVELOPMENT_LAND_LISTING
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


LAND_LISTING_SIGNAL_SCORES = {
    'DEVELOPMENT_LAND_LISTING': 25,
}

DEVELOPMENT_KEYWORDS = [
    'development', 'build-to-rent', 'subdivision', 'planned community',
    'residential development', 'master planned', 'multifamily',
]


def _search_land_listings(city, state, num=10):
    """Search for large development land listings."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} land for sale development acreage residential subdivision',
        f'{city} {state} LoopNet land listing build-to-rent multifamily development',
        f'{city} {state} commercial land sale planned community master planned',
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
            print(f"[LandListingCollector] Search error: {e}")
    return results


def _extract_listing_signals(documents, city, state):
    """Use Claude to extract development land listing signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    keywords_str = ', '.join(DEVELOPMENT_KEYWORDS)
    prompt = f"""Analyze these search results about land listings in {city}, {state}.
Extract land listings that appear to be intended for residential or multifamily development.

Filter for listings that match these criteria:
- Acreage greater than 10 acres
- Keywords suggesting development intent: {keywords_str}

Sources may include commercial real estate brokerage sites, LoopNet,
broker marketing pages, and land development listing platforms.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": "DEVELOPMENT_LAND_LISTING"
- "acreage": acreage as a number, or null
- "listing_broker": listing broker or brokerage name, or null
- "price": listing price as string (e.g. "$2,500,000"), or null
- "location": address or location description, or null
- "latitude": latitude if available, or null
- "longitude": longitude if available, or null
- "description": brief description of listing and development potential
- "confidence": float 0.0-1.0
- "url": source URL

Only include listings that appear to be large enough for residential development (10+ acres).
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
        print(f"[LandListingCollector] AI extraction error: {e}")
        return []


def _store_listing_signals(signals, city, state):
    """Store land listing signals into property_signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        if not sig.get('description') and not sig.get('location'):
            continue
        sig_id = str(uuid.uuid4())
        metadata = dict(sig)
        metadata['source_collector'] = 'land_listing_collector'
        broker = (sig.get('listing_broker') or '').strip()
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, 'DEVELOPMENT_LAND_LISTING', 'land_listing',
                broker or None, sig.get('location'),
                city, state, json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        if broker:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'broker', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), broker, broker.upper().strip()))
            except Exception:
                pass
    conn.commit()
    conn.close()
    return stored


def collect_land_listings(cities=None):
    """Main entry point: collect development land listing signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[LandListingCollector] Scanning {city}, {state}...")
        documents = _search_land_listings(city, state)
        count = 0
        if documents:
            signals = _extract_listing_signals(documents, city, state)
            count = _store_listing_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} land listing signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='LAND_LISTING',
                        title=f"Development land listings detected — {city}, {state}",
                        description=f"{count} development land listing signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[LandListingCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[LandListingCollector] Done. {total} total signals collected.")
    return total
