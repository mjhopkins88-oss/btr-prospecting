"""
Land Transaction Intelligence Collector.
Detects parcel purchases, deed transfers, and ownership changes that
signal developer land acquisition before development begins.

Signal types:
  LAND_PURCHASE
  DEED_TRANSFER
  OWNER_CHANGE
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


LAND_SIGNAL_SCORES = {
    'LAND_PURCHASE': 30,
    'DEED_TRANSFER': 25,
    'OWNER_CHANGE': 15,
}


def _search_land_transactions(city, state, num=10):
    """Search for land purchases and deed transfers."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} land purchase residential development acreage',
        f'{city} {state} deed transfer developer multifamily subdivision',
    ]
    results = []
    for q in queries:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q, 'tbm': 'nws', 'num': num, 'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[LandTransactionCollector] Search error: {e}")
    # Also search organic results for county records
    try:
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': f'{city} {state} county property deed transfer developer land sale',
            'num': num, 'api_key': SERPAPI_KEY,
        }, timeout=30)
        data = resp.json()
        results.extend(data.get('organic_results', []))
    except Exception as e:
        print(f"[LandTransactionCollector] Portal search error: {e}")
    return results


def _extract_land_signals(documents, city, state):
    """Use Claude to extract land transaction signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about land transactions in {city}, {state}.
Extract any land purchases, deed transfers, or ownership changes related to
residential or multifamily development.

Focus on: large acreage purchases, developer land acquisitions, parcel assemblage,
commercial-to-residential land conversions, and bulk lot sales.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": one of "LAND_PURCHASE", "DEED_TRANSFER", "OWNER_CHANGE"
- "buyer_entity": buyer name or null
- "seller_entity": seller name or null
- "parcel_id": parcel ID or APN if mentioned, or null
- "transaction_date": date if found, or null
- "price": transaction price as string (e.g. "$4,200,000"), or null
- "acreage": acreage if mentioned, or null
- "address": property address or location, or null
- "latitude": latitude if available, or null
- "longitude": longitude if available, or null
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include real land transactions for development, not individual home sales.
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
        print(f"[LandTransactionCollector] AI extraction error: {e}")
        return []


def _store_land_signals(signals, city, state):
    """Store land transaction signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        buyer = (sig.get('buyer_entity') or '').strip()
        if not buyer and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'LAND_PURCHASE')
        if signal_type not in LAND_SIGNAL_SCORES:
            signal_type = 'LAND_PURCHASE'

        metadata = dict(sig)
        metadata['source_collector'] = 'land_transaction_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, parcel_id, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'land_transaction',
                buyer or None, sig.get('address'),
                city, state, sig.get('parcel_id'),
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        # Track buyer entity
        if buyer:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'developer', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), buyer, buyer.upper().strip()))
            except Exception:
                pass
        # Track seller entity
        seller = (sig.get('seller_entity') or '').strip()
        if seller:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'landowner', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), seller, seller.upper().strip()))
            except Exception:
                pass
    conn.commit()
    conn.close()
    return stored


def collect_land_transactions(cities=None):
    """Main entry point: collect land transaction signals for target cities."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[LandTransactionCollector] Scanning {city}, {state}...")
        documents = _search_land_transactions(city, state)
        count = 0
        if documents:
            signals = _extract_land_signals(documents, city, state)
            count = _store_land_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} land transaction signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='LAND_TRANSACTION',
                        title=f"Land transaction signals detected — {city}, {state}",
                        description=f"{count} land purchase/deed transfer signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[LandTransactionCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[LandTransactionCollector] Done. {total} total signals collected.")
    return total
