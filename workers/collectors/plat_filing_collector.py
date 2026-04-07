"""
Subdivision Plat Filing Intelligence Collector.
Detects subdivision plat filings that appear before permits or construction.

Signal types:
  SUBDIVISION_PLAT
  PRELIMINARY_PLAT
  FINAL_PLAT
  LOT_SPLIT
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


PLAT_SIGNAL_SCORES = {
    'SUBDIVISION_PLAT': 30,
    'PRELIMINARY_PLAT': 25,
    'FINAL_PLAT': 35,
    'LOT_SPLIT': 20,
}


def _search_plat_filings(city, state, num=10):
    """Search for subdivision plat filings."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} subdivision plat filing residential development',
        f'{city} {state} preliminary plat final plat multifamily lots',
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
            print(f"[PlatFilingCollector] Search error: {e}")
    return results


def _extract_plat_signals(documents, city, state):
    """Use Claude to extract plat filing signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about subdivision plat filings in {city}, {state}.
Extract any subdivision plats, preliminary plats, final plats, or lot splits
related to residential or multifamily development.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": one of "SUBDIVISION_PLAT", "PRELIMINARY_PLAT", "FINAL_PLAT", "LOT_SPLIT"
- "developer": developer or applicant name, or null
- "project_name": project or subdivision name, or null
- "lot_count": number of lots if mentioned, or null
- "acreage": total acreage if mentioned, or null
- "location": address or location description, or null
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include real subdivision plat filings, not general zoning discussions.
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
        print(f"[PlatFilingCollector] AI extraction error: {e}")
        return []


def _store_plat_signals(signals, city, state):
    """Store plat filing signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        developer = (sig.get('developer') or '').strip()
        if not developer and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'SUBDIVISION_PLAT')
        if signal_type not in PLAT_SIGNAL_SCORES:
            signal_type = 'SUBDIVISION_PLAT'
        metadata = dict(sig)
        metadata['source_collector'] = 'plat_filing_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'plat_filing',
                developer or None, sig.get('location'),
                city, state, json.dumps(metadata, default=str),
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
    conn.commit()
    conn.close()
    return stored


def collect_plat_filings(cities=None):
    """Main entry point: collect plat filing signals for target cities."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[PlatFilingCollector] Scanning {city}, {state}...")
        documents = _search_plat_filings(city, state)
        count = 0
        if documents:
            signals = _extract_plat_signals(documents, city, state)
            count = _store_plat_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} plat filing signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='PLAT_FILING',
                        title=f"Plat filing signals detected — {city}, {state}",
                        description=f"{count} subdivision plat signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[PlatFilingCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[PlatFilingCollector] Done. {total} total signals collected.")
    return total
