"""
Construction Financing Intelligence Collector.
Detects construction loans and commercial mortgages that signal
imminent development activity.

Signal types:
  CONSTRUCTION_FINANCING
  COMMERCIAL_MORTGAGE
  SECURED_LOAN
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


FINANCING_SIGNAL_SCORES = {
    'CONSTRUCTION_FINANCING': 45,
    'COMMERCIAL_MORTGAGE': 35,
    'SECURED_LOAN': 25,
}


def _search_financing(city, state, num=10):
    """Search for construction financing and commercial mortgages."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} construction loan multifamily apartment development',
        f'{city} {state} commercial mortgage residential development financing',
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
            print(f"[FinancingCollector] Search error: {e}")
    return results


def _extract_financing_signals(documents, city, state):
    """Use Claude to extract financing signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these articles about construction financing in {city}, {state}.
Extract any construction loans, commercial mortgages, or secured lending
for residential or multifamily development projects.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": one of "CONSTRUCTION_FINANCING", "COMMERCIAL_MORTGAGE", "SECURED_LOAN"
- "borrower": borrower or developer name, or null
- "lender": lender or bank name, or null
- "loan_amount": loan amount as string (e.g. "$48,000,000"), or null
- "property_address": property address, or null
- "parcel_reference": parcel ID if mentioned, or null
- "project_name": project name if mentioned, or null
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include real construction/development financing, not consumer mortgages.
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
        print(f"[FinancingCollector] AI extraction error: {e}")
        return []


def _store_financing_signals(signals, city, state):
    """Store financing signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        borrower = (sig.get('borrower') or '').strip()
        if not borrower and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'CONSTRUCTION_FINANCING')
        if signal_type not in FINANCING_SIGNAL_SCORES:
            signal_type = 'CONSTRUCTION_FINANCING'
        metadata = dict(sig)
        metadata['source_collector'] = 'construction_financing_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, parcel_id, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'construction_financing',
                borrower or None, sig.get('property_address'),
                city, state, sig.get('parcel_reference'),
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        if borrower:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'developer', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), borrower, borrower.upper().strip()))
            except Exception:
                pass
        lender = (sig.get('lender') or '').strip()
        if lender:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'lender', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), lender, lender.upper().strip()))
            except Exception:
                pass
    conn.commit()
    conn.close()
    return stored


def collect_construction_financing(cities=None):
    """Main entry point: collect construction financing signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[FinancingCollector] Scanning {city}, {state}...")
        documents = _search_financing(city, state)
        count = 0
        if documents:
            signals = _extract_financing_signals(documents, city, state)
            count = _store_financing_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} financing signals stored")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='CONSTRUCTION_FINANCING',
                        title=f"Construction financing detected — {city}, {state}",
                        description=f"{count} construction financing signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[FinancingCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[FinancingCollector] Done. {total} total signals collected.")
    return total
