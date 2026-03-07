"""
Infrastructure Planning Detection Collector.
Detects development signals from transportation and infrastructure planning,
including traffic impact studies, road expansions, and infrastructure extensions.

Signal types:
  TRAFFIC_IMPACT_STUDY
  ROAD_EXPANSION_APPROVAL
  INFRASTRUCTURE_EXTENSION
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


INFRASTRUCTURE_SIGNAL_SCORES = {
    'TRAFFIC_IMPACT_STUDY': 20,
    'ROAD_EXPANSION_APPROVAL': 25,
    'INFRASTRUCTURE_EXTENSION': 25,
}


def _search_infrastructure(city, state, num=10):
    """Search for infrastructure planning and transportation documents."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} traffic impact study residential development',
        f'{city} {state} road expansion approval new development infrastructure',
        f'{city} {state} city council agenda infrastructure extension subdivision',
        f'{city} {state} DOT transportation planning residential growth',
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
            print(f"[InfrastructureCollector] Search error: {e}")
    return results


def _extract_infrastructure_signals(documents, city, state):
    """Use Claude to extract infrastructure planning signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about infrastructure planning in {city}, {state}.
Extract any traffic impact studies, road expansion approvals, or infrastructure extensions
related to residential or multifamily development.

Sources may include city council agendas, transportation planning documents,
road expansion proposals, traffic impact studies, and DOT infrastructure filings.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": one of "TRAFFIC_IMPACT_STUDY", "ROAD_EXPANSION_APPROVAL", "INFRASTRUCTURE_EXTENSION"
- "project_area": project area or location description, or null
- "developer_entity": developer or applicant name, or null
- "document_date": date of document if mentioned, or null
- "latitude": latitude if available, or null
- "longitude": longitude if available, or null
- "description": brief description
- "confidence": float 0.0-1.0
- "url": source URL

Only include infrastructure planning tied to development activity, not routine road maintenance.
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
        print(f"[InfrastructureCollector] AI extraction error: {e}")
        return []


def _store_infrastructure_signals(signals, city, state):
    """Store infrastructure signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        developer = (sig.get('developer_entity') or '').strip()
        if not developer and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'TRAFFIC_IMPACT_STUDY')
        if signal_type not in INFRASTRUCTURE_SIGNAL_SCORES:
            signal_type = 'TRAFFIC_IMPACT_STUDY'
        metadata = dict(sig)
        metadata['source_collector'] = 'infrastructure_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'infrastructure_planning',
                developer or None, sig.get('project_area'),
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


def _boost_nearby_parcels(city, state):
    """Boost development probability for parcels near infrastructure signals."""
    conn = get_db()
    cur = conn.cursor()
    boosted = 0
    try:
        cur.execute('''
            SELECT DISTINCT p.parcel_id
            FROM parcels p
            JOIN property_signals ps ON ps.city = p.city AND ps.state = p.state
            WHERE ps.signal_type IN ('TRAFFIC_IMPACT_STUDY', 'ROAD_EXPANSION_APPROVAL', 'INFRASTRUCTURE_EXTENSION')
            AND ps.city = ? AND ps.state = ?
            AND p.parcel_id IS NOT NULL
        ''', (city, state))
        parcels = cur.fetchall()
        for (parcel_id,) in parcels:
            cur.execute('''
                UPDATE parcels SET development_probability = MIN(
                    COALESCE(development_probability, 0) + 5, 100
                ) WHERE parcel_id = ?
            ''', (parcel_id,))
            boosted += 1
        conn.commit()
    except Exception as e:
        print(f"[InfrastructureCollector] Boost error: {e}")
    conn.close()
    return boosted


def collect_infrastructure(cities=None):
    """Main entry point: collect infrastructure planning signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[InfrastructureCollector] Scanning {city}, {state}...")
        documents = _search_infrastructure(city, state)
        count = 0
        if documents:
            signals = _extract_infrastructure_signals(documents, city, state)
            count = _store_infrastructure_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} infrastructure signals stored")
                boosted = _boost_nearby_parcels(city, state)
                if boosted:
                    print(f"  -> {boosted} nearby parcels boosted")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='INFRASTRUCTURE_PLANNING',
                        title=f"Infrastructure planning signals detected — {city}, {state}",
                        description=f"{count} infrastructure signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[InfrastructureCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[InfrastructureCollector] Done. {total} total signals collected.")
    return total
