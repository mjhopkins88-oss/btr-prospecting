"""
Construction Hiring Signal Detection Collector.
Detects development signals from contractor hiring activity,
job postings, and project staffing announcements.

Signal types:
  CONSTRUCTION_HIRING_SIGNAL
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


HIRING_SIGNAL_SCORES = {
    'CONSTRUCTION_HIRING_SIGNAL': 15,
}


def _search_hiring_signals(city, state, num=10):
    """Search for construction hiring and contractor staffing activity."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'{city} {state} construction hiring multifamily residential development jobs',
        f'{city} {state} contractor hiring project superintendent apartment construction',
        f'{city} {state} construction job posting site manager residential builder',
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
            print(f"[ConstructionHiringCollector] Search error: {e}")
    return results


def _extract_hiring_signals(documents, city, state):
    """Use Claude to extract construction hiring signals."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about construction hiring in {city}, {state}.
Extract any construction hiring activity, job postings, or staffing signals
that indicate upcoming residential or multifamily development projects.

Sources may include construction job boards, LinkedIn job postings,
contractor websites, and project hiring announcements.

Documents:
{text}

Return a JSON array where each element has:
- "signal_type": "CONSTRUCTION_HIRING_SIGNAL"
- "contractor_name": contractor or construction company name, or null
- "project_location": project location or job site, or null
- "job_title": job title being hired for, or null
- "posting_date": date of posting if mentioned, or null
- "description": brief description of hiring signal and its development implications
- "confidence": float 0.0-1.0
- "url": source URL

Only include hiring signals related to residential/multifamily construction projects.
Exclude general staffing agency postings without specific project ties.
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
        print(f"[ConstructionHiringCollector] AI extraction error: {e}")
        return []


def _store_hiring_signals(signals, city, state):
    """Store construction hiring signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        contractor = (sig.get('contractor_name') or '').strip()
        if not contractor and not sig.get('description'):
            continue
        sig_id = str(uuid.uuid4())
        metadata = dict(sig)
        metadata['source_collector'] = 'construction_hiring_collector'
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, 'CONSTRUCTION_HIRING_SIGNAL', 'construction_hiring',
                contractor or None, sig.get('project_location'),
                city, state, json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass
        if contractor:
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


def _cluster_and_boost(city, state):
    """Cluster hiring signals geographically and boost development probability."""
    conn = get_db()
    cur = conn.cursor()
    boosted = 0
    try:
        # Count hiring signals in this city
        cur.execute('''
            SELECT COUNT(*) FROM property_signals
            WHERE signal_type = 'CONSTRUCTION_HIRING_SIGNAL'
            AND city = ? AND state = ?
        ''', (city, state))
        hiring_count = cur.fetchone()[0]

        # If multiple hiring signals in same area, boost nearby parcels
        if hiring_count >= 3:
            boost = min(hiring_count * 3, 15)
            cur.execute('''
                UPDATE parcels SET development_probability = MIN(
                    COALESCE(development_probability, 0) + ?, 100
                ) WHERE city = ? AND state = ? AND parcel_id IS NOT NULL
            ''', (boost, city, state))
            boosted = cur.rowcount
            conn.commit()
    except Exception as e:
        print(f"[ConstructionHiringCollector] Cluster boost error: {e}")
    conn.close()
    return boosted


def collect_construction_hiring(cities=None):
    """Main entry point: collect construction hiring signals."""
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[ConstructionHiringCollector] Scanning {city}, {state}...")
        documents = _search_hiring_signals(city, state)
        count = 0
        if documents:
            signals = _extract_hiring_signals(documents, city, state)
            count = _store_hiring_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} construction hiring signals stored")
                boosted = _cluster_and_boost(city, state)
                if boosted:
                    print(f"  -> {boosted} nearby parcels boosted (hiring cluster)")
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='CONSTRUCTION_HIRING',
                        title=f"Construction hiring signals detected — {city}, {state}",
                        description=f"{count} construction hiring signals found",
                        city=city, state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")
        city_counts[f"{city} {state}"] = count

    print(f"\n[ConstructionHiringCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[ConstructionHiringCollector] Done. {total} total signals collected.")
    return total
