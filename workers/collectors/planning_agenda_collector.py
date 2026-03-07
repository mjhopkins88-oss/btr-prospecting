"""
Planning Agenda Intelligence Collector.
Detects development signals from city planning commission agendas,
zoning board documents, and site plan review case lists.

Planning agendas often reveal development projects months before
permits or construction activity become visible.

Signal types:
  ZONING_AGENDA_ITEM
  SITE_PLAN_SUBMISSION
  SUBDIVISION_APPLICATION
  REZONING_REQUEST
  DEVELOPMENT_REVIEW_CASE
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


# Signal confidence scores — feed into development_probability scoring
PLANNING_SIGNAL_SCORES = {
    'REZONING_REQUEST': 30,
    'SITE_PLAN_SUBMISSION': 35,
    'SUBDIVISION_APPLICATION': 25,
    'DEVELOPMENT_REVIEW_CASE': 20,
    'ZONING_AGENDA_ITEM': 20,
}

# Keywords indicating development-related agenda items
PLANNING_KEYWORDS = [
    'rezoning', 'site plan', 'subdivision', 'development review',
    'conditional use permit', 'planned unit development', 'PUD',
    'multifamily', 'single family rental', 'residential',
    'build to rent', 'BTR', 'apartments', 'townhomes',
    'mixed use', 'density', 'variance', 'special use',
]


def _search_planning_agendas(city, state, num=8):
    """Search for city planning commission agendas and zoning board documents."""
    if not SERPAPI_KEY or not requests:
        return []

    queries = [
        f'{city} {state} planning commission agenda residential development',
        f'{city} {state} zoning board meeting rezoning multifamily',
        f'{city} {state} site plan review development case subdivision',
    ]
    results = []
    for q in queries[:2]:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q, 'num': num, 'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('organic_results', []))
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[PlanningAgendaCollector] Search error: {e}")
    return results


def _extract_planning_signals(documents, city, state):
    """Use Claude to extract planning agenda signals from search results."""
    if not ANTHROPIC_API_KEY or not anthropic or not documents:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    text = json.dumps(documents[:12], indent=2, default=str)

    prompt = f"""Analyze these search results about planning commission agendas and zoning board
documents in {city}, {state}. Extract any development-related agenda items, site plan
submissions, rezoning requests, subdivision applications, or development review cases.

Focus on items mentioning residential, multifamily, BTR, single family rental, apartments,
townhomes, or mixed-use development.

Documents:
{text}

Return a JSON array where each element has:
- "developer": developer or applicant name if mentioned, or null
- "project_name": project name if mentioned, or null
- "location": address or location description if mentioned, or null
- "parcel_reference": parcel ID or APN if mentioned, or null
- "unit_count": number of units if mentioned, or null
- "signal_type": one of "REZONING_REQUEST", "SITE_PLAN_SUBMISSION", "SUBDIVISION_APPLICATION", "DEVELOPMENT_REVIEW_CASE", "ZONING_AGENDA_ITEM"
- "description": brief description of the agenda item
- "meeting_date": meeting date if found, or null
- "confidence": float 0.0-1.0
- "url": source URL

Only include items about real development proposals, not general policy discussions.
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
        print(f"[PlanningAgendaCollector] AI extraction error: {e}")
        return []


def _store_planning_signals(signals, city, state):
    """Store planning agenda signals into property_signals and entities."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for sig in signals:
        developer = (sig.get('developer') or '').strip()
        description = (sig.get('description') or '').strip()
        if not developer and not description:
            continue

        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'ZONING_AGENDA_ITEM')
        # Validate signal type
        if signal_type not in PLANNING_SIGNAL_SCORES:
            signal_type = 'ZONING_AGENDA_ITEM'

        location = sig.get('location') or sig.get('address')

        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, parcel_id, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'planning_agenda',
                developer or None, location,
                city, state,
                sig.get('parcel_reference'),
                json.dumps(sig, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Track developer as entity if present
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


def collect_planning_agendas(cities=None):
    """
    Main entry point: collect planning agenda signals for target cities.
    Scans planning commission pages for agenda documents, zoning board
    case lists, and site plan review items.
    """
    cities = cities or TARGET_CITIES
    total = 0
    city_counts = {}

    for market in cities:
        city, state = market['city'], market['state']
        print(f"[PlanningAgendaCollector] Scanning {city}, {state}...")

        documents = _search_planning_agendas(city, state)
        count = 0
        if documents:
            signals = _extract_planning_signals(documents, city, state)
            count = _store_planning_signals(signals, city, state)
            total += count
            if count:
                print(f"  -> {count} planning signals stored")

                # Emit intelligence event
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='PLANNING_SIGNAL',
                        title=f"Planning agenda signals detected — {city}, {state}",
                        description=f"{count} planning/zoning signals found from commission agendas",
                        city=city,
                        state=state,
                    )
                except Exception:
                    pass
        else:
            print(f"  -> 0 documents found")

        city_counts[f"{city} {state}"] = count

    # Summary
    print(f"\n[PlanningAgendaCollector] SUMMARY")
    for city_label, count in city_counts.items():
        print(f"  {city_label}: {count} signals detected")
    print(f"[PlanningAgendaCollector] Done. {total} total planning signals collected.")
    return total
