"""
Autonomous Data Source Discovery Engine.
Discovers new public data sources for BTR/multifamily development intelligence.

Searches for:
  - City/county open data portals
  - GIS parcel viewers
  - Building permit databases
  - Planning commission meeting archives
  - Court filing systems (deed records)
  - Construction bid platforms

Stores discovered sources in data_sources table for collector use.
"""
import json
import os
import uuid
from datetime import datetime

from db import get_db
from shared.config import TARGET_CITIES

SERPAPI_KEY = os.getenv('SERPAPI_API_KEY', '')

# Source type definitions
SOURCE_TYPES = {
    'OPEN_DATA_PORTAL': {
        'queries': [
            '{city} {state} open data portal',
            '{city} {state} city data catalog',
        ],
        'priority': 90,
    },
    'GIS_PARCEL_VIEWER': {
        'queries': [
            '{city} {state} GIS parcel viewer',
            '{county} county property map viewer',
        ],
        'priority': 85,
    },
    'PERMIT_DATABASE': {
        'queries': [
            '{city} {state} building permit search',
            '{city} {state} online permit portal',
        ],
        'priority': 80,
    },
    'PLANNING_COMMISSION': {
        'queries': [
            '{city} {state} planning commission agendas',
            '{city} {state} city council meeting minutes development',
        ],
        'priority': 75,
    },
    'DEED_RECORDS': {
        'queries': [
            '{county} county deed records search',
            '{county} county recorder of deeds online',
        ],
        'priority': 70,
    },
    'CONSTRUCTION_BIDS': {
        'queries': [
            '{city} {state} construction bid opportunities',
            '{state} government construction bids RFP',
        ],
        'priority': 65,
    },
}


def _search_for_sources(query):
    """Search for data sources using SerpAPI."""
    if not SERPAPI_KEY:
        return []

    try:
        import requests
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': query,
            'api_key': SERPAPI_KEY,
            'num': 5,
        }, timeout=15)

        if resp.status_code != 200:
            return []

        data = resp.json()
        results = []
        for r in data.get('organic_results', [])[:5]:
            results.append({
                'title': r.get('title', ''),
                'url': r.get('link', ''),
                'snippet': r.get('snippet', ''),
            })
        return results
    except Exception as e:
        print(f"[SourceDiscovery] Search error: {e}")
        return []


def _store_source(source_type, city, state, title, url, snippet, priority):
    """Store a discovered data source."""
    conn = get_db()
    cur = conn.cursor()

    try:
        # Check for duplicates by URL
        cur.execute(
            'SELECT id FROM data_sources WHERE url = ?', (url,)
        )
        if cur.fetchone():
            conn.close()
            return False

        cur.execute('''
            INSERT INTO data_sources
            (id, source_type, city, state, title, url, description,
             priority, status, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'discovered', CURRENT_TIMESTAMP)
        ''', (
            str(uuid.uuid4()), source_type, city, state,
            title, url, snippet, priority,
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[SourceDiscovery] Storage error: {e}")
        conn.close()
        return False


def discover_sources(cities=None):
    """
    Discover new data sources for target cities.
    Returns count of newly discovered sources.
    """
    print(f"[SourceDiscovery] START — {datetime.utcnow().isoformat()}")

    if cities is None:
        cities = TARGET_CITIES

    discovered = 0

    for market in cities:
        city = market['city']
        state = market['state']
        county = market.get('county', city)

        for source_type, config in SOURCE_TYPES.items():
            for query_template in config['queries']:
                query = query_template.format(
                    city=city, state=state, county=county,
                )
                results = _search_for_sources(query)

                for result in results:
                    if not result.get('url'):
                        continue
                    # Filter for government/official sources
                    url = result['url'].lower()
                    is_gov = any(d in url for d in ['.gov', '.us', '.org', 'gis', 'arcgis'])
                    if not is_gov:
                        continue

                    stored = _store_source(
                        source_type=source_type,
                        city=city,
                        state=state,
                        title=result['title'],
                        url=result['url'],
                        snippet=result.get('snippet', ''),
                        priority=config['priority'],
                    )
                    if stored:
                        discovered += 1
                        print(f"  Discovered: [{source_type}] {result['title'][:60]} — {city}, {state}")

    print(f"[SourceDiscovery] COMPLETE — {discovered} new sources discovered")
    return discovered


def get_sources_for_city(city, state, source_type=None):
    """Get discovered data sources for a specific city."""
    conn = get_db()
    cur = conn.cursor()

    sql = '''
        SELECT id, source_type, title, url, description, priority, status
        FROM data_sources
        WHERE city = ? AND state = ?
    '''
    params = [city, state]

    if source_type:
        sql += ' AND source_type = ?'
        params.append(source_type)

    sql += ' ORDER BY priority DESC'

    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()

    return [
        {
            'id': r[0], 'source_type': r[1], 'title': r[2],
            'url': r[3], 'description': r[4], 'priority': r[5],
            'status': r[6],
        }
        for r in rows
    ]


def run_source_discovery():
    """Full source discovery cycle."""
    return discover_sources()
