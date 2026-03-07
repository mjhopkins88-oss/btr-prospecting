"""
Autonomous Signal Discovery AI.
Automatically discovers new development data sources across cities.

Scans government websites to identify:
  - Permit dashboards
  - Planning commission pages
  - Zoning case portals
  - GIS open data portals
  - ArcGIS datasets
  - City open data portals

When a potential data source is detected, adds it to data_sources with
confidence_score and priority_score. Collectors automatically attempt
ingestion from discovered sources.

If ingestion succeeds: increase priority_score.
If ingestion repeatedly fails: decrease priority_score.

Extends the existing source_discovery_engine with AI-driven discovery,
automatic ingestion testing, and adaptive priority scoring.
"""
import json
import os
import re
import uuid
from datetime import datetime, timedelta

from db import get_db
from shared.config import TARGET_CITIES

SERPAPI_KEY = os.getenv('SERPAPI_API_KEY', '')


# ---------------------------------------------------------------------------
# Extended source type definitions with AI-specific queries
# ---------------------------------------------------------------------------
AI_SOURCE_TYPES = {
    'PERMIT_DASHBOARD': {
        'queries': [
            '{city} {state} online permit portal login',
            '{city} {state} building permit status search',
            '{city} {state} permit tracking system',
            'site:{city_domain} permits',
        ],
        'priority': 95,
        'url_patterns': ['permit', 'building', 'inspect'],
    },
    'PLANNING_COMMISSION_PAGE': {
        'queries': [
            '{city} {state} planning commission agenda packets',
            '{city} {state} planning and zoning board meetings',
            '{city} {state} development review board agenda',
        ],
        'priority': 90,
        'url_patterns': ['planning', 'zoning', 'development'],
    },
    'ZONING_CASE_PORTAL': {
        'queries': [
            '{city} {state} zoning case search',
            '{city} {state} zoning application status',
            '{city} {state} rezoning cases public',
        ],
        'priority': 88,
        'url_patterns': ['zoning', 'case', 'rezone'],
    },
    'GIS_OPEN_DATA': {
        'queries': [
            '{city} {state} GIS data download',
            '{city} {state} open GIS data parcels',
            '{city} {state} geographic information system public data',
        ],
        'priority': 85,
        'url_patterns': ['gis', 'geoportal', 'map', 'spatial'],
    },
    'ARCGIS_DATASET': {
        'queries': [
            'site:arcgis.com {city} {state} parcels',
            'site:arcgis.com {city} {state} permits',
            'site:arcgis.com {city} {state} zoning',
            '{city} {state} arcgis open data hub',
        ],
        'priority': 85,
        'url_patterns': ['arcgis', 'esri', 'hub'],
    },
    'CITY_OPEN_DATA_PORTAL': {
        'queries': [
            '{city} {state} open data portal API',
            '{city} {state} data.{city_domain}',
            '{city} {state} city data catalog Socrata CKAN',
        ],
        'priority': 92,
        'url_patterns': ['data', 'opendata', 'catalog', 'socrata'],
    },
    'CONSTRUCTION_BID_PLATFORM': {
        'queries': [
            '{city} {state} construction bid opportunities government',
            '{city} {state} public works construction RFP',
        ],
        'priority': 70,
        'url_patterns': ['bid', 'procurement', 'rfp'],
    },
    'DEED_RECORD_SYSTEM': {
        'queries': [
            '{county} county {state} deed records online search',
            '{county} county {state} recorder of deeds',
        ],
        'priority': 75,
        'url_patterns': ['deed', 'recorder', 'clerk', 'record'],
    },
}

# Government domain patterns for validation
GOV_DOMAIN_PATTERNS = [
    r'\.gov\b', r'\.us\b', r'\.org\b',
    r'arcgis\.com', r'esri\.com',
    r'socrata', r'data\.', r'gis\.',
    r'opendata', r'cityof', r'countyof',
]

# City domain approximations
CITY_DOMAINS = {
    'Phoenix': 'phoenix.gov',
    'Dallas': 'dallascityhall.com',
    'Atlanta': 'atlantaga.gov',
    'Charlotte': 'charlottenc.gov',
    'Nashville': 'nashville.gov',
    'Tampa': 'tampagov.net',
    'Denver': 'denvergov.org',
    'Raleigh': 'raleighnc.gov',
    'Austin': 'austintexas.gov',
    'Orlando': 'orlando.gov',
}


# ---------------------------------------------------------------------------
# Search and validation helpers
# ---------------------------------------------------------------------------

def _search(query):
    """Execute a search query via SerpAPI."""
    if not SERPAPI_KEY:
        return []

    try:
        import requests
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': query,
            'api_key': SERPAPI_KEY,
            'num': 10,
        }, timeout=15)

        if resp.status_code != 200:
            return []

        data = resp.json()
        results = []
        for r in data.get('organic_results', [])[:10]:
            results.append({
                'title': r.get('title', ''),
                'url': r.get('link', ''),
                'snippet': r.get('snippet', ''),
            })
        return results
    except Exception as e:
        print(f"[SignalDiscoveryAI] Search error: {e}")
        return []


def _is_government_source(url):
    """Check if a URL is likely a government or official data source."""
    url_lower = url.lower()
    for pattern in GOV_DOMAIN_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    return False


def _calculate_confidence(url, title, snippet, source_type_config):
    """
    Calculate confidence score (0-100) that this is a valid data source.
    Based on URL pattern matching, title relevance, and domain type.
    """
    score = 0

    url_lower = url.lower()
    title_lower = (title or '').lower()
    snippet_lower = (snippet or '').lower()

    # URL pattern matching
    for pattern in source_type_config.get('url_patterns', []):
        if pattern in url_lower:
            score += 15

    # Government domain bonus
    if '.gov' in url_lower:
        score += 25
    elif '.us' in url_lower or '.org' in url_lower:
        score += 15
    elif 'arcgis' in url_lower:
        score += 20

    # Title keyword matching
    dev_keywords = ['permit', 'planning', 'zoning', 'parcel', 'gis',
                    'building', 'development', 'construction', 'data']
    for kw in dev_keywords:
        if kw in title_lower:
            score += 5
        if kw in snippet_lower:
            score += 3

    # Penalize non-relevant results
    spam_keywords = ['news', 'article', 'blog', 'opinion', 'review']
    for kw in spam_keywords:
        if kw in title_lower:
            score -= 10

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Source storage and priority management
# ---------------------------------------------------------------------------

def _store_discovered_source(source_type, city, state, title, url,
                              snippet, confidence_score, priority_score):
    """Store a discovered data source with confidence and priority scores."""
    conn = get_db()
    cur = conn.cursor()

    try:
        # Check for duplicate URL
        cur.execute('SELECT id, priority FROM data_sources WHERE url = ?', (url,))
        existing = cur.fetchone()

        if existing:
            # Update confidence if higher
            conn.close()
            return False

        cur.execute('''
            INSERT INTO data_sources
                (id, source_type, city, state, title, url, description,
                 priority, status, reliability_score, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'discovered', ?, CURRENT_TIMESTAMP)
        ''', (str(uuid.uuid4()), source_type, city, state, title, url,
              snippet, priority_score, confidence_score))

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[SignalDiscoveryAI] Storage error: {e}")
        conn.close()
        return False


def _update_source_priority(source_id, success):
    """
    Update source priority based on ingestion result.
    Success increases priority; failure decreases it.
    """
    conn = get_db()
    cur = conn.cursor()

    if success:
        cur.execute('''
            UPDATE data_sources
            SET priority = MIN(100, priority + 5),
                reliability_score = MIN(100, COALESCE(reliability_score, 0) + 10),
                status = 'active',
                last_checked = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (source_id,))
    else:
        cur.execute('''
            UPDATE data_sources
            SET priority = MAX(0, priority - 10),
                reliability_score = MAX(0, COALESCE(reliability_score, 0) - 5),
                last_checked = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (source_id,))

        # Mark as inactive if priority drops too low
        cur.execute('''
            UPDATE data_sources
            SET status = 'inactive'
            WHERE id = ? AND priority <= 10
        ''', (source_id,))

    conn.commit()
    conn.close()


def _attempt_ingestion(url, source_type):
    """
    Attempt to ingest data from a discovered source.
    Returns True if the source appears to have usable data.
    """
    try:
        import requests
        resp = requests.get(url, timeout=15, headers={
            'User-Agent': 'BTR-Command-DataCollector/1.0'
        })

        if resp.status_code != 200:
            return False

        content = resp.text.lower()
        content_type = resp.headers.get('content-type', '').lower()

        # Check for API/data indicators
        if 'json' in content_type or 'xml' in content_type:
            return True

        # Check HTML for data indicators
        data_indicators = [
            'api', 'dataset', 'download', 'export',
            'permit', 'parcel', 'zoning', 'application',
            'search results', 'records found',
        ]
        indicator_count = sum(1 for ind in data_indicators if ind in content)
        return indicator_count >= 2

    except Exception:
        return False


# ---------------------------------------------------------------------------
# Discovery cycle
# ---------------------------------------------------------------------------

def _discover_for_city(city, state):
    """Run AI-powered discovery for a single city."""
    discovered = 0
    city_domain = CITY_DOMAINS.get(city, f'{city.lower()}.gov')
    county = city  # Simplification — could be enhanced with county lookup

    for source_type, config in AI_SOURCE_TYPES.items():
        for query_template in config['queries']:
            try:
                query = query_template.format(
                    city=city, state=state, county=county,
                    city_domain=city_domain,
                )
            except KeyError:
                continue

            results = _search(query)

            for result in results:
                url = result.get('url', '')
                if not url:
                    continue

                # Only consider government/official sources
                if not _is_government_source(url):
                    continue

                confidence = _calculate_confidence(
                    url, result.get('title', ''),
                    result.get('snippet', ''), config
                )

                if confidence < 30:
                    continue

                priority = config['priority']

                stored = _store_discovered_source(
                    source_type=source_type,
                    city=city, state=state,
                    title=result.get('title', ''),
                    url=url,
                    snippet=result.get('snippet', ''),
                    confidence_score=confidence,
                    priority_score=priority,
                )
                if stored:
                    discovered += 1
                    print(f"  [AI] Discovered [{source_type}] "
                          f"conf={confidence} {result['title'][:50]} — {city}, {state}")

    return discovered


def _test_discovered_sources():
    """
    Test recently discovered sources to validate they contain usable data.
    Updates priority scores based on results.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT id, url, source_type
        FROM data_sources
        WHERE status = 'discovered'
        AND last_checked IS NULL
        ORDER BY priority DESC
        LIMIT 20
    ''')
    sources = cur.fetchall()
    conn.close()

    tested = 0
    successes = 0
    for source_id, url, source_type in sources:
        success = _attempt_ingestion(url, source_type)
        _update_source_priority(source_id, success)
        tested += 1
        if success:
            successes += 1

    return tested, successes


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_discovery_stats():
    """Get statistics about discovered data sources."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT source_type, status, COUNT(*) as count,
               AVG(reliability_score) as avg_reliability
        FROM data_sources
        GROUP BY source_type, status
        ORDER BY source_type, status
    ''')
    rows = cur.fetchall()
    conn.close()

    stats = {}
    for source_type, status, count, avg_rel in rows:
        if source_type not in stats:
            stats[source_type] = {}
        stats[source_type][status] = {
            'count': count,
            'avg_reliability': round(avg_rel or 0, 1),
        }
    return stats


def get_high_priority_sources(limit=20):
    """Get highest priority active data sources."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT id, source_type, city, state, title, url,
               priority, reliability_score, status
        FROM data_sources
        WHERE status IN ('discovered', 'active')
        ORDER BY priority DESC, reliability_score DESC
        LIMIT ?
    ''', (limit,))
    rows = cur.fetchall()
    conn.close()

    return [{
        'id': r[0], 'source_type': r[1], 'city': r[2], 'state': r[3],
        'title': r[4], 'url': r[5], 'priority': r[6],
        'reliability_score': r[7], 'status': r[8],
    } for r in rows]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_signal_discovery_ai(cities=None):
    """
    Main entry point — run autonomous signal discovery across target cities.
    """
    print("[SignalDiscoveryAI] Starting autonomous signal discovery...")

    if cities is None:
        cities = TARGET_CITIES

    total_discovered = 0
    for market in cities:
        city = market['city']
        state = market['state']
        print(f"[SignalDiscoveryAI] Scanning {city}, {state}...")
        discovered = _discover_for_city(city, state)
        total_discovered += discovered

    print(f"[SignalDiscoveryAI] Discovery phase complete: {total_discovered} new sources")

    # Test discovered sources for ingestion viability
    print("[SignalDiscoveryAI] Testing discovered sources...")
    tested, successes = _test_discovered_sources()
    print(f"[SignalDiscoveryAI] Tested {tested} sources, {successes} viable")

    result = {
        'cities_scanned': len(cities),
        'sources_discovered': total_discovered,
        'sources_tested': tested,
        'sources_viable': successes,
    }
    print(f"[SignalDiscoveryAI] Complete: {result}")
    return result


if __name__ == '__main__':
    run_signal_discovery_ai()
