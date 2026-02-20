"""
Permit Adapter — limited-scope permit/planning portal queries.

Only targets the 4 configured Daily Discovery cities.
Uses public open-data APIs where available (Socrata-based) to avoid scraping.

For each city, uses ONE stable endpoint:
  - Phoenix, AZ: city open-data portal (Socrata)
  - Dallas, TX: city open-data portal (Socrata)
  - Atlanta, GA: SerpAPI search for permit news (no open API)
  - Charlotte, NC: SerpAPI search for permit news (no open API)

Results cached for 24 hours. Only runs live on scheduled 7am job;
manual "Run Now" uses cached results.
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta

import requests

from adapters.base import BaseAdapter
from discovery_config import PERMIT_CACHE_TTL_HOURS

DB_PATH = 'prospects.db'

# Keywords to filter permits for BTR/multifamily relevance
PERMIT_KEYWORDS = [
    'multifamily', 'multi-family', 'apartment', 'rental',
    'townhome', 'townhouse', 'build to rent', 'btr',
    'single family rental', 'sfr', 'residential',
    'duplex', 'triplex', 'fourplex', 'community',
]

# City-specific endpoint configs
CITY_ENDPOINTS = {
    'Phoenix': {
        'type': 'socrata',
        'url': 'https://www.phoenixopendata.com/resource/m3dh-jped.json',
        'params': {
            '$limit': 20,
            '$order': 'issue_date DESC',
            '$where': "issue_date > '{cutoff}'",
        },
        'title_field': 'permit_num',
        'date_field': 'issue_date',
        'desc_field': 'work_desc',
        'address_field': 'address',
        'state': 'AZ',
    },
    'Dallas': {
        'type': 'socrata',
        'url': 'https://www.dallasopendata.com/resource/building-permits.json',
        'params': {
            '$limit': 20,
            '$order': 'issue_date DESC',
            '$where': "issue_date > '{cutoff}'",
        },
        'title_field': 'permit_num',
        'date_field': 'issue_date',
        'desc_field': 'description',
        'address_field': 'address',
        'state': 'TX',
    },
    'Atlanta': {
        'type': 'search',
        'query': 'site:atlantaga.gov OR site:bizjournals.com/atlanta (building permit OR rezoning OR "land use") (multifamily OR apartment OR "build to rent") {year}',
        'state': 'GA',
    },
    'Charlotte': {
        'type': 'search',
        'query': 'site:charlottenc.gov OR site:bizjournals.com/charlotte (building permit OR rezoning OR "land use") (multifamily OR apartment OR "build to rent") {year}',
        'state': 'NC',
    },
}


class PermitAdapter(BaseAdapter):
    name = 'permit'
    source_type = 'permit'

    def __init__(self, limiter, use_cache_only=False):
        super().__init__(limiter)
        self.use_cache_only = use_cache_only

    def fetch(self, cities, config):
        items = []

        for city_info in cities:
            city = city_info['city']
            state = city_info['state']

            if city not in CITY_ENDPOINTS:
                continue

            if not self.limiter.can_call():
                break

            # Check cache first
            cached = self._get_cached(city)
            if cached is not None:
                items.extend(cached)
                continue

            # If cache-only mode (manual run), skip live fetch
            if self.use_cache_only:
                print(f"[Permit] {city}: no cache, skipping (manual run)")
                continue

            city_items = self._fetch_city(city, state)
            items.extend(city_items)

            # Cache results
            self._set_cached(city, city_items)

        return items

    def _fetch_city(self, city, state):
        """Fetch permits for a single city."""
        endpoint = CITY_ENDPOINTS.get(city, {})
        ep_type = endpoint.get('type', '')

        if ep_type == 'socrata':
            return self._fetch_socrata(city, endpoint)
        elif ep_type == 'search':
            return self._fetch_via_search(city, endpoint)
        return []

    def _fetch_socrata(self, city, endpoint):
        """Fetch from Socrata open-data API."""
        if not self.limiter.wait():
            return []

        cutoff = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT00:00:00')
        state = endpoint['state']

        params = {}
        for k, v in endpoint['params'].items():
            params[k] = v.format(cutoff=cutoff) if isinstance(v, str) else v

        try:
            resp = requests.get(
                endpoint['url'],
                params=params,
                headers={'Accept': 'application/json'},
                timeout=15
            )

            if resp.status_code == 429:
                self.limiter.report_error(429, resp.headers.get('Retry-After'))
                return []

            if resp.status_code != 200:
                print(f"[Permit] {city} Socrata HTTP {resp.status_code}")
                self.limiter.report_error(resp.status_code)
                # Fall back to search
                search_endpoint = {
                    'type': 'search',
                    'query': f'"{city}" (building permit OR construction permit) (multifamily OR apartment OR "build to rent") {datetime.now().year}',
                    'state': state,
                }
                return self._fetch_via_search(city, search_endpoint)

            data = resp.json()
            items = []

            for record in data:
                desc = record.get(endpoint.get('desc_field', 'description'), '')
                title_val = record.get(endpoint.get('title_field', ''), '')
                date_val = record.get(endpoint.get('date_field', ''), '')
                address = record.get(endpoint.get('address_field', ''), '')

                # Filter for BTR/multifamily relevance
                search_text = (str(desc) + ' ' + str(title_val) + ' ' + str(address)).lower()
                if not any(kw in search_text for kw in PERMIT_KEYWORDS):
                    continue

                # Format date
                if date_val and 'T' in str(date_val):
                    date_val = str(date_val).split('T')[0]

                items.append({
                    'title': f'Permit {title_val} — {address}' if address else f'Permit {title_val}',
                    'url': endpoint['url'],
                    'snippet': str(desc)[:300] if desc else f'Building permit at {address}',
                    'published_at': str(date_val),
                    'source_name': f'{city} Open Data',
                    'source_type': 'permit',
                    'confidence': 'medium',
                    'city': city,
                    'state': state,
                    'entity_name': '',
                    'signal_type': 'permit_rezoning',
                })

            print(f"[Permit] {city}: {len(items)} relevant permits from Socrata")
            return items

        except requests.exceptions.Timeout:
            print(f"[Permit] {city} Socrata timeout")
            return []
        except Exception as e:
            print(f"[Permit] {city} Socrata error: {e}")
            return []

    def _fetch_via_search(self, city, endpoint):
        """Fetch permit news via SerpAPI or Claude web_search fallback."""
        if not self.limiter.wait():
            return []

        state = endpoint['state']
        query = endpoint['query'].format(year=datetime.now().year)

        try:
            serp_key = os.getenv('SERPAPI_API_KEY', '')
            if serp_key:
                from serpapi_client import cached_serpapi_search
                results = cached_serpapi_search(
                    query, num=5, feature='discovery_permit', city=city, state=state
                )
            else:
                results = self._claude_web_search(query)

            items = []
            for r in results:
                items.append({
                    'title': r.get('title', ''),
                    'url': r.get('link', r.get('url', '')),
                    'snippet': r.get('snippet', ''),
                    'published_at': r.get('date', r.get('published_at', '')),
                    'source_name': r.get('source', r.get('source_name', '')),
                    'source_type': 'permit',
                    'confidence': 'low',
                    'city': city,
                    'state': state,
                    'entity_name': '',
                    'signal_type': 'permit_rezoning',
                })

            print(f"[Permit] {city}: {len(items)} results from search")
            return items

        except Exception as e:
            print(f"[Permit] {city} search error: {e}")
            return []

    def _claude_web_search(self, query):
        """Fallback search using Claude web_search tool."""
        import anthropic

        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

        prompt = f"""Search for: {query}

Return ONLY a JSON array of search results:
[
  {{"title": "...", "link": "https://...", "snippet": "...", "date": "...", "source": "..."}}
]

Return up to 5 results. Return ONLY the JSON array, no other text."""

        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": 3}],
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = ""
            for block in message.content:
                if block.type == "text":
                    response_text += block.text

            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response_text[json_start:json_end])
        except Exception as e:
            print(f"[Permit] Claude web_search fallback error: {e}")

        return []

    # --- Cache (SQLite-backed, 24h TTL) ---

    def _get_cached(self, city):
        """Get cached permit results for a city."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                'SELECT payload_json FROM search_cache WHERE cache_key = ? AND expires_at > ?',
                (f'permit:{city.lower()}', datetime.utcnow().isoformat())
            )
            row = c.fetchone()
            conn.close()
            if row:
                return json.loads(row[0])
        except Exception:
            pass
        return None

    def _set_cached(self, city, items):
        """Cache permit results for a city."""
        try:
            now = datetime.utcnow()
            expires = now + timedelta(hours=PERMIT_CACHE_TTL_HOURS)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                '''INSERT OR REPLACE INTO search_cache
                   (cache_key, created_at, expires_at, payload_json)
                   VALUES (?, ?, ?, ?)''',
                (f'permit:{city.lower()}', now.isoformat(), expires.isoformat(), json.dumps(items))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Permit] Cache write error for {city}: {e}")
