"""
SerpAPI client for BTR prospect and discovery searches.

Replaces Claude web_search as the retrieval layer.
Claude is still used for extraction/classification (Stage B),
but SerpAPI handles candidate URL/snippet retrieval (Stage A).
"""
import os
import json
import sqlite3
from datetime import datetime, timedelta

import requests

from rate_limit import serp_limiter

DB_PATH = 'prospects.db'
SERPAPI_KEY = os.getenv('SERPAPI_API_KEY', '')
SERPAPI_URL = 'https://serpapi.com/search.json'


class SerpAPIError(Exception):
    """Raised when SerpAPI returns an error or is rate-limited."""
    pass


def serpapi_search(query, num=10):
    """
    Search Google via SerpAPI.
    Returns list of dicts: { title, link, snippet, source, date }
    Raises SerpAPIError on failure so callers can surface it to the UI.
    """
    if not SERPAPI_KEY:
        raise SerpAPIError(
            'SERPAPI_API_KEY is not set. Add it to your environment variables.'
        )

    # Respect global rate limiter
    serp_limiter.wait()

    params = {
        'api_key': SERPAPI_KEY,
        'engine': 'google',
        'q': query,
        'num': min(num, 20),
        'hl': 'en',
        'gl': 'us',
    }

    resp = requests.get(SERPAPI_URL, params=params, timeout=20)

    if resp.status_code == 429:
        serp_limiter.report_429(resp.headers.get('Retry-After'))
        raise SerpAPIError('SerpAPI rate limited (429). Try again in a few minutes.')

    if resp.status_code != 200:
        body_snippet = resp.text[:300]
        raise SerpAPIError(
            f'SerpAPI HTTP {resp.status_code}: {body_snippet}'
        )

    data = resp.json()

    if 'error' in data:
        raise SerpAPIError(f"SerpAPI error: {data['error']}")

    results = []
    for item in data.get('organic_results', []):
        results.append({
            'title': item.get('title', ''),
            'link': item.get('link', ''),
            'snippet': item.get('snippet', ''),
            'source': item.get('displayed_link') or item.get('source', ''),
            'date': item.get('date', ''),
        })

    return results


# ---------------------------------------------------------------------------
# Search cache (SQLite-backed, 24-hour TTL)
# ---------------------------------------------------------------------------

def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_cached(cache_key):
    """Return cached payload list if still valid, else None."""
    try:
        conn = _get_db()
        c = conn.cursor()
        c.execute(
            'SELECT payload_json FROM search_cache WHERE cache_key = ? AND expires_at > ?',
            (cache_key, datetime.utcnow().isoformat())
        )
        row = c.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return None


def set_cached(cache_key, payload):
    """Store payload in cache with 24h expiry."""
    try:
        now = datetime.utcnow()
        expires = now + timedelta(hours=24)
        conn = _get_db()
        c = conn.cursor()
        c.execute(
            '''INSERT OR REPLACE INTO search_cache
               (cache_key, created_at, expires_at, payload_json)
               VALUES (?, ?, ?, ?)''',
            (cache_key, now.isoformat(), expires.isoformat(), json.dumps(payload))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Cache] Write error: {e}")


def cached_serpapi_search(query, num=10, feature='general', city='', state=''):
    """
    SerpAPI search with 24h SQLite cache.
    Returns list of result dicts.
    """
    today = datetime.utcnow().strftime('%Y-%m-%d')
    key = f"{feature}:{city.lower()}:{state.lower()}:{query[:80]}:{today}"

    cached = get_cached(key)
    if cached is not None:
        print(f"[SerpAPI] Cache hit for {key[:60]}")
        return cached

    results = serpapi_search(query, num=num)
    set_cached(key, results)
    return results
