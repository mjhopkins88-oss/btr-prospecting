"""
SerpAPI client for BTR prospect and discovery searches.

Replaces Claude web_search as the retrieval layer.
Claude is still used for extraction/classification (Stage B),
but SerpAPI handles candidate URL/snippet retrieval (Stage A).

Includes:
  - Tiered caching (72h market, 7d company, 24h manual)
  - Daily search budget (default 10 automated searches/day)
  - Query normalization & deduplication
  - Signal pool for shared market results
  - Usage logging
"""
import os
import re
import json
import sqlite3
import threading
from datetime import datetime, timedelta

import requests

from rate_limit import serp_limiter
from db import get_db as _get_db_central

SERPAPI_KEY = os.getenv('SERPAPI_API_KEY', '')
SERPAPI_URL = 'https://serpapi.com/search.json'

# Daily budget for automated (non-manual) searches
DAILY_BUDGET = int(os.getenv('SERPAPI_DAILY_BUDGET', '10'))

# Cache TTLs by feature category
_CACHE_TTL_HOURS = {
    'market':          72,   # broad market queries
    'discovery':       72,
    'discovery_pr':    72,
    'discovery_permit':72,
    'statewide':       72,
    'gov_signals':     72,
    'company':         168,  # 7 days
    'prospect':        24,
    'general':         24,
}

# In-process tracking
_budget_lock = threading.Lock()
_budget_date = None      # 'YYYY-MM-DD'
_budget_used = 0
_budget_cache_hits = 0
_budget_skipped = 0

# Query dedup within a single run
_run_dedup = {}          # normalized_query -> results
_run_dedup_lock = threading.Lock()


class SerpAPIError(Exception):
    """Raised when SerpAPI returns an error or is rate-limited."""
    pass


# ---------------------------------------------------------------------------
# Query normalization
# ---------------------------------------------------------------------------

def _normalize_query(query):
    """Normalize a query for cache-key and dedup purposes."""
    q = query.lower().strip()
    q = re.sub(r'\s+', ' ', q)        # collapse whitespace
    return q


# ---------------------------------------------------------------------------
# Daily budget
# ---------------------------------------------------------------------------

def _check_budget(feature):
    """Return True if an automated search is allowed under the daily budget."""
    global _budget_date, _budget_used
    today = datetime.utcnow().strftime('%Y-%m-%d')

    with _budget_lock:
        if _budget_date != today:
            _budget_date = today
            _budget_used = _load_daily_count(today)

        if _budget_used >= DAILY_BUDGET:
            return False
        return True


def _increment_budget():
    global _budget_used
    today = datetime.utcnow().strftime('%Y-%m-%d')
    with _budget_lock:
        _budget_used += 1
        _persist_daily_count(today, _budget_used)


def _load_daily_count(date_str):
    """Load today's API call count from DB."""
    try:
        conn = _get_db()
        c = conn.cursor()
        c.execute(
            'SELECT api_calls FROM serpapi_daily_budget WHERE date_str = ?',
            (date_str,)
        )
        row = c.fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception:
        return 0


def _persist_daily_count(date_str, count):
    """Persist today's API call count to DB."""
    try:
        conn = _get_db()
        c = conn.cursor()
        c.execute(
            '''INSERT OR REPLACE INTO serpapi_daily_budget
               (date_str, api_calls, cache_hits, skipped, updated_at)
               VALUES (?, ?, ?, ?, ?)''',
            (date_str, count, _budget_cache_hits, _budget_skipped,
             datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SerpAPI] Budget persist error: {e}")


# ---------------------------------------------------------------------------
# Core search
# ---------------------------------------------------------------------------

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
# Search cache (SQLite-backed, tiered TTL)
# ---------------------------------------------------------------------------

def _get_db():
    return _get_db_central()


def _ttl_hours(feature):
    """Return cache TTL in hours for a given feature category."""
    return _CACHE_TTL_HOURS.get(feature, 24)


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


def set_cached(cache_key, payload, ttl_hours=24):
    """Store payload in cache with configurable expiry."""
    try:
        now = datetime.utcnow()
        expires = now + timedelta(hours=ttl_hours)
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


def cached_serpapi_search(query, num=10, feature='general', city='', state='',
                          manual=False):
    """
    SerpAPI search with tiered SQLite cache, daily budget, and dedup.

    feature: determines cache TTL (see _CACHE_TTL_HOURS)
    manual:  if True, bypasses daily budget cap (for user-triggered searches)
    """
    global _budget_cache_hits, _budget_skipped

    norm_q = _normalize_query(query)
    ttl = _ttl_hours(feature)

    # Cache key: feature + location + normalized query (no date — TTL handles freshness)
    key = f"{feature}:{city.lower()}:{state.lower()}:{norm_q[:120]}"

    # 1) Check cache
    cached = get_cached(key)
    if cached is not None:
        with _budget_lock:
            _budget_cache_hits += 1
        print(f"[SerpAPI] Cache hit ({ttl}h TTL) for {key[:60]}")
        return cached

    # 2) In-run dedup: if the same normalized query was already fetched this run
    with _run_dedup_lock:
        if norm_q in _run_dedup:
            print(f"[SerpAPI] Run dedup hit for: {norm_q[:60]}")
            return _run_dedup[norm_q]

    # 3) Budget check (skip for manual/on-demand searches)
    if not manual and not _check_budget(feature):
        with _budget_lock:
            _budget_skipped += 1
        print(f"[SerpAPI] BUDGET EXHAUSTED ({DAILY_BUDGET}/day). Skipping: {norm_q[:60]}")
        return []

    # 4) Execute search
    results = serpapi_search(query, num=num)

    # 5) Store in cache with tiered TTL
    set_cached(key, results, ttl_hours=ttl)

    # 6) Store in run dedup
    with _run_dedup_lock:
        _run_dedup[norm_q] = results

    # 7) Store results in signal pool
    _store_signal_pool(results, query, feature, city, state)

    # 8) Increment budget counter
    if not manual:
        _increment_budget()

    print(f"[SerpAPI] API call #{_budget_used}/{DAILY_BUDGET} for: {norm_q[:60]}")
    return results


# ---------------------------------------------------------------------------
# Signal pool — shared results store
# ---------------------------------------------------------------------------

def _store_signal_pool(results, query, feature, city, state):
    """Store search results in the shared signal pool, deduplicating by URL."""
    try:
        conn = _get_db()
        c = conn.cursor()
        now = datetime.utcnow().isoformat()
        for r in results:
            url = r.get('link', '')
            if not url:
                continue
            c.execute(
                'SELECT 1 FROM signal_pool WHERE url = ?', (url,)
            )
            if c.fetchone():
                continue
            c.execute(
                '''INSERT INTO signal_pool
                   (url, title, snippet, source, published_date, query,
                    feature, city, state, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (url, r.get('title', ''), r.get('snippet', ''),
                 r.get('source', ''), r.get('date', ''),
                 query[:200], feature, city, state, now)
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SignalPool] Store error: {e}")


def get_signal_pool(feature=None, city=None, hours=72):
    """Retrieve recent signals from the pool, optionally filtered."""
    try:
        conn = _get_db()
        c = conn.cursor()
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        where = ['fetched_at > ?']
        params = [since]
        if feature:
            where.append('feature = ?')
            params.append(feature)
        if city:
            where.append('LOWER(city) = ?')
            params.append(city.lower())
        c.execute(
            f"SELECT * FROM signal_pool WHERE {' AND '.join(where)} "
            "ORDER BY fetched_at DESC LIMIT 200",
            params
        )
        cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, row)) for row in c.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Stats / logging
# ---------------------------------------------------------------------------

def get_serpapi_stats():
    """Return today's SerpAPI usage stats for admin/debug visibility."""
    global _budget_date, _budget_used, _budget_cache_hits, _budget_skipped
    today = datetime.utcnow().strftime('%Y-%m-%d')
    with _budget_lock:
        if _budget_date != today:
            _budget_date = today
            _budget_used = _load_daily_count(today)
            _budget_cache_hits = 0
            _budget_skipped = 0
    return {
        'date': today,
        'api_calls': _budget_used,
        'daily_budget': DAILY_BUDGET,
        'remaining': max(0, DAILY_BUDGET - _budget_used),
        'cache_hits': _budget_cache_hits,
        'skipped_budget': _budget_skipped,
    }


def clear_run_dedup():
    """Clear the in-run dedup cache. Call at the start of each background run."""
    with _run_dedup_lock:
        _run_dedup.clear()
