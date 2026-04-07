"""
Signal Collector: News articles via SerpAPI + Claude extraction.
Searches for BTR/SFR development news in target markets and stores
raw signals into li_signals.
"""
import json
import os
import traceback
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

try:
    import anthropic
except ImportError:
    anthropic = None

from shared.config import SERPAPI_KEY, ANTHROPIC_API_KEY, AI_MODEL, TARGET_CITIES, ICP_KEYWORDS
from shared.database import new_id, get_db, is_postgres


def _search_news(query, num=10):
    """Search Google News via SerpAPI."""
    if not SERPAPI_KEY or not requests:
        return []
    try:
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': query,
            'tbm': 'nws',
            'num': num,
            'api_key': SERPAPI_KEY,
        }, timeout=30)
        data = resp.json()
        return data.get('news_results', [])
    except Exception as e:
        print(f"[NewsCollector] SerpAPI error: {e}")
        return []


def _extract_signals_with_ai(articles, city, state):
    """Use Claude to extract structured signal data from news articles."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    articles_text = json.dumps(articles[:10], indent=2, default=str)

    prompt = f"""Analyze these news articles about real estate development in {city}, {state}.
For each article that mentions a real development project (BTR, SFR, multifamily, land acquisition),
extract structured data.

Articles:
{articles_text}

Return a JSON array where each element has:
- "headline": the article headline
- "url": article URL
- "published_at": publication date (ISO format or null)
- "signal_type": one of "land_acquisition", "permit_filed", "construction_start", "project_announced", "funding", "zoning_change", "other"
- "strength": float 0.0-1.0 indicating how strong this signal is for BTR/SFR development
- "project_name": extracted project name or null
- "company_name": developer/builder company name or null
- "body": 1-2 sentence summary of the signal

Return ONLY the JSON array, no other text."""

    try:
        resp = client.messages.create(
            model=AI_MODEL,
            max_tokens=2000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        # Strip markdown fences if present
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[NewsCollector] AI extraction error: {e}")
        return []


def _store_signals(signals, city, state, source_type='news'):
    """Store extracted signals into li_signals table."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    for sig in signals:
        sid = new_id()
        headline = (sig.get('headline') or '')[:500]
        url = sig.get('url') or ''
        if not headline and not url:
            continue
        try:
            cur.execute('''
                INSERT OR IGNORE INTO li_signals
                (id, source_type, headline, body, url, published_at, city, state,
                 raw_json, signal_type, strength, normalized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                sid, source_type, headline,
                sig.get('body'), url,
                sig.get('published_at'), city, state,
                json.dumps(sig, default=str),
                sig.get('signal_type', 'news'),
                float(sig.get('strength', 0.5)),
                0,
            ))
            stored += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return stored


def collect_news(cities=None):
    """
    Main entry point: collect news signals for target cities.
    Can be called directly or enqueued via RQ.
    """
    cities = cities or TARGET_CITIES
    total = 0
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[NewsCollector] Scanning {city}, {state}...")
        for keyword in ICP_KEYWORDS[:3]:  # top 3 keywords to limit API calls
            query = f'{keyword} {city} {state} development'
            articles = _search_news(query, num=5)
            if articles:
                signals = _extract_signals_with_ai(articles, city, state)
                count = _store_signals(signals, city, state)
                total += count
                print(f"  → {keyword}: {count} signals stored")
    print(f"[NewsCollector] Done. {total} total signals collected.")
    return total
