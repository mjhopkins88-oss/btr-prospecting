"""
Signal Collector: Building permits and zoning changes.
Searches for permit filings and zoning actions in target markets.
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

from shared.config import SERPAPI_KEY, ANTHROPIC_API_KEY, AI_MODEL, TARGET_CITIES
from shared.database import new_id, get_db


def _search_permits(city, state, num=10):
    """Search for building permit news via SerpAPI."""
    if not SERPAPI_KEY or not requests:
        return []
    queries = [
        f'building permit filed {city} {state} residential',
        f'zoning change approved {city} {state} residential development',
    ]
    results = []
    for q in queries:
        try:
            resp = requests.get('https://serpapi.com/search.json', params={
                'q': q,
                'tbm': 'nws',
                'num': num,
                'api_key': SERPAPI_KEY,
            }, timeout=30)
            data = resp.json()
            results.extend(data.get('news_results', []))
        except Exception as e:
            print(f"[PermitsCollector] SerpAPI error: {e}")
    return results


def _extract_permit_signals(articles, city, state):
    """Use Claude to extract permit/zoning signals from articles."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    articles_text = json.dumps(articles[:8], indent=2, default=str)

    prompt = f"""Analyze these articles about building permits and zoning in {city}, {state}.
Extract structured data about any real residential development permits or zoning changes.

Articles:
{articles_text}

Return a JSON array where each element has:
- "headline": article headline
- "url": article URL
- "published_at": date or null
- "signal_type": one of "permit_filed", "zoning_change", "construction_start", "other"
- "strength": float 0.0-1.0 (permits for large residential = higher)
- "project_name": project name or null
- "company_name": applicant/developer or null
- "unit_count": number of units if mentioned, or null
- "body": 1-2 sentence summary

Return ONLY the JSON array."""

    try:
        resp = client.messages.create(
            model=AI_MODEL,
            max_tokens=2000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[PermitsCollector] AI extraction error: {e}")
        return []


def _store_signals(signals, city, state):
    """Store permit signals into li_signals."""
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
                sid, 'permits', headline,
                sig.get('body'), url,
                sig.get('published_at'), city, state,
                json.dumps(sig, default=str),
                sig.get('signal_type', 'permit_filed'),
                float(sig.get('strength', 0.6)),
                0,
            ))
            stored += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return stored


def collect_permits(cities=None):
    """Main entry point: collect permit/zoning signals for target cities."""
    cities = cities or TARGET_CITIES
    total = 0
    for market in cities:
        city, state = market['city'], market['state']
        print(f"[PermitsCollector] Scanning {city}, {state}...")
        articles = _search_permits(city, state, num=5)
        if articles:
            signals = _extract_permit_signals(articles, city, state)
            count = _store_signals(signals, city, state)
            total += count
            print(f"  → {count} permit signals stored")
    print(f"[PermitsCollector] Done. {total} total signals collected.")
    return total
