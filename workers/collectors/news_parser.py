"""
News Intelligence Collector.
Searches Google News, PRNewswire, and regional business journals
for development signals. Extracts developer name, project location,
project type, and estimated units.
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


# Search query templates for different signal types
NEWS_QUERIES = [
    '{city} {state} build to rent development announced',
    '{city} {state} multifamily apartment project approved',
    '{city} {state} residential land acquisition developer',
    '{city} {state} BTR community groundbreaking',
    '{city} {state} zoning approved residential development',
    'PRNewswire {city} {state} residential development',
]

# Regional business journal domains for targeted searches
REGIONAL_JOURNALS = [
    'bizjournals.com',
    'globest.com',
    'multihousingnews.com',
    'rejournals.com',
    'connectcre.com',
]


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
        print(f"[NewsParser] Search error: {e}")
        return []


def _search_press_releases(city, state, num=5):
    """Search specifically for press releases about development."""
    if not SERPAPI_KEY or not requests:
        return []
    query = f'site:prnewswire.com OR site:businesswire.com {city} {state} residential development'
    try:
        resp = requests.get('https://serpapi.com/search.json', params={
            'q': query,
            'num': num,
            'api_key': SERPAPI_KEY,
        }, timeout=30)
        data = resp.json()
        return data.get('organic_results', [])
    except Exception as e:
        print(f"[NewsParser] PR search error: {e}")
        return []


def _extract_news_signals(articles, city, state):
    """Use Claude to extract development signals from news articles."""
    if not ANTHROPIC_API_KEY or not anthropic or not articles:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    articles_text = json.dumps(articles[:12], indent=2, default=str)

    prompt = f"""Analyze these news articles about real estate development in {city}, {state}.
Extract structured signals about BTR, multifamily, and residential development projects.

Articles:
{articles_text}

Return a JSON array where each element has:
- "headline": article headline
- "developer": developer/builder company name
- "project_name": project name if mentioned
- "project_type": "BTR", "Multifamily", "SFR", "Mixed-Use", "Townhomes", or "Other"
- "address": project address or location
- "city": "{city}"
- "state": "{state}"
- "estimated_units": number of units if mentioned, or null
- "estimated_value": dollar value if mentioned, or null
- "signal_type": one of "LAND_PURCHASE", "ZONING_APPLICATION", "BUILDING_PERMIT",
  "DEVELOPER_EXPANSION", "NEWS_SIGNAL"
- "url": article URL
- "published_at": publication date or null
- "confidence": float 0.0-1.0

Only include items about real development projects, not general market commentary.
Return ONLY the JSON array."""

    try:
        resp = client.messages.create(
            model=AI_MODEL,
            max_tokens=3000,
            messages=[{'role': 'user', 'content': prompt}]
        )
        text = resp.content[0].text.strip()
        if text.startswith('```'):
            text = text.split('\n', 1)[1]
            text = text.rsplit('```', 1)[0]
        return json.loads(text)
    except Exception as e:
        print(f"[NewsParser] AI extraction error: {e}")
        return []


def _store_news_signals(signals, city, state):
    """Store news signals into property_signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for sig in signals:
        developer = (sig.get('developer') or '').strip()
        headline = (sig.get('headline') or '').strip()
        if not developer and not headline:
            continue

        sig_id = str(uuid.uuid4())
        signal_type = sig.get('signal_type', 'NEWS_SIGNAL')

        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, address,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, signal_type, 'news_intelligence',
                developer, sig.get('address'),
                sig.get('city') or city,
                sig.get('state') or state,
                json.dumps(sig, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Also store into li_signals for existing pipeline compatibility
        try:
            cur.execute('''
                INSERT OR IGNORE INTO li_signals
                (id, source_type, headline, body, url, published_at, city, state,
                 raw_json, signal_type, strength, normalized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()), 'news_parser', headline,
                f"{developer} — {sig.get('project_name', '')}",
                sig.get('url'), sig.get('published_at'),
                sig.get('city') or city,
                sig.get('state') or state,
                json.dumps(sig, default=str),
                signal_type.lower(),
                float(sig.get('confidence', 0.5)),
                0,
            ))
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


def parse_news(cities=None):
    """
    Main entry point: collect news intelligence signals for target markets.
    Searches Google News, press releases, and regional journals.
    """
    cities = cities or TARGET_CITIES
    total = 0

    for market in cities:
        city, state = market['city'], market['state']
        print(f"[NewsParser] Scanning {city}, {state}...")

        all_articles = []

        # Search news with top query templates (limit API calls)
        for template in NEWS_QUERIES[:3]:
            query = template.format(city=city, state=state)
            articles = _search_news(query, num=5)
            all_articles.extend(articles)

        # Search press releases
        pr_results = _search_press_releases(city, state, num=5)
        all_articles.extend(pr_results)

        if all_articles:
            # Deduplicate by URL
            seen_urls = set()
            unique = []
            for a in all_articles:
                url = a.get('link') or a.get('url') or ''
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    unique.append(a)

            signals = _extract_news_signals(unique, city, state)
            count = _store_news_signals(signals, city, state)
            total += count
            print(f"  → {count} news signals stored")

    print(f"[NewsParser] Done. {total} total news signals collected.")
    return total
