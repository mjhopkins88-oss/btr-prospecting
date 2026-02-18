"""
Daily Discovery Engine — Event Signal Scanner

Searches CRE news sources for BTR/SFR activity signals (builds, permits,
acquisitions, sales, recapitalizations). Uses Google News RSS for fetching
and Claude for classification only (no web_search tool).
"""
import hashlib
import json
import time
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import quote_plus
import requests
import anthropic
import os

DB_PATH = 'prospects.db'

# Search terms for BTR activity signals
SIGNAL_SEARCH_TERMS = [
    '"build to rent"',
    '"multifamily"',
    '"breaking ground"',
    '"under construction"',
    '"permit"',
    '"rezoning"',
    '"acquires" OR "acquisition"',
    '"sells" OR "sale"',
    '"recapitalization"',
]

# Grouped to minimize HTTP requests (3 groups = 3 requests per city)
TERM_GROUPS = [
    '"build to rent" OR "breaking ground" OR "under construction" OR "multifamily"',
    '"permit" OR "rezoning" OR "acquisition" OR "acquires"',
    '"sale" OR "sells" OR "recapitalization"',
]

# 24-hour in-memory response cache
_response_cache = {}
CACHE_TTL = 86400  # seconds


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def compute_fingerprint(title, url, city):
    """Compute dedup fingerprint from normalized title + url + city."""
    normalized = f"{title.lower().strip()}|{url.lower().strip()}|{city.lower().strip()}"
    return hashlib.sha256(normalized.encode()).hexdigest()[:32]


def is_seen(fingerprint):
    """Check if fingerprint exists in discovery_signal_seen."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT 1 FROM discovery_signal_seen WHERE fingerprint = ?', (fingerprint,))
    found = c.fetchone() is not None
    conn.close()
    return found


def mark_seen(fingerprint):
    """Insert fingerprint into discovery_signal_seen."""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(
            'INSERT OR IGNORE INTO discovery_signal_seen (fingerprint, first_seen_at) VALUES (?, ?)',
            (fingerprint, datetime.utcnow().isoformat())
        )
        conn.commit()
    except Exception:
        pass
    conn.close()


# ---------------------------------------------------------------------------
# Fetching — Google News RSS
# ---------------------------------------------------------------------------

def fetch_city_signals(city, state, sources, request_count, max_requests=50):
    """
    Fetch news signals for a city from configured sources via Google News RSS.
    Returns (list_of_raw_signal_dicts, updated_request_count).
    """
    if request_count >= max_requests:
        return [], request_count

    # Build site: filter from configured sources (skip non-scrapable ones)
    scrapable = [s for s in sources if s not in ('sec.gov EDGAR', 'linkedin.com')]
    site_filter = " OR ".join(f"site:{s}" for s in scrapable) if scrapable else ""

    all_items = []

    for terms in TERM_GROUPS:
        if request_count >= max_requests:
            break

        query = f"({site_filter}) ({terms}) {city}" if site_filter else f"({terms}) {city}"
        cache_key = f"{query}|{datetime.utcnow().strftime('%Y-%m-%d')}"

        # Check 24h cache
        if cache_key in _response_cache:
            cached = _response_cache[cache_key]
            if (datetime.utcnow() - cached['ts']).total_seconds() < CACHE_TTL:
                all_items.extend(cached['items'])
                continue

        # Fetch
        encoded = quote_plus(query)
        url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
        items = _fetch_with_backoff(url)
        request_count += 1

        _response_cache[cache_key] = {'items': items, 'ts': datetime.utcnow()}
        all_items.extend(items)

        # Concurrency = 1: pause between requests
        time.sleep(1)

    # Attach city/state
    for item in all_items:
        item['city'] = city
        item['state'] = state

    return all_items, request_count


def _fetch_with_backoff(url, max_retries=5):
    """Fetch URL with exponential backoff on 429s."""
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(url, timeout=15, headers={
                'User-Agent': 'BTR-Prospecting-Engine/1.0'
            })

            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2 ** (attempt + 1)))
                if attempt < max_retries:
                    print(f"[Discovery] 429 rate limited, waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue
                else:
                    print("[Discovery] 429 after all retries")
                    return []

            if resp.status_code != 200:
                print(f"[Discovery] HTTP {resp.status_code} for {url[:80]}")
                return []

            return _parse_rss(resp.text)

        except requests.exceptions.Timeout:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return []
        except Exception as e:
            print(f"[Discovery] Fetch error: {e}")
            return []

    return []


def _parse_rss(xml_text):
    """Parse Google News RSS XML into signal dicts."""
    items = []
    try:
        root = ET.fromstring(xml_text)
        for item_el in root.findall('.//item'):
            title = (item_el.findtext('title') or '').strip()
            link = (item_el.findtext('link') or '').strip()
            description = (item_el.findtext('description') or '').strip()
            pub_date = (item_el.findtext('pubDate') or '').strip()
            source_el = item_el.find('source')
            source_name = (source_el.text or '').strip() if source_el is not None else ''

            if title and link:
                items.append({
                    'title': title,
                    'url': link,
                    'snippet': description[:500] if description else '',
                    'published_at': pub_date,
                    'source_name': source_name,
                })
    except ET.ParseError as e:
        print(f"[Discovery] RSS parse error: {e}")
    return items


# ---------------------------------------------------------------------------
# Classification — Claude (text-only, NO web_search tool)
# ---------------------------------------------------------------------------

def classify_signals(items, client):
    """
    Batch-classify raw news items into BTR signal types using Claude.
    Returns only items classified as relevant BTR activity.
    """
    classified = []
    batch_size = 10

    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]

        items_json = json.dumps([{
            'index': j,
            'title': it['title'],
            'snippet': it.get('snippet', ''),
            'source_name': it.get('source_name', ''),
            'city': it.get('city', ''),
        } for j, it in enumerate(batch)], indent=2)

        prompt = f"""Classify each news item below as a BTR/SFR (Build-to-Rent / Single-Family Rental) activity signal.

For each item, determine:
1. signal_type: one of "new_build", "under_construction", "permit_rezoning", "acquisition", "sale", "recapitalization", "other", or "not_relevant"
2. entity_name: the company or community name involved
3. summary: 1-3 sentence clean description of the activity

Items:
{items_json}

Return ONLY a valid JSON array:
[
  {{
    "index": 0,
    "signal_type": "new_build",
    "entity_name": "Company Name",
    "summary": "Brief description of the activity."
  }}
]

Rules:
- Mark items as "not_relevant" if they are NOT about BTR, SFR, multifamily rental, or related real estate development
- Only classify items that are clearly about real estate activity
- Return ONLY the JSON array, no other text"""

        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = ""
            for block in message.content:
                if block.type == "text":
                    response_text += block.text

            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                classifications = json.loads(response_text[json_start:json_end])

                for cls in classifications:
                    idx = cls.get('index', -1)
                    if 0 <= idx < len(batch) and cls.get('signal_type') != 'not_relevant':
                        item = batch[idx].copy()
                        item['signal_type'] = cls.get('signal_type', 'other')
                        item['entity_name'] = cls.get('entity_name', '')
                        item['summary'] = cls.get('summary', '')
                        classified.append(item)

        except Exception as e:
            print(f"[Discovery] Classification error: {e}")
            # On failure, include items unclassified so they aren't lost
            for it in batch:
                c = it.copy()
                c['signal_type'] = 'unclassified'
                c['entity_name'] = ''
                c['summary'] = it.get('title', '')
                classified.append(c)

        # Pause between Claude calls
        time.sleep(1)

    return classified


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_discovery_job(config):
    """
    Main discovery orchestrator.
    Scans cities, deduplicates, classifies, returns structured results.
    Returns (results_dict, digest_text, total_new_count).
    """
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

    cities = config['cities']
    sources = config.get('target_sources', [])
    max_new = config.get('max_signals_per_day', 10)

    print(f"[Discovery] Starting signal scan across {len(cities)} cities (max {max_new} new)...")

    all_new_signals = []
    results = {}
    request_count = 0

    for city_info in cities:
        if len(all_new_signals) >= max_new:
            break

        city = city_info['city']
        state = city_info['state']
        location = f"{city}, {state}"

        print(f"[Discovery] Scanning {location}...")

        # 1. Fetch raw signals
        raw_items, request_count = fetch_city_signals(city, state, sources, request_count)

        if not raw_items:
            results[location] = {'signals': [], 'new_count': 0}
            print(f"[Discovery] {location}: no raw items found")
            continue

        # 2. Deduplicate against seen fingerprints
        unseen = []
        for item in raw_items:
            fp = compute_fingerprint(item['title'], item['url'], city)
            if not is_seen(fp):
                item['fingerprint'] = fp
                unseen.append(item)

        if not unseen:
            results[location] = {'signals': [], 'new_count': 0}
            print(f"[Discovery] {location}: all items already seen")
            continue

        # Fetch a few extra in case some are classified as not_relevant
        remaining = max_new - len(all_new_signals)
        unseen = unseen[:remaining + 5]

        # 3. Classify with Claude (text-only, no web_search)
        classified = classify_signals(unseen, client)

        # 4. Take only what we need, mark as seen
        city_new = []
        for sig in classified:
            if len(all_new_signals) >= max_new:
                break
            fp = sig.get('fingerprint')
            if fp:
                mark_seen(fp)
            city_new.append(sig)
            all_new_signals.append(sig)

        results[location] = {
            'signals': city_new,
            'new_count': len(city_new),
        }
        print(f"[Discovery] {location}: {len(city_new)} new signals")

    # Build digest
    digest = _format_signal_digest(results, all_new_signals)

    return results, digest, len(all_new_signals)


def _format_signal_digest(results, all_signals):
    """Format results into a human-readable digest."""
    lines = []
    lines.append("=" * 60)
    lines.append("  BTR DAILY DISCOVERY — ACTIVITY SIGNALS")
    lines.append(f"  {datetime.now().strftime('%A, %B %d, %Y at %I:%M %p PT')}")
    lines.append("=" * 60)
    lines.append("")

    if not all_signals:
        lines.append("  No new qualified activity found today.")
        lines.append("")
    else:
        for location, data in results.items():
            sigs = data.get('signals', [])
            if not sigs:
                continue
            lines.append(f"--- {location} ({len(sigs)} new) ---")
            for i, s in enumerate(sigs, 1):
                label = s.get('signal_type', 'other').replace('_', ' ').title()
                lines.append(f"  {i}. [{label}] {s.get('entity_name', 'Unknown')}")
                lines.append(f"     {s.get('summary', s.get('title', ''))}")
                if s.get('source_name'):
                    lines.append(f"     Source: {s['source_name']}")
                if s.get('url'):
                    lines.append(f"     Link: {s['url']}")
                lines.append("")
            lines.append("")

    lines.append(f"TOTAL NEW SIGNALS: {len(all_signals)}")
    lines.append("=" * 60)
    return "\n".join(lines)
