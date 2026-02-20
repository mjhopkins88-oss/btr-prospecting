"""
Daily Discovery Engine — Event Signal Scanner (v2 with Source Adapters)

Multi-source architecture:
  - EDGARAdapter: SEC filings for monitored BTR operators
  - PressReleaseAdapter: PRNewswire/BusinessWire via SerpAPI or Claude web_search
  - PermitAdapter: City permit portals (Socrata API + search fallback)
  - Legacy news: SerpAPI / Claude web_search for CRE news

All adapters share a global rate limiter (discovery_rate_limiter).
One adapter failing does NOT fail the entire run.
"""
import hashlib
import json
import time
import sqlite3
from datetime import datetime
import anthropic
import os

from discovery_config import ADAPTER_CONFIG, MAX_ITEMS_PER_DAY
from discovery_rate_limiter import discovery_limiter

DB_PATH = 'prospects.db'

# Legacy news query patterns per city
DISCOVERY_QUERIES = [
    '("build to rent" OR BTR OR multifamily) "{city} {state}" (acquires OR acquisition OR sells OR sale OR groundbreaking OR permit OR rezoning OR entitlement OR "under construction")',
]


def _serpapi_available():
    return bool(os.getenv('SERPAPI_API_KEY', ''))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def compute_fingerprint(title, url, city, state):
    """Compute dedup fingerprint from normalized title + url + city + state."""
    normalized = f"{title.lower().strip()}|{url.lower().strip()}|{city.lower().strip()}|{state.lower().strip()}"
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


def _update_source_refresh(source_type, items_found):
    """Update the last-refreshed timestamp for a source type."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            '''INSERT OR REPLACE INTO discovery_source_refresh
               (source_type, last_refreshed_at, items_found)
               VALUES (?, ?, ?)''',
            (source_type, datetime.utcnow().isoformat(), items_found)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Discovery] Error updating source refresh for {source_type}: {e}")


def get_source_refresh_times():
    """Get last-refreshed timestamps for all source types."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT source_type, last_refreshed_at, items_found FROM discovery_source_refresh')
        rows = c.fetchall()
        conn.close()
        return {row[0]: {'last_refreshed_at': row[1], 'items_found': row[2]} for row in rows}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Fetching — legacy news (SerpAPI or Claude web_search)
# ---------------------------------------------------------------------------

def fetch_city_signals(city, state):
    """
    Fetch news/activity signals for a city.
    Uses SerpAPI if available, otherwise falls back to Claude web_search.
    Returns list of raw signal dicts with source_type='news'.
    """
    if _serpapi_available():
        items = _fetch_city_signals_serpapi(city, state)
    else:
        items = _fetch_city_signals_websearch(city, state)

    # Tag all items with source_type and confidence
    for item in items:
        item.setdefault('source_type', 'news')
        item.setdefault('confidence', 'medium')

    return items


def _fetch_city_signals_serpapi(city, state):
    """Fetch signals via SerpAPI."""
    from serpapi_client import cached_serpapi_search, SerpAPIError

    all_items = []
    seen_links = set()

    for query_template in DISCOVERY_QUERIES:
        query = query_template.replace('{city}', city).replace('{state}', state)

        try:
            results = cached_serpapi_search(
                query, num=10, feature='discovery', city=city, state=state
            )
            for r in results:
                link = r.get('link', '')
                if link and link not in seen_links:
                    seen_links.add(link)
                    all_items.append({
                        'title': r.get('title', ''),
                        'url': link,
                        'snippet': r.get('snippet', ''),
                        'published_at': r.get('date', ''),
                        'source_name': r.get('source', ''),
                        'city': city,
                        'state': state,
                    })
        except SerpAPIError as e:
            print(f"[Discovery] SerpAPI error for {city}, {state}: {e}")
        except Exception as e:
            print(f"[Discovery] Fetch error for {city}, {state}: {e}")

    return all_items


def _fetch_city_signals_websearch(city, state):
    """Fetch signals via Claude web_search (fallback when no SerpAPI key)."""
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

    search_prompt = f"""Search for recent Build-to-Rent (BTR), Single-Family Rental (SFR), and multifamily development news in {city}, {state}.

Look for:
- New BTR/SFR community groundbreakings or construction starts
- Land acquisitions for rental housing developments
- Permits, rezoning, or entitlements for BTR projects
- Sales or acquisitions of BTR communities
- Recapitalizations or financing for rental developments

For each news item found, provide the title, URL, a brief snippet, the source name, and the publication date.

Return ONLY a valid JSON array:
[
  {{
    "title": "Article title",
    "url": "https://...",
    "snippet": "Brief description of the activity",
    "source_name": "Source website",
    "published_at": "Date if available"
  }}
]

Return ONLY the JSON array, no other text. Include up to 10 results."""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            tools=[
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": 5
                }
            ],
            messages=[{"role": "user", "content": search_prompt}]
        )

        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        json_start = response_text.find('[')
        json_end = response_text.rfind(']') + 1
        if json_start >= 0 and json_end > json_start:
            raw_results = json.loads(response_text[json_start:json_end])
            items = []
            seen_links = set()
            for r in raw_results:
                link = r.get('url', '')
                if link and link not in seen_links:
                    seen_links.add(link)
                    items.append({
                        'title': r.get('title', ''),
                        'url': link,
                        'snippet': r.get('snippet', ''),
                        'published_at': r.get('published_at', ''),
                        'source_name': r.get('source_name', ''),
                        'city': city,
                        'state': state,
                    })
            return items
        else:
            print(f"[Discovery] No JSON array in Claude web_search response for {city}, {state}")
            return []

    except Exception as e:
        print(f"[Discovery] Claude web_search error for {city}, {state}: {e}")
        return []


# ---------------------------------------------------------------------------
# Classification — Claude (text-only, NO web_search tool)
# ---------------------------------------------------------------------------

def classify_signals(items, client):
    """
    Batch-classify raw news items into BTR signal types using Claude.
    Returns only items classified as relevant BTR activity.
    Items that already have a signal_type set by the adapter are passed through.
    """
    # Separate pre-classified items (from adapters) and unclassified
    pre_classified = []
    needs_classification = []

    for item in items:
        st = item.get('signal_type', '')
        if st and st not in ('', 'other', 'unclassified'):
            pre_classified.append(item)
        else:
            needs_classification.append(item)

    # Classify items without a signal type
    classified = list(pre_classified)
    batch_size = 10

    for i in range(0, len(needs_classification), batch_size):
        batch = needs_classification[i:i + batch_size]

        items_json = json.dumps([{
            'index': j,
            'title': it['title'],
            'snippet': it.get('snippet', ''),
            'source_name': it.get('source_name', ''),
            'source_type': it.get('source_type', 'news'),
            'city': it.get('city', ''),
        } for j, it in enumerate(batch)], indent=2)

        prompt = f"""Classify each news item below as a BTR/SFR (Build-to-Rent / Single-Family Rental) activity signal.

For each item, determine:
1. signal_type: one of "new_build", "under_construction", "permit_rezoning", "acquisition", "sale", "recapitalization", "financing", "other", or "not_relevant"
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
                        item['entity_name'] = cls.get('entity_name', '') or item.get('entity_name', '')
                        item['summary'] = cls.get('summary', '')
                        classified.append(item)

        except Exception as e:
            print(f"[Discovery] Classification error: {e}")
            # On failure, include items unclassified so they aren't lost
            for it in batch:
                c = it.copy()
                c['signal_type'] = 'unclassified'
                c.setdefault('entity_name', '')
                c['summary'] = it.get('title', '')
                classified.append(c)

        # Pause between Claude calls
        time.sleep(1)

    return classified


# ---------------------------------------------------------------------------
# Orchestrator (v2 — adapter-based)
# ---------------------------------------------------------------------------

def run_discovery_job(config, is_scheduled=False):
    """
    Main discovery orchestrator.
    Runs adapters, merges results, deduplicates, classifies, returns structured results.

    Args:
        config: Discovery configuration dict
        is_scheduled: True if this is the 7am scheduled run (runs all adapters including permits)

    Returns (results_dict, digest_text, total_new_count, adapter_stats).
    """
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

    cities = config['cities']
    max_new = config.get('max_signals_per_day', MAX_ITEMS_PER_DAY)

    print(f"[Discovery] Starting signal scan across {len(cities)} cities (max {max_new} new)...")
    print(f"[Discovery] Mode: {'scheduled' if is_scheduled else 'manual'}")

    # Reset the global rate limiter for this run
    discovery_limiter.reset()

    # --- Phase 1: Run adapters to collect raw items ---
    all_raw_items = []
    adapter_stats = {}

    # 1a. EDGAR adapter
    if ADAPTER_CONFIG['edgar']['enabled']:
        should_run = (is_scheduled and ADAPTER_CONFIG['edgar']['run_on_schedule']) or \
                     (not is_scheduled and ADAPTER_CONFIG['edgar']['run_on_manual'])
        if should_run:
            print("[Discovery] Running EDGAR adapter...")
            from adapters.edgar import EDGARAdapter
            edgar = EDGARAdapter(discovery_limiter)
            edgar_items = edgar.safe_fetch(cities, config)
            adapter_stats['edgar'] = {'items': len(edgar_items), 'status': 'ok'}
            _update_source_refresh('filing', len(edgar_items))
            all_raw_items.extend(edgar_items)
            print(f"[Discovery] EDGAR: {len(edgar_items)} items")
        else:
            adapter_stats['edgar'] = {'items': 0, 'status': 'skipped'}

    # 1b. Press release adapter
    if ADAPTER_CONFIG['press_release']['enabled']:
        should_run = (is_scheduled and ADAPTER_CONFIG['press_release']['run_on_schedule']) or \
                     (not is_scheduled and ADAPTER_CONFIG['press_release']['run_on_manual'])
        if should_run:
            print("[Discovery] Running press release adapter...")
            from adapters.press_release import PressReleaseAdapter
            pr = PressReleaseAdapter(discovery_limiter)
            pr_items = pr.safe_fetch(cities, config)
            adapter_stats['press_release'] = {'items': len(pr_items), 'status': 'ok'}
            _update_source_refresh('press_release', len(pr_items))
            all_raw_items.extend(pr_items)
            print(f"[Discovery] Press releases: {len(pr_items)} items")
        else:
            adapter_stats['press_release'] = {'items': 0, 'status': 'skipped'}

    # 1c. Permit adapter
    if ADAPTER_CONFIG['permit']['enabled']:
        should_run_live = is_scheduled and ADAPTER_CONFIG['permit']['run_on_schedule']
        use_cache_only = not should_run_live  # manual run only uses cached results

        if should_run_live or ADAPTER_CONFIG['permit']['run_on_manual']:
            print(f"[Discovery] Running permit adapter (cache_only={use_cache_only})...")
            from adapters.permit import PermitAdapter
            permit = PermitAdapter(discovery_limiter, use_cache_only=use_cache_only)
            permit_items = permit.safe_fetch(cities, config)
            adapter_stats['permit'] = {'items': len(permit_items), 'status': 'ok'}
            if permit_items:
                _update_source_refresh('permit', len(permit_items))
            all_raw_items.extend(permit_items)
            print(f"[Discovery] Permits: {len(permit_items)} items")
        else:
            adapter_stats['permit'] = {'items': 0, 'status': 'skipped'}

    # 1d. Legacy news (SerpAPI / Claude web_search) — always runs
    print("[Discovery] Running news search...")
    news_items = []
    for city_info in cities:
        if not discovery_limiter.can_call():
            break
        city = city_info['city']
        state = city_info['state']
        city_news = fetch_city_signals(city, state)
        news_items.extend(city_news)

    adapter_stats['news'] = {'items': len(news_items), 'status': 'ok'}
    _update_source_refresh('news', len(news_items))
    all_raw_items.extend(news_items)
    print(f"[Discovery] News: {len(news_items)} items")

    print(f"[Discovery] Total raw items from all adapters: {len(all_raw_items)}")
    print(f"[Discovery] Rate limiter calls used: {discovery_limiter.calls_used}")

    # --- Phase 2: Deduplicate ---
    unseen = []
    seen_urls = set()

    for item in all_raw_items:
        url = item.get('url', '')
        title = item.get('title', '')
        city = item.get('city', '')
        state = item.get('state', '')

        # URL-level dedup within this run
        if url and url in seen_urls:
            continue
        if url:
            seen_urls.add(url)

        fp = compute_fingerprint(title, url, city, state)
        if not is_seen(fp):
            item['fingerprint'] = fp
            unseen.append(item)

    print(f"[Discovery] After dedup: {len(unseen)} unseen items")

    if not unseen:
        results = {}
        for city_info in cities:
            location = f"{city_info['city']}, {city_info['state']}"
            results[location] = {'signals': [], 'new_count': 0}
        digest = _format_signal_digest(results, [])
        return results, digest, 0, adapter_stats

    # Limit what we classify to avoid excessive Claude calls
    unseen = unseen[:max_new + 10]

    # --- Phase 3: Classify with Claude ---
    classified = classify_signals(unseen, client)

    # --- Phase 4: Organize by city, cap, mark seen ---
    all_new_signals = []
    results = {}

    # Group by city
    city_signals = {}
    for sig in classified:
        city = sig.get('city', '') or 'Global'
        state = sig.get('state', '')
        location = f"{city}, {state}" if state else city
        city_signals.setdefault(location, []).append(sig)

    # Ensure all configured cities appear in results
    for city_info in cities:
        location = f"{city_info['city']}, {city_info['state']}"
        if location not in city_signals:
            city_signals[location] = []

    for location, signals in city_signals.items():
        city_new = []
        for sig in signals:
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
        if city_new:
            print(f"[Discovery] {location}: {len(city_new)} new signals")

    # Build digest
    digest = _format_signal_digest(results, all_new_signals)

    return results, digest, len(all_new_signals), adapter_stats


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
        # Group by source_type for summary
        source_counts = {}
        for s in all_signals:
            st = s.get('source_type', 'news')
            source_counts[st] = source_counts.get(st, 0) + 1

        lines.append("  Sources: " + ", ".join(f"{v} {k}" for k, v in source_counts.items()))
        lines.append("")

        for location, data in results.items():
            sigs = data.get('signals', [])
            if not sigs:
                continue
            lines.append(f"--- {location} ({len(sigs)} new) ---")
            for i, s in enumerate(sigs, 1):
                label = s.get('signal_type', 'other').replace('_', ' ').title()
                src = s.get('source_type', 'news').upper()
                conf = s.get('confidence', 'medium')
                lines.append(f"  {i}. [{label}] [{src}:{conf}] {s.get('entity_name', 'Unknown')}")
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
