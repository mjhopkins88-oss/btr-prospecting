"""
Background job functions for prospecting runs.
These run in background via RQ worker or threading fallback.
"""
import json
import time
import sqlite3
import uuid
import traceback
from datetime import datetime, timedelta
import anthropic
import os

DB_PATH = 'prospects.db'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def execute_prospecting_run(run_id, search_params):
    """
    Main prospecting job. Searches cities, deduplicates, stores results progressively.
    """
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

    cities = search_params.get('cities', [])
    max_per_city = search_params.get('maxProspectsPerCity', 25)
    max_total = min(search_params.get('maxTotalProspects', 300), 300)

    try:
        _update_run(run_id, status='running')

        all_prospects = []
        seen_companies = set()

        # Load existing company names for global dedup
        existing = _get_all_existing_companies()
        seen_companies.update(name.lower() for name in existing)

        for city_info in cities:
            if len(all_prospects) >= max_total:
                break

            # Accept both string and dict formats
            if isinstance(city_info, str):
                city = city_info
                state = ''
            else:
                city = city_info.get('city', '')
                state = city_info.get('state', '')

            if not city:
                continue

            remaining = min(max_per_city, max_total - len(all_prospects))
            print(f"[Job {run_id[:8]}] Searching {city}, {state} for up to {remaining} prospects...")

            prospects = _search_city(client, city, state, remaining, seen_companies)

            # Deduplicate within this run
            new_batch = []
            for p in prospects:
                key = p.get('company', '').lower().strip()
                if not key:
                    continue
                if key in seen_companies:
                    continue
                seen_companies.add(key)
                new_batch.append(p)

            # Store batch
            if new_batch:
                _store_run_prospects(run_id, new_batch)
                # Also insert into legacy prospects table
                _save_to_legacy_prospects(new_batch)
                all_prospects.extend(new_batch)
                _update_run(run_id, total_prospects=len(all_prospects))

            print(f"[Job {run_id[:8]}] {city}: {len(new_batch)} new prospects stored ({len(all_prospects)} total)")

            # Rate-limit between cities
            if len(cities) > 1:
                time.sleep(2)

        _update_run(run_id, status='completed',
                    completed_at=datetime.utcnow().isoformat(),
                    total_prospects=len(all_prospects))
        print(f"[Job {run_id[:8]}] Completed: {len(all_prospects)} prospects")

    except Exception as e:
        traceback.print_exc()
        _update_run(run_id, status='failed', error=str(e))
        print(f"[Job {run_id[:8]}] Failed: {e}")


def _search_city(client, city, state, limit, seen_companies):
    """Search for BTR prospects in a single city using Claude web search."""
    location = f"{city}, {state}" if state else city
    today = datetime.now().strftime('%B %d, %Y')
    ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime('%B %Y')

    # Exclude already-known companies
    exclude_names = [n for n in list(seen_companies)[:30] if n]
    exclude_clause = ""
    if exclude_names:
        names = ", ".join(exclude_names)
        exclude_clause = f"\n\nIMPORTANT: I already have these companies. Find DIFFERENT ones:\n{names}\n"

    # Cap per-API-call at 10 to keep response reliable
    ask_count = min(limit, 10)

    search_prompt = f"""You are a real estate intelligence researcher. Today's date is {today}.

Search for Build-to-Rent (BTR) / Single-Family Rental (SFR) developers in {location}.

SEARCH THESE SOURCES:
- bisnow.com — "build to rent {city}" or "BTR {city}"
- multihousingnews.com — "single family rental {city}"
- bizjournals.com — "build to rent {city}"
- linkedin.com — BTR developers in {city}
- commercialobserver.com, credaily.com — CRE news for {city}

SEARCH PATTERNS:
- "build to rent" + "{city}"
- "single family rental community" + "{city}"
- "groundbreaking" + "{city}"

ALSO CHECK for activity from: Invitation Homes, American Homes 4 Rent, Tricon Residential, Progress Residential in {location}.

FOCUS ON RECENT ACTIVITY from the last 90 days (since {ninety_days_ago}). Look for groundbreakings, land acquisitions, construction starts, capital raises, new projects.
{exclude_clause}
Find up to {ask_count} companies. For each extract:
- Company name
- CEO/key executive name and title
- LinkedIn profile URL (if findable)
- City and state
- Recent project name and details
- Project status (Under construction / Pre-leasing / etc.)
- Total Investment Value estimate
- Active signals (financing, construction, sales, expansion)
- Why to call them NOW (specific trigger)
- Score 0-100 based on: recency of activity, deal size, expansion signals

Return ONLY valid JSON:
{{
  "prospects": [
    {{
      "company": "Company Name",
      "executive": "Executive Name",
      "title": "CEO",
      "linkedin": "linkedin.com/in/profile",
      "city": "{city}",
      "state": "{state}",
      "score": 85,
      "tiv": "$50M-200M",
      "units": "200-500 units",
      "projectName": "Project Name",
      "projectStatus": "Under construction",
      "signals": ["Signal 1", "Signal 2"],
      "whyNow": "Why call now"
    }}
  ]
}}

CRITICAL: Return ONLY the JSON object, no other text."""

    try:
        max_retries = 3
        message = None
        for attempt in range(max_retries + 1):
            try:
                message = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=4096,
                    tools=[{
                        "type": "web_search_20250305",
                        "name": "web_search",
                        "max_uses": 5
                    }],
                    messages=[{"role": "user", "content": search_prompt}]
                )
                break
            except anthropic.RateLimitError:
                if attempt < max_retries:
                    wait_time = 2 ** (attempt + 1)
                    print(f"[Job] Rate limited for {location} (attempt {attempt + 1}), waiting {wait_time}s")
                    time.sleep(wait_time)
                else:
                    print(f"[Job] Rate limited for {location} after all retries")
                    return []

        if not message:
            return []

        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        if not response_text.strip():
            return []

        # Parse JSON with balanced-brace extraction
        json_start = response_text.find('{"prospects"')
        if json_start == -1:
            json_start = response_text.find('{  "prospects"')
        if json_start == -1:
            json_start = response_text.find('{\n')

        if json_start == -1:
            return []

        brace_count = 0
        json_end = json_start
        for i in range(json_start, len(response_text)):
            if response_text[i] == '{':
                brace_count += 1
            elif response_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = i + 1
                    break

        data = json.loads(response_text[json_start:json_end])
        prospects = data.get('prospects', [])
        return prospects[:limit]

    except Exception as e:
        print(f"[Job] Search error for {location}: {e}")
        return []


def _get_all_existing_companies():
    """Get all company names from both tables for dedup."""
    try:
        conn = get_db()
        c = conn.cursor()
        names = set()
        c.execute('SELECT DISTINCT company FROM prospects')
        names.update(row[0] for row in c.fetchall() if row[0])
        c.execute('SELECT DISTINCT company_name FROM run_prospects')
        names.update(row[0] for row in c.fetchall() if row[0])
        conn.close()
        return names
    except Exception:
        return set()


def _store_run_prospects(run_id, prospects):
    """Insert prospects into run_prospects table."""
    conn = get_db()
    c = conn.cursor()
    for p in prospects:
        try:
            c.execute('''
                INSERT OR IGNORE INTO run_prospects
                (id, run_id, company_name, city, state, score, tiv_estimate,
                 deal_status, signals, why_call_now, executive, title, linkedin,
                 units, project_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                run_id,
                p.get('company', ''),
                p.get('city', ''),
                p.get('state', ''),
                p.get('score', 0),
                p.get('tiv', ''),
                p.get('projectStatus', ''),
                json.dumps(p.get('signals', [])),
                p.get('whyNow', ''),
                p.get('executive', ''),
                p.get('title', ''),
                p.get('linkedin', ''),
                p.get('units', ''),
                p.get('projectName', ''),
                datetime.utcnow().isoformat()
            ))
        except Exception as e:
            print(f"[Job] Error storing prospect {p.get('company')}: {e}")
    conn.commit()
    conn.close()


def _save_to_legacy_prospects(prospects):
    """Also save to the original prospects table for backward compatibility."""
    conn = get_db()
    c = conn.cursor()
    for p in prospects:
        try:
            c.execute('''
                INSERT OR IGNORE INTO prospects
                (company, executive, title, linkedin, city, state, score, tiv, units,
                 project_name, project_status, signals, why_now)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                p.get('company'),
                p.get('executive'),
                p.get('title'),
                p.get('linkedin'),
                p.get('city'),
                p.get('state', ''),
                p.get('score'),
                p.get('tiv'),
                p.get('units'),
                p.get('projectName'),
                p.get('projectStatus'),
                json.dumps(p.get('signals', [])),
                p.get('whyNow')
            ))
        except Exception:
            pass
    conn.commit()
    conn.close()


def _update_run(run_id, **kwargs):
    """Update a prospecting_runs row."""
    conn = get_db()
    c = conn.cursor()
    sets = []
    values = []
    for k, v in kwargs.items():
        sets.append(f"{k} = ?")
        values.append(v)
    sets.append("updated_at = ?")
    values.append(datetime.utcnow().isoformat())
    values.append(run_id)
    c.execute(f"UPDATE prospecting_runs SET {', '.join(sets)} WHERE id = ?", values)
    conn.commit()
    conn.close()
