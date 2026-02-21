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

            # Rate-limit between cities (configurable)
            if len(cities) > 1:
                between_delay = float(os.getenv('SERP_BETWEEN_CITY_DELAY_SECONDS', '5'))
                time.sleep(between_delay)

        _update_run(run_id, status='completed',
                    completed_at=datetime.utcnow().isoformat(),
                    total_prospects=len(all_prospects))
        print(f"[Job {run_id[:8]}] Completed: {len(all_prospects)} prospects")

    except Exception as e:
        traceback.print_exc()
        _update_run(run_id, status='failed', error=str(e))
        print(f"[Job {run_id[:8]}] Failed: {e}")


def _search_city(client, city, state, limit, seen_companies):
    """
    Search for BTR prospects in a single city.
    Stage A: SerpAPI retrieves candidate URLs/snippets.
    Stage B: Claude extracts + scores + generates "Why Call Now".
    """
    from serpapi_client import cached_serpapi_search, SerpAPIError

    location = f"{city}, {state}" if state else city
    today = datetime.now().strftime('%B %d, %Y')
    ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime('%B %Y')

    # --- Stage A: SerpAPI candidate retrieval ---
    queries = [
        f'site:bisnow.com ("build to rent" OR BTR) "{city} {state}"',
        f'site:multihousingnews.com ("build to rent" OR BTR) "{city} {state}"',
        f'site:bizjournals.com ("build to rent" OR BTR) "{city} {state}"',
        f'("build to rent" OR "single family rental community") ("{city}" OR "{city} {state}") (acquires OR acquisition OR sells OR sale OR groundbreaking OR "under construction")',
    ]

    all_candidates = []
    seen_links = set()

    for query in queries:
        try:
            results = cached_serpapi_search(
                query, num=5, feature='prospect', city=city, state=state
            )
            for r in results:
                link = r.get('link', '')
                if link and link not in seen_links:
                    seen_links.add(link)
                    all_candidates.append(r)
        except SerpAPIError as e:
            print(f"[Job] SerpAPI error for {location}: {e}")
            # Surface error so it propagates to the UI
            raise
        except Exception as e:
            print(f"[Job] SerpAPI query failed for {location}: {e}")

        # Stop early if we have enough candidates
        if len(all_candidates) >= 20:
            break

    if not all_candidates:
        print(f"[Job] No SerpAPI candidates found for {location}")
        return []

    print(f"[Job] {location}: {len(all_candidates)} candidate URLs from SerpAPI")

    # --- Stage B: Claude extraction from candidates ---
    # Exclude already-known companies
    exclude_names = [n for n in list(seen_companies)[:30] if n]
    exclude_clause = ""
    if exclude_names:
        names = ", ".join(exclude_names)
        exclude_clause = f"\n\nIMPORTANT: I already have these companies. Find DIFFERENT ones:\n{names}\n"

    ask_count = min(limit, 10)
    all_prospects = []

    # Process candidates in batches of 10
    for batch_start in range(0, len(all_candidates), 10):
        if len(all_prospects) >= ask_count:
            break

        batch = all_candidates[batch_start:batch_start + 10]
        candidates_json = json.dumps([{
            'title': c['title'],
            'url': c['link'],
            'snippet': c.get('snippet', ''),
            'source': c.get('source', ''),
            'date': c.get('date', ''),
        } for c in batch], indent=2)

        extraction_prompt = f"""You are a real estate intelligence researcher. Today's date is {today}.

I have search results about Build-to-Rent (BTR) / Single-Family Rental (SFR) activity in {location}.
Analyze these search results and extract BTR developer prospects.

SEARCH RESULTS:
{candidates_json}

FOCUS ON RECENT ACTIVITY from the last 90 days (since {ninety_days_ago}). Look for groundbreakings, land acquisitions, construction starts, capital raises, new projects.
{exclude_clause}
Extract up to {ask_count - len(all_prospects)} companies from these results. For each extract:
- Company name
- CEO/key executive name and title (if mentioned)
- LinkedIn profile URL (if mentioned)
- City and state
- Recent project name and details
- Project status (Under construction / Pre-leasing / etc.)
- Total Investment Value estimate (if mentioned)
- Active signals (financing, construction, sales, expansion)
- Why to call them NOW (specific trigger from the search result)
- Score 0-100 (the total of the four sub-scores below)
- Score breakdown (must sum to the total score):
  - capital_event (0-40): recapitalizations, credit facilities, JV capital, acquisitions, institutional partners
  - construction_stage (0-25): under construction, groundbreaking, permitting, first deliveries
  - expansion_velocity (0-20): multi-market growth, pipeline mentions, "expanding into", multiple projects
  - freshness (0-15): activity within last 14 days=15, last 30 days=10, last 90 days=5
- Score explanation: 2-4 bullet points explaining why it scored that way
- Insurance triggers: 0-4 labels from this list that apply:
  "Builder's Risk → Property conversion", "New lender covenants / insurance requirements",
  "Portfolio scale / blanket limits", "New state expansion", "JV / institutional capital event",
  "Refinance window / debt facility", "Lease-up stabilization shift"

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
      "score_breakdown": {{
        "capital_event": 35,
        "construction_stage": 20,
        "expansion_velocity": 18,
        "freshness": 12
      }},
      "score_explanation": [
        "Recent $200M credit facility with institutional lender",
        "3 communities under construction across TX",
        "Expanding into AZ and FL markets",
        "Activity reported within last 2 weeks"
      ],
      "insurance_triggers": [
        "Builder's Risk → Property conversion",
        "JV / institutional capital event"
      ],
      "tiv": "$50M-200M",
      "units": "200-500 units",
      "projectName": "Project Name",
      "projectStatus": "Under construction",
      "signals": ["Signal 1", "Signal 2"],
      "whyNow": "Why call now"
    }}
  ]
}}

CRITICAL: Return ONLY the JSON object, no other text. Only include companies clearly related to BTR/SFR development."""

        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                messages=[{"role": "user", "content": extraction_prompt}]
            )

            response_text = ""
            for block in message.content:
                if block.type == "text":
                    response_text += block.text

            if not response_text.strip():
                continue

            # Parse JSON with balanced-brace extraction
            json_start = response_text.find('{"prospects"')
            if json_start == -1:
                json_start = response_text.find('{  "prospects"')
            if json_start == -1:
                json_start = response_text.find('{\n')

            if json_start == -1:
                continue

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
            all_prospects.extend(prospects)

        except anthropic.RateLimitError:
            print(f"[Job] Claude rate limited during extraction for {location}")
            time.sleep(5)
        except Exception as e:
            print(f"[Job] Claude extraction error for {location}: {e}")

    return all_prospects[:limit]


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
            # Pack new scoring fields into score_meta JSON blob
            score_meta = json.dumps({
                'score_breakdown': p.get('score_breakdown', {}),
                'score_explanation': p.get('score_explanation', []),
                'insurance_triggers': p.get('insurance_triggers', []),
            })
            c.execute('''
                INSERT OR IGNORE INTO run_prospects
                (id, run_id, company_name, city, state, score, tiv_estimate,
                 deal_status, signals, why_call_now, executive, title, linkedin,
                 units, project_name, created_at, score_meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                datetime.utcnow().isoformat(),
                score_meta
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
