"""
BTR Prospecting System - Backend Server
Flask API with Claude AI integration for automated prospect discovery
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import json
import time
import csv
import io
import anthropic
from dotenv import load_dotenv
import sqlite3
import re
import threading
import traceback
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static')
CORS(app)

# Initialize Claude client
client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

# Simple in-memory cache to avoid redundant API calls
# Key: "city|limit", Value: {"prospects": [...], "timestamp": datetime}
_search_cache = {}
CACHE_TTL_SECONDS = 900  # 15 minutes

# Daily Discovery configuration
DISCOVERY_CONFIG = {
    'cities': [
        {'city': 'Phoenix', 'state': 'AZ'},
        {'city': 'Dallas', 'state': 'TX'},
        {'city': 'Atlanta', 'state': 'GA'},
        {'city': 'Charlotte', 'state': 'NC'},
    ],
    'icp_keywords': [
        'build to rent developer',
        'single family rental',
        'residential land developer',
        'homebuilder',
        'horizontal multifamily',
        'BTR community builder',
    ],
    'target_sources': [
        'bisnow.com',
        'multihousingnews.com',
        'credaily.com',
        'commercialobserver.com',
        'bizjournals.com',
        'linkedin.com',
        'sec.gov EDGAR',
    ],
    'search_patterns': [
        '"build to rent" + {city}',
        '"single family rental community" + {city}',
        '"groundbreaking" + {city}',
    ],
    'monitor_operators': [
        'Invitation Homes',
        'American Homes 4 Rent',
        'Tricon Residential',
        'Progress Residential',
    ],
    'min_rating': 4.0,
    'min_reviews': 10,
    'top_n_per_city': 1,
    'schedule_hour': 7,
    'schedule_minute': 0,
    'timezone': 'America/Los_Angeles',
    'delivery_method': 'in_app',  # 'in_app' or 'webhook'
    'webhook_url': '',
}

# Track whether a discovery run is in progress
_discovery_running = False

# Database setup
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS prospects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT NOT NULL,
            executive TEXT,
            title TEXT,
            linkedin TEXT,
            email TEXT,
            phone TEXT,
            city TEXT,
            state TEXT,
            score INTEGER,
            tiv TEXT,
            units TEXT,
            project_name TEXT,
            project_status TEXT,
            signals TEXT,
            why_now TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(company, project_name)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS discovery_seen (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_name TEXT NOT NULL,
            city TEXT NOT NULL,
            state TEXT NOT NULL,
            address TEXT,
            phone TEXT,
            website TEXT,
            rating REAL,
            review_count INTEGER,
            category TEXT,
            icp_keyword TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(business_name, city, state)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS discovery_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            results_json TEXT,
            digest_text TEXT,
            city_count INTEGER DEFAULT 0,
            total_new INTEGER DEFAULT 0,
            status TEXT DEFAULT 'completed'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def search_btr_prospects(city="Texas", limit=10):
    """
    Use Claude API to search for BTR prospects.
    Returns (prospects_list, error_message) tuple.
    """
    # Check API key first
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key or api_key == 'your_anthropic_api_key_here':
        return [], "ANTHROPIC_API_KEY is not set. Add it to your .env file or Railway environment variables."

    # Check cache first to avoid redundant API calls
    cache_key = f"{city.lower().strip()}|{limit}"
    if cache_key in _search_cache:
        cached = _search_cache[cache_key]
        age = (datetime.now() - cached['timestamp']).total_seconds()
        if age < CACHE_TTL_SECONDS:
            print(f"Returning cached results for {city} ({int(age)}s old)")
            return cached['prospects'], None
        else:
            del _search_cache[cache_key]

    try:
        # Get existing companies so we can ask for NEW ones
        existing = get_existing_companies(city)
        exclude_clause = ""
        if existing:
            names = ", ".join(existing[:20])  # Cap at 20 to keep prompt short
            exclude_clause = f"\n\nIMPORTANT: I already have these companies in my database, so DO NOT include them. Find DIFFERENT companies:\n{names}\n"

        today = datetime.now().strftime('%B %d, %Y')

        # Construct search prompt with date awareness
        search_prompt = f"""You are a real estate intelligence researcher. Today's date is {today}.

Search for Build-to-Rent (BTR) / Single-Family Rental (SFR) developers in {city}.

FOCUS ON RECENT ACTIVITY: Prioritize news, deals, and developments from the last 90 days (since {(datetime.now() - timedelta(days=90)).strftime('%B %Y')}). Look for the most current and up-to-date information available.
{exclude_clause}
Find companies that are:
1. Actively developing BTR/SFR communities with recent activity
2. Have news from the last 1-3 months (capital raises, acquisitions, new projects, construction starts, land purchases)
3. Are expansion-focused or institutional-backed

For each prospect, extract:
- Company name
- CEO/key executive name
- LinkedIn profile (if findable)
- City location
- Recent project details (include dates when available)
- Active signals (financing, construction, sales, expansion)
- Total Investment Value estimate

Search for {min(limit, 5)} prospects and return ONLY valid JSON in this exact format:

{{
  "prospects": [
    {{
      "company": "Company Name",
      "executive": "Executive Name",
      "title": "CEO",
      "linkedin": "linkedin.com/in/profile",
      "city": "City",
      "state": "TX",
      "score": 85,
      "tiv": "$50M-200M",
      "units": "200-500 units",
      "projectName": "Project Name",
      "projectStatus": "Under construction / Pre-leasing / Recently opened",
      "signals": ["Signal 1", "Signal 2", "Signal 3"],
      "whyNow": "Why call this prospect now"
    }}
  ]
}}

CRITICAL: Return ONLY the JSON object, no other text. Use real web search to find current, accurate data."""

        print(f"Calling Claude API for {city} prospects...")

        # Retry with exponential backoff on rate limit errors
        max_retries = 3
        message = None
        for attempt in range(max_retries + 1):
            try:
                message = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=2000,
                    tools=[
                        {
                            "type": "web_search_20250305",
                            "name": "web_search",
                            "max_uses": 2
                        }
                    ],
                    messages=[
                        {
                            "role": "user",
                            "content": search_prompt
                        }
                    ]
                )
                break  # Success - exit retry loop
            except anthropic.RateLimitError:
                if attempt < max_retries:
                    wait_time = 2 ** (attempt + 1)  # 2s, 4s, 8s
                    print(f"Rate limited (attempt {attempt + 1}/{max_retries + 1}), waiting {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    return [], "API rate limit reached after retries. Please wait 1-2 minutes and try again."

        if message is None:
            return [], "Failed to get a response from Claude API. Try again."

        # Extract response text from all text blocks
        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        print(f"Claude response length: {len(response_text)} chars")

        if not response_text.strip():
            return [], "Claude returned an empty response. The AI may still be searching - try again."

        # Parse JSON from response - find the JSON object containing "prospects"
        # Use a balanced brace approach for more reliable extraction
        json_start = response_text.find('{"prospects"')
        if json_start == -1:
            json_start = response_text.find('{  "prospects"')
        if json_start == -1:
            json_start = response_text.find('{\n')

        if json_start != -1:
            # Find the matching closing brace
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

            json_str = response_text[json_start:json_end]
            try:
                data = json.loads(json_str)
                prospects = data.get('prospects', [])
                if prospects:
                    print(f"Successfully parsed {len(prospects)} prospects")
                    # Cache successful results
                    _search_cache[cache_key] = {
                        'prospects': prospects,
                        'timestamp': datetime.now()
                    }
                    return prospects, None
                else:
                    return [], "Claude found no prospects in this area. Try a different city or state."
            except json.JSONDecodeError as e:
                print(f"JSON parse error: {e}")
                print(f"Attempted to parse: {json_str[:500]}")
                return [], f"Failed to parse AI response. Try searching again."
        else:
            print(f"No JSON found in response: {response_text[:500]}")
            return [], "AI response did not contain prospect data. Try searching again."

    except anthropic.AuthenticationError:
        return [], "Invalid ANTHROPIC_API_KEY. Check your API key in .env or Railway variables."
    except anthropic.APIConnectionError:
        return [], "Cannot connect to Claude API. Check your internet connection."
    except Exception as e:
        print(f"Search error: {str(e)}")
        return [], f"Search failed: {str(e)}"

def get_existing_companies(city=None):
    """Get list of company names already in the database, optionally filtered by city"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    if city:
        c.execute('SELECT DISTINCT company FROM prospects WHERE LOWER(city) LIKE ? OR LOWER(state) LIKE ?',
                  (f'%{city.lower()}%', f'%{city.lower()}%'))
    else:
        c.execute('SELECT DISTINCT company FROM prospects')
    companies = [row[0] for row in c.fetchall()]
    conn.close()
    return companies

def save_prospects_to_db(prospects):
    """Save prospects to SQLite database"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    
    saved_count = 0
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
                p.get('state', 'TX'),
                p.get('score'),
                p.get('tiv'),
                p.get('units'),
                p.get('projectName'),
                p.get('projectStatus'),
                json.dumps(p.get('signals', [])),
                p.get('whyNow')
            ))
            if c.rowcount > 0:
                saved_count += 1
        except Exception as e:
            print(f"Error saving prospect {p.get('company')}: {str(e)}")
            continue
    
    conn.commit()
    conn.close()
    return saved_count

def get_all_prospects_from_db():
    """Retrieve all prospects from database"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT * FROM prospects ORDER BY score DESC, created_at DESC')
    
    prospects = []
    for row in c.fetchall():
        prospects.append({
            'id': row[0],
            'company': row[1],
            'executive': row[2],
            'title': row[3],
            'linkedin': row[4],
            'email': row[5],
            'phone': row[6],
            'city': row[7],
            'state': row[8],
            'score': row[9],
            'tiv': row[10],
            'units': row[11],
            'projectName': row[12],
            'projectStatus': row[13],
            'signals': json.loads(row[14]) if row[14] else [],
            'whyNow': row[15],
            'createdAt': row[16]
        })
    
    conn.close()
    return prospects

MASTER_CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'btr-prospects-master.csv')

def generate_master_csv():
    """Regenerate the master CSV spreadsheet from all database prospects"""
    prospects = get_all_prospects_from_db()

    headers = [
        'Company', 'Executive', 'Title', 'LinkedIn', 'City', 'State',
        'Score', 'TIV', 'Units', 'Project Name', 'Project Status',
        'Signals', 'Why Call Now', 'Date Found'
    ]

    with open(MASTER_CSV_PATH, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for p in prospects:
            signals = ', '.join(p.get('signals', [])) if isinstance(p.get('signals'), list) else p.get('signals', '')
            writer.writerow([
                p.get('company', ''),
                p.get('executive', ''),
                p.get('title', ''),
                p.get('linkedin', ''),
                p.get('city', ''),
                p.get('state', ''),
                p.get('score', ''),
                p.get('tiv', ''),
                p.get('units', ''),
                p.get('projectName', ''),
                p.get('projectStatus', ''),
                signals,
                p.get('whyNow', ''),
                p.get('createdAt', '')
            ])

    print(f"Master CSV updated: {len(prospects)} prospects written to {MASTER_CSV_PATH}")
    return len(prospects)

# Generate master CSV on startup if prospects exist
generate_master_csv()

# --- Daily Discovery Engine ---

def get_seen_businesses(city, state):
    """Get list of business names already seen for a city"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT business_name FROM discovery_seen WHERE LOWER(city) = ? AND LOWER(state) = ?',
              (city.lower(), state.lower()))
    names = [row[0] for row in c.fetchall()]
    conn.close()
    return names


def search_city_directory(city_info, config):
    """Search business directories for one city using Claude web search.
    Returns (filtered_businesses_list, error_message_or_None)."""
    city = city_info['city']
    state = city_info['state']

    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key or api_key == 'your_anthropic_api_key_here':
        return [], "API key not configured"

    seen_names = get_seen_businesses(city, state)
    seen_clause = ""
    if seen_names:
        names_list = ", ".join(seen_names[:30])
        seen_clause = f"\n\nSKIP these businesses I have already catalogued — do NOT include them:\n{names_list}\n"

    keywords_list = "\n".join(f"- {kw}" for kw in config['icp_keywords'])
    sources_list = "\n".join(f"- {src}" for src in config.get('target_sources', []))
    patterns_list = "\n".join(f"- {p.replace('{city}', city)}" for p in config.get('search_patterns', []))
    operators_list = ", ".join(config.get('monitor_operators', []))
    today = datetime.now().strftime('%B %d, %Y')
    min_rating = config['min_rating']
    min_reviews = config['min_reviews']

    prompt = f"""You are a BTR/SFR industry researcher. Today is {today}.

Find companies actively building or operating Build-to-Rent / Single-Family Rental communities in {city}, {state}.

PRIORITY SOURCES — search these first:
{sources_list}

SEARCH PATTERNS to use:
{patterns_list}

ICP KEYWORDS:
{keywords_list}

ALSO CHECK for recent activity from these major BTR operators in {city}:
{operators_list}

WHAT TO LOOK FOR:
- News articles about BTR groundbreakings, land acquisitions, or construction starts in {city}
- LinkedIn profiles of BTR developers headquartered in or expanding to {city}
- Developer press releases announcing new communities
- Companies listed as BTR/SFR builders on industry sites

For each company found, extract: name, address, phone, website, rating (if available, otherwise use 5.0), review_count (if available, otherwise use 10), category, and which ICP keyword they match.
{seen_clause}
Return ONLY valid JSON in this exact format:
{{
  "businesses": [
    {{
      "name": "Company Name",
      "address": "Full Address, {city}, {state} ZIP",
      "phone": "(555) 123-4567",
      "website": "https://example.com",
      "rating": 4.5,
      "review_count": 87,
      "category": "BTR Developer",
      "icp_match": "build to rent developer"
    }}
  ]
}}

Find up to 3 businesses. Return ONLY the JSON object, no other text."""

    try:
        max_retries = 3
        message = None
        for attempt in range(max_retries + 1):
            try:
                message = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1000,
                    tools=[{
                        "type": "web_search_20250305",
                        "name": "web_search",
                        "max_uses": 2
                    }],
                    messages=[{"role": "user", "content": prompt}]
                )
                break
            except anthropic.RateLimitError:
                if attempt < max_retries:
                    wait_time = 2 ** (attempt + 1)
                    print(f"[Discovery] Rate limited for {city}, {state} (attempt {attempt + 1}), waiting {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    return [], "Rate limited after retries"

        if message is None:
            return [], "No response from API"

        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        if not response_text.strip():
            return [], "Empty response"

        # Parse JSON using balanced-brace extraction
        json_start = response_text.find('{"businesses"')
        if json_start == -1:
            json_start = response_text.find('{\n')
        if json_start == -1:
            json_start = response_text.find('{')

        if json_start == -1:
            return [], "No JSON found in response"

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

        json_str = response_text[json_start:json_end]
        data = json.loads(json_str)
        businesses = data.get('businesses', [])

        # Filter by minimum rating and review count, deduplicate
        seen_lower = [s.lower() for s in seen_names]
        filtered = []
        for b in businesses:
            try:
                rating = float(b.get('rating', 0))
                reviews = int(b.get('review_count', 0))
            except (ValueError, TypeError):
                continue
            name = b.get('name', '').strip()
            if not name:
                continue
            if rating < min_rating or reviews < min_reviews:
                continue
            if name.lower() in seen_lower:
                continue
            b['rating'] = rating
            b['review_count'] = reviews
            filtered.append(b)

        # Rank by rating DESC, then review_count DESC
        filtered.sort(key=lambda x: (-x['rating'], -x['review_count']))

        return filtered, None

    except anthropic.AuthenticationError:
        return [], "Invalid API key"
    except json.JSONDecodeError as e:
        print(f"[Discovery] JSON parse error for {city}, {state}: {e}")
        return [], "Failed to parse response"
    except Exception as e:
        print(f"[Discovery] Error for {city}, {state}: {e}")
        return [], str(e)


def format_discovery_digest(results):
    """Format discovery results into a human-readable digest"""
    lines = []
    lines.append("=" * 60)
    lines.append("  BTR DAILY DISCOVERY DIGEST")
    lines.append(f"  {datetime.now().strftime('%A, %B %d, %Y at %I:%M %p PT')}")
    lines.append("=" * 60)
    lines.append("")

    total_new = 0
    for location, data in results.items():
        businesses = data.get('businesses', [])
        new_count = data.get('new_count', 0)
        error = data.get('error', '')
        total_new += new_count

        lines.append(f"--- {location} ---")
        if error:
            lines.append(f"  [Error: {error}]")
        elif not businesses:
            lines.append("  No new businesses found.")
        else:
            for i, b in enumerate(businesses, 1):
                lines.append(f"  {i}. {b.get('name', 'Unknown')}")
                lines.append(f"     Rating: {b.get('rating', 'N/A')} stars ({b.get('review_count', 0)} reviews)")
                lines.append(f"     Category: {b.get('category', 'N/A')}")
                if b.get('address'):
                    lines.append(f"     Address: {b['address']}")
                if b.get('phone'):
                    lines.append(f"     Phone: {b['phone']}")
                if b.get('website'):
                    lines.append(f"     Website: {b['website']}")
                lines.append("")
        lines.append("")

    lines.append(f"TOTAL NEW DISCOVERIES: {total_new}")
    lines.append("=" * 60)
    return "\n".join(lines)


def run_daily_discovery():
    """Main daily discovery orchestrator — searches all configured cities"""
    config = DISCOVERY_CONFIG
    top_n = config['top_n_per_city']

    print(f"[Discovery] Starting daily discovery run at {datetime.now().isoformat()}")

    all_results = {}
    total_new = 0

    for city_info in config['cities']:
        city = city_info['city']
        state = city_info['state']
        location = f"{city}, {state}"

        print(f"[Discovery] Searching {location}...")

        businesses, error = search_city_directory(city_info, config)

        if error:
            print(f"[Discovery] Error for {location}: {error}")
            all_results[location] = {'businesses': [], 'error': error}
            continue

        # Take top N per city
        top_businesses = businesses[:top_n]

        # Persist new results to discovery_seen
        conn = sqlite3.connect('prospects.db')
        c = conn.cursor()
        new_count = 0
        for b in top_businesses:
            try:
                c.execute('''
                    INSERT OR IGNORE INTO discovery_seen
                    (business_name, city, state, address, phone, website, rating, review_count, category, icp_keyword)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    b.get('name', ''),
                    city, state,
                    b.get('address', ''),
                    b.get('phone', ''),
                    b.get('website', ''),
                    b.get('rating', 0),
                    b.get('review_count', 0),
                    b.get('category', ''),
                    b.get('icp_match', '')
                ))
                if c.rowcount > 0:
                    new_count += 1
            except Exception as e:
                print(f"[Discovery] Error saving {b.get('name')}: {e}")
        conn.commit()
        conn.close()

        total_new += new_count
        all_results[location] = {
            'businesses': top_businesses,
            'new_count': new_count,
            'total_found': len(businesses)
        }
        print(f"[Discovery] {location}: {len(top_businesses)} top results, {new_count} new")

        # Pace between cities to avoid rate limiting
        time.sleep(2)

    # Generate formatted digest
    digest = format_discovery_digest(all_results)

    # Save run record
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO discovery_runs (results_json, digest_text, city_count, total_new, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        json.dumps(all_results),
        digest,
        len(config['cities']),
        total_new,
        'completed'
    ))
    conn.commit()
    conn.close()

    # Deliver via webhook if configured
    if config['delivery_method'] == 'webhook' and config['webhook_url']:
        try:
            import urllib.request
            payload = json.dumps({
                'type': 'daily_discovery',
                'run_at': datetime.now().isoformat(),
                'total_new': total_new,
                'results': all_results,
                'digest': digest
            }).encode('utf-8')
            req = urllib.request.Request(
                config['webhook_url'],
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=10)
            print(f"[Discovery] Webhook delivered to {config['webhook_url']}")
        except Exception as e:
            print(f"[Discovery] Webhook delivery failed: {e}")

    print(f"[Discovery] Run complete. {total_new} new businesses across {len(config['cities'])} cities.")
    return all_results, digest

# API Routes

@app.route('/')
def index():
    """Serve the main HTML app"""
    return send_from_directory('static', 'index.html')

@app.route('/favicon.ico')
def favicon():
    """Prevent favicon 404 errors"""
    return '', 204

@app.route('/health')
def health():
    """Simple health check for Railway"""
    return jsonify({'status': 'ok'}), 200

@app.route('/api/health')
def api_health():
    """API health check endpoint"""
    api_key = os.getenv('ANTHROPIC_API_KEY')
    key_status = 'not set'
    if api_key and api_key != 'your_anthropic_api_key_here':
        key_status = f'configured (ends in ...{api_key[-4:]})'
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'api_key_status': key_status
    }), 200

@app.route('/api/search', methods=['POST'])
def api_search():
    """Search for new BTR prospects"""
    try:
        data = request.json
        city = data.get('city', 'Texas')
        limit = data.get('limit', 10)

        print(f"Searching for {limit} prospects in {city}...")

        # Search using Claude API - now returns (prospects, error_msg)
        prospects, error_msg = search_btr_prospects(city, limit)

        if error_msg:
            # On rate limit or API failure, return existing DB results so UI isn't empty
            db_prospects = get_all_prospects_from_db()
            return jsonify({
                'success': False,
                'message': error_msg,
                'prospects': db_prospects,
                'fromCache': True
            }), 200

        if not prospects:
            return jsonify({
                'success': False,
                'message': 'No prospects found. Try a different city or state.',
                'prospects': []
            }), 200

        # Save to database
        saved_count = save_prospects_to_db(prospects)

        # Auto-update master spreadsheet
        total = generate_master_csv()

        return jsonify({
            'success': True,
            'message': f'Found {len(prospects)} prospects, saved {saved_count} new ones. Master spreadsheet updated ({total} total).',
            'prospects': prospects,
            'savedCount': saved_count,
            'totalInSpreadsheet': total
        })

    except Exception as e:
        print(f"API Error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Search failed: {str(e)}',
            'prospects': []
        }), 500

@app.route('/api/prospects', methods=['GET'])
def api_get_prospects():
    """Get all prospects from database"""
    try:
        prospects = get_all_prospects_from_db()
        return jsonify({
            'success': True,
            'prospects': prospects
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e),
            'prospects': []
        }), 500

@app.route('/api/prospects/<int:prospect_id>', methods=['DELETE'])
def api_delete_prospect(prospect_id):
    """Delete a prospect"""
    try:
        conn = sqlite3.connect('prospects.db')
        c = conn.cursor()
        c.execute('DELETE FROM prospects WHERE id = ?', (prospect_id,))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Prospect deleted'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/export', methods=['GET'])
def api_export_csv():
    """Download the master CSV spreadsheet with all prospects"""
    try:
        # Always regenerate fresh from DB before download
        count = generate_master_csv()
        if count == 0:
            return jsonify({
                'success': False,
                'message': 'No prospects to export. Run a search first.'
            }), 200

        return send_file(
            MASTER_CSV_PATH,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'btr-prospects-master-{datetime.now().strftime("%Y-%m-%d")}.csv'
        )
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Export failed: {str(e)}'
        }), 500

@app.route('/api/email/generate', methods=['POST'])
def api_generate_email():
    """Generate personalized email for a prospect using EMAIL GEN SPEC"""
    try:
        data = request.json
        prospect = data.get('prospect', {})

        if not prospect or not prospect.get('company'):
            return jsonify({
                'success': False,
                'message': 'No prospect data provided.'
            }), 400

        # Email options (with defaults)
        email_purpose = data.get('emailPurpose', 'cold_outreach')
        tone = data.get('tone', 'professional_direct')
        offer = data.get('offer', '15_min_call')
        trigger_event = data.get('triggerEvent', '')

        # Extract name parts safely
        full_name = str(prospect.get('executive', '') or '').strip()
        name_parts = full_name.split() if full_name else []
        first_name = name_parts[0] if name_parts else 'there'
        last_name = name_parts[-1] if len(name_parts) > 1 else ''

        # Determine role-based angle from title
        title = str(prospect.get('title', '') or '').lower()
        if any(k in title for k in ['cfo', 'finance', 'capital', 'treasurer']):
            role_angle = "CFO/Finance: cost of risk -> DSCR/refi/exit impact"
        elif any(k in title for k in ['asset', 'portfolio']):
            role_angle = "Asset Management: portfolio consistency + claims outcomes + renewals stability"
        elif any(k in title for k in ['develop', 'construction', 'build', 'project']):
            role_angle = "Developer/Construction: structure early + construction-to-perm + cost control"
        elif any(k in title for k in ['operat', 'property', 'manage']):
            role_angle = "Operations: fewer surprises + smoother renewals + practical risk fixes"
        elif any(k in title for k in ['broker', 'agent']):
            role_angle = "Broker/AM: partnership + differentiated capacity + program fit"
        else:
            role_angle = "Developer/Construction: structure early + construction-to-perm + cost control"

        # Safely handle signals - could be list, JSON string, or plain string
        raw_signals = prospect.get('signals', [])
        if isinstance(raw_signals, str):
            try:
                raw_signals = json.loads(raw_signals)
            except (json.JSONDecodeError, ValueError):
                raw_signals = [raw_signals] if raw_signals else []
        if isinstance(raw_signals, list):
            signals = ', '.join(str(s) for s in raw_signals)
        else:
            signals = str(raw_signals)

        trigger = str(trigger_event or prospect.get('whyNow', '') or '')

        prompt = f"""You are an expert B2B email copywriter for commercial insurance. Follow the EMAIL GEN SPEC exactly.

RULES:
- 90-150 words total (HARD CAP 170)
- 2-4 short paragraphs, 1-2 sentences each
- Grade level: clear, plain English; no jargon unless industry-specific
- Ask exactly ONE question, and it must be the CTA
- No bullet lists
- Do NOT use any of these phrases: "Hope you're doing well", "hope this finds you well", "Just checking in", "Circling back" (unless follow_up), multiple CTAs, overconfident claims
- Include at most ONE specific detail reference about the company/project
- If you cannot verify a detail, omit it — NEVER invent facts
- No generic flattery ("impressive company", "love what you're doing")

Generate a personalized email with these inputs:

RECIPIENT:
- recipient_first_name: {first_name}
- recipient_last_name: {last_name}
- recipient_title: {prospect.get('title') or 'Executive'}
- company_name: {prospect.get('company', '')}
- industry: BTR (Build-to-Rent)
- geography: {prospect.get('city') or 'Texas'}, {prospect.get('state') or 'TX'}

EMAIL CONFIG:
- email_purpose: {email_purpose}
- tone: {tone}
- offer: {offer}
- value_prop: We specialize in protecting BTR portfolios — structuring insurance programs that safeguard NOI, stabilize renewal costs, and protect exit valuations from day one.

SENDER:
- sender_name: Max Hopkins
- sender_title: BTR Insurance Specialist
- sender_company: BTR Insurance
- sender_email: max@btrinsurance.com

CONTEXT:
- Project: {prospect.get('projectName') or 'N/A'}
- Project Status: {prospect.get('projectStatus') or 'N/A'}
- TIV: {prospect.get('tiv') or 'N/A'}
- Units: {prospect.get('units') or 'N/A'}
- Signals: {signals}
- Trigger Event / Why Now: {trigger}

ROLE-BASED ANGLE TO USE: {role_angle}

CTA RULES:
- If offer is 15_min_call: "Open to a quick 15-minute call this week?"
- If offer is share_resource: Offer to send a relevant resource
- If offer is quick_question: Ask one specific question about their situation

OUTPUT FORMAT — Return ONLY valid JSON, nothing else:
{{"subject": "3-6 word subject line", "body": "Hi {first_name},\\n\\n[paragraph 1]\\n\\n[paragraph 2]\\n\\nBest,\\nMax Hopkins\\nBTR Insurance Specialist\\nmax@btrinsurance.com"}}

QUALITY CHECKS before finalizing:
- Word count <= 170
- One question mark total
- One CTA only
- No forbidden phrases
- No unverified claims"""

        print(f"Email gen: generating for {prospect.get('company')} / {full_name}")

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        email_text = message.content[0].text if message.content else ""
        print(f"Email gen raw response: {email_text[:200]}")

        # Try to parse JSON response
        try:
            # Strip any markdown code fences
            cleaned = email_text.strip()
            if cleaned.startswith('```'):
                # Remove opening fence (with optional language tag)
                first_newline = cleaned.find('\n')
                if first_newline != -1:
                    cleaned = cleaned[first_newline + 1:]
                else:
                    cleaned = cleaned[3:]
                # Remove closing fence
                if cleaned.rstrip().endswith('```'):
                    cleaned = cleaned.rstrip()[:-3]
                cleaned = cleaned.strip()

            email_json = json.loads(cleaned)
            subject = email_json.get('subject', '')
            body = email_json.get('body', '')

            print(f"Email gen success: subject='{subject[:50]}', body length={len(body)}")

            return jsonify({
                'success': True,
                'subject': subject,
                'body': body,
                'email': f"Subject: {subject}\n\n{body}" if subject else body
            })
        except (json.JSONDecodeError, ValueError) as parse_err:
            print(f"Email gen JSON parse failed: {parse_err}, returning raw text")
            # Fallback: try to extract subject line from raw text
            subject = ''
            body = email_text
            lines = email_text.strip().split('\n')
            for i, line in enumerate(lines):
                if line.upper().startswith('SUBJECT:'):
                    subject = line.split(':', 1)[1].strip()
                    body = '\n'.join(lines[i+1:]).strip()
                    break

            return jsonify({
                'success': True,
                'subject': subject,
                'body': body,
                'email': email_text
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e),
            'email': ''
        }), 500

# --- Daily Discovery API Routes ---

@app.route('/api/discovery/config', methods=['GET'])
def api_discovery_config():
    """Get current discovery configuration"""
    return jsonify({'success': True, 'config': DISCOVERY_CONFIG})


@app.route('/api/discovery/config', methods=['PUT'])
def api_update_discovery_config():
    """Update discovery configuration (runtime only)"""
    data = request.json
    if 'min_rating' in data:
        DISCOVERY_CONFIG['min_rating'] = float(data['min_rating'])
    if 'min_reviews' in data:
        DISCOVERY_CONFIG['min_reviews'] = int(data['min_reviews'])
    if 'top_n_per_city' in data:
        DISCOVERY_CONFIG['top_n_per_city'] = int(data['top_n_per_city'])
    if 'icp_keywords' in data:
        DISCOVERY_CONFIG['icp_keywords'] = data['icp_keywords']
    if 'delivery_method' in data:
        DISCOVERY_CONFIG['delivery_method'] = data['delivery_method']
    if 'webhook_url' in data:
        DISCOVERY_CONFIG['webhook_url'] = data['webhook_url']
    return jsonify({'success': True, 'config': DISCOVERY_CONFIG})


@app.route('/api/discovery/latest', methods=['GET'])
def api_discovery_latest():
    """Get the most recent discovery run"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT * FROM discovery_runs ORDER BY run_at DESC LIMIT 1')
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': True, 'run': None, 'message': 'No discovery runs yet.'})
    return jsonify({
        'success': True,
        'run': {
            'id': row[0], 'run_at': row[1],
            'results': json.loads(row[2]) if row[2] else {},
            'digest': row[3], 'city_count': row[4],
            'total_new': row[5], 'status': row[6]
        }
    })


@app.route('/api/discovery/run', methods=['POST'])
def api_discovery_run():
    """Manually trigger a discovery run (background thread)"""
    global _discovery_running
    if _discovery_running:
        return jsonify({'success': False, 'message': 'A discovery run is already in progress.'})

    _discovery_running = True

    def run_bg():
        global _discovery_running
        try:
            run_daily_discovery()
        except Exception as e:
            print(f"[Discovery] Background run failed: {e}")
            traceback.print_exc()
        finally:
            _discovery_running = False

    thread = threading.Thread(target=run_bg, daemon=True)
    thread.start()
    return jsonify({'success': True, 'message': 'Discovery run started. Results will appear shortly.'})


@app.route('/api/discovery/status', methods=['GET'])
def api_discovery_status():
    """Check if a discovery run is currently in progress"""
    return jsonify({'success': True, 'running': _discovery_running})


@app.route('/api/discovery/history', methods=['GET'])
def api_discovery_history():
    """Get past discovery run summaries"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT id, run_at, city_count, total_new, status FROM discovery_runs ORDER BY run_at DESC LIMIT 20')
    runs = []
    for row in c.fetchall():
        runs.append({
            'id': row[0], 'run_at': row[1],
            'city_count': row[2], 'total_new': row[3], 'status': row[4]
        })
    conn.close()
    return jsonify({'success': True, 'runs': runs})


@app.route('/api/discovery/run/<int:run_id>', methods=['GET'])
def api_discovery_run_detail(run_id):
    """Get full results for a specific discovery run"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT * FROM discovery_runs WHERE id = ?', (run_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'message': 'Run not found'}), 404
    return jsonify({
        'success': True,
        'run': {
            'id': row[0], 'run_at': row[1],
            'results': json.loads(row[2]) if row[2] else {},
            'digest': row[3], 'city_count': row[4],
            'total_new': row[5], 'status': row[6]
        }
    })


# --- Scheduler Setup ---
_scheduler = BackgroundScheduler(daemon=True)
_scheduler.add_job(
    run_daily_discovery,
    CronTrigger(
        hour=DISCOVERY_CONFIG['schedule_hour'],
        minute=DISCOVERY_CONFIG['schedule_minute'],
        timezone=pytz.timezone(DISCOVERY_CONFIG['timezone'])
    ),
    id='daily_discovery',
    name='Daily BTR Discovery',
    replace_existing=True
)
_scheduler.start()
print(f"[Scheduler] Daily discovery scheduled for {DISCOVERY_CONFIG['schedule_hour']}:{DISCOVERY_CONFIG['schedule_minute']:02d} AM {DISCOVERY_CONFIG['timezone']}")


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

