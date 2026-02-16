"""
BTR Prospecting System - Backend Server
Flask API with Claude AI integration for automated prospect discovery
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import json
import time
import anthropic
from dotenv import load_dotenv
import sqlite3
import re

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

        return jsonify({
            'success': True,
            'message': f'Found {len(prospects)} prospects, saved {saved_count} new ones',
            'prospects': prospects,
            'savedCount': saved_count
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

@app.route('/api/email/generate', methods=['POST'])
def api_generate_email():
    """Generate personalized email for a prospect"""
    try:
        data = request.json
        prospect = data.get('prospect')
        
        # Use Claude to generate personalized email
        prompt = f"""Generate a personalized cold email for this BTR prospect:

Company: {prospect.get('company')}
Executive: {prospect.get('executive')}
Title: {prospect.get('title')}
Project: {prospect.get('projectName')}
Status: {prospect.get('projectStatus')}
Signals: {', '.join(prospect.get('signals', []))}
Why Now: {prospect.get('whyNow')}

Write a concise, professional email that:
1. References their specific project/recent activity
2. Highlights why NOW is the time to talk about insurance
3. Focuses on protecting NOI and exit valuations (not just buildings)
4. Includes a clear call-to-action
5. Is 150 words or less

Format:
SUBJECT: [subject line]

[email body]

Best,
Max Hopkins
BTR Insurance Specialist"""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        email_text = message.content[0].text if message.content else ""
        
        return jsonify({
            'success': True,
            'email': email_text
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e),
            'email': ''
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

