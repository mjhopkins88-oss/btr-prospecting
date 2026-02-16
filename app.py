"""
BTR Prospecting System - Backend Server
Flask API with Claude AI integration for automated prospect discovery
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime
import json
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
    Use Claude API to search for BTR prospects
    """
    try:
        # Construct search prompt
        search_prompt = f"""You are a real estate intelligence researcher. Search for Build-to-Rent (BTR) / Single-Family Rental (SFR) developers in {city}.

Find companies that are:
1. Actively developing BTR/SFR communities
2. Have recent news (capital raises, acquisitions, new projects, construction starts)
3. Are expansion-focused or institutional-backed

For each prospect, extract:
- Company name
- CEO/key executive name
- LinkedIn profile (if findable)
- City location
- Recent project details
- Active signals (financing, construction, sales, expansion)
- Total Investment Value estimate

Search for {limit} prospects and return ONLY valid JSON in this exact format:

{{
  "prospects": [
    {{
      "company": "Company Name",
      "executive": "Executive Name",
      "title": "CEO",
      "linkedin": "linkedin.com/in/profile",
      "city": "City",
      "state": "TX",
      "score": 85-95,
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

        # Call Claude API with web search tool
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            tools=[
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": 5
                }
            ],
            messages=[
                {
                    "role": "user",
                    "content": search_prompt
                }
            ]
        )

        # Extract response
        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        # Parse JSON from response
        # Try to find JSON in the response
        json_match = re.search(r'\{[\s\S]*"prospects"[\s\S]*\}', response_text)
        if json_match:
            json_str = json_match.group(0)
            data = json.loads(json_str)
            return data.get('prospects', [])
        else:
            print("No JSON found in response:", response_text)
            return []

    except Exception as e:
        print(f"Search error: {str(e)}")
        return []

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

@app.route('/health')
def health():
    """Simple health check for Railway"""
    return jsonify({'status': 'ok'}), 200

@app.route('/api/health')
def api_health():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'api_key_configured': bool(os.getenv('ANTHROPIC_API_KEY'))
    }), 200

@app.route('/api/search', methods=['POST'])
def api_search():
    """Search for new BTR prospects"""
    try:
        data = request.json
        city = data.get('city', 'Texas')
        limit = data.get('limit', 10)
        
        print(f"Searching for {limit} prospects in {city}...")
        
        # Search using Claude API
        prospects = search_btr_prospects(city, limit)
        
        if not prospects:
            return jsonify({
                'success': False,
                'message': 'No prospects found. Please try again or try a different location.',
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

