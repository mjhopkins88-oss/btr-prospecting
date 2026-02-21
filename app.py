"""
BTR Prospecting System - Backend Server
Flask API with Claude AI integration for automated prospect discovery
"""

from flask import Flask, request, jsonify, send_from_directory, send_file, g, make_response
from flask_cors import CORS
from functools import wraps
import os
import secrets
import hashlib
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
import uuid
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz
import bcrypt

# Load environment variables
load_dotenv()

SESSION_SECRET = os.getenv('SESSION_SECRET', secrets.token_hex(32))
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
SESSION_DURATION_HOURS = 720  # 30 days

app = Flask(__name__, static_folder='static')
CORS(app, supports_credentials=True)

# --- Login rate limiter (in-memory) ---
_login_attempts = {}  # email -> { count, locked_until }
_LOGIN_MAX_ATTEMPTS = 10
_LOGIN_LOCKOUT_MINUTES = 10

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
    'monitor_operators': [
        'Invitation Homes',
        'American Homes 4 Rent',
        'Tricon Residential',
        'Progress Residential',
    ],
    'max_signals_per_day': 10,
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
            status TEXT DEFAULT 'completed',
            adapter_stats TEXT
        )
    ''')
    # Add adapter_stats column if missing (migration for existing DBs)
    try:
        c.execute("SELECT adapter_stats FROM discovery_runs LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE discovery_runs ADD COLUMN adapter_stats TEXT")
    c.execute('''
        CREATE TABLE IF NOT EXISTS prospecting_runs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            search_params TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            total_prospects INTEGER DEFAULT 0,
            error TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS run_prospects (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES prospecting_runs(id),
            company_name TEXT NOT NULL,
            city TEXT,
            state TEXT,
            score INTEGER DEFAULT 0,
            tiv_estimate TEXT,
            deal_status TEXT,
            signals TEXT,
            why_call_now TEXT,
            executive TEXT,
            title TEXT,
            linkedin TEXT,
            units TEXT,
            project_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            score_meta TEXT
        )
    ''')
    # Add score_meta column if missing (migration for existing DBs)
    try:
        c.execute("SELECT score_meta FROM run_prospects LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE run_prospects ADD COLUMN score_meta TEXT")
    c.execute('CREATE INDEX IF NOT EXISTS idx_run_prospects_score ON run_prospects(run_id, score DESC)')
    c.execute('''
        CREATE TABLE IF NOT EXISTS discovery_signal_seen (
            fingerprint TEXT PRIMARY KEY,
            first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS search_cache (
            cache_key TEXT PRIMARY KEY,
            created_at TIMESTAMP,
            expires_at TIMESTAMP,
            payload_json TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS discovery_source_refresh (
            source_type TEXT PRIMARY KEY,
            last_refreshed_at TIMESTAMP,
            items_found INTEGER DEFAULT 0
        )
    ''')
    # --- Auth & CRM Tables ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS workspaces (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'producer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            session_token TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS crm_companies (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            prospect_key TEXT NOT NULL,
            company_name TEXT NOT NULL,
            website TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(workspace_id, prospect_key)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS crm_leads (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            company_id TEXT NOT NULL REFERENCES crm_companies(id),
            owner_user_id TEXT REFERENCES users(id),
            status TEXT NOT NULL DEFAULT 'New',
            last_touch_at TIMESTAMP,
            next_followup_at TIMESTAMP,
            priority INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS crm_touchpoints (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            lead_id TEXT NOT NULL REFERENCES crm_leads(id),
            user_id TEXT NOT NULL REFERENCES users(id),
            type TEXT NOT NULL,
            outcome TEXT,
            notes TEXT,
            occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            next_followup_at TIMESTAMP
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_crm_leads_owner ON crm_leads(workspace_id, owner_user_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_crm_leads_followup ON crm_leads(workspace_id, next_followup_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_crm_companies_key ON crm_companies(workspace_id, prospect_key)')
    # --- Trend Detection & Weekly Briefs Tables ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS trend_signals (
            id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            city TEXT NOT NULL,
            topic TEXT NOT NULL,
            count_7d INTEGER NOT NULL,
            count_30d INTEGER NOT NULL,
            trend_ratio REAL NOT NULL,
            classification TEXT NOT NULL,
            computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(state, city, topic, computed_at)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_trend_signals_date ON trend_signals(computed_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_trend_signals_state ON trend_signals(state, computed_at)')
    c.execute('''
        CREATE TABLE IF NOT EXISTS weekly_briefs (
            id TEXT PRIMARY KEY,
            brief_json TEXT NOT NULL,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            week_start TEXT NOT NULL,
            week_end TEXT NOT NULL
        )
    ''')
    # --- Weighted Signals (materialized from discovery_runs + search_cache) ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS weighted_signals (
            id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            city TEXT NOT NULL,
            topic TEXT NOT NULL,
            signal_weight INTEGER NOT NULL DEFAULT 1,
            entity_name TEXT,
            title TEXT,
            summary TEXT,
            source TEXT,
            source_type TEXT,
            confidence TEXT,
            published_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_weighted_signals_state ON weighted_signals(state, city)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_weighted_signals_date ON weighted_signals(published_at)')
    # --- Market Momentum ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS market_momentum (
            id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            city TEXT NOT NULL,
            window_end_date TEXT NOT NULL,
            signals_7d INTEGER DEFAULT 0,
            signals_14d INTEGER DEFAULT 0,
            signals_30d INTEGER DEFAULT 0,
            weighted_signals_7d INTEGER DEFAULT 0,
            weighted_signals_14d INTEGER DEFAULT 0,
            weighted_signals_30d INTEGER DEFAULT 0,
            momentum_score REAL DEFAULT 0,
            momentum_label TEXT DEFAULT 'Stable',
            computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(state, city, window_end_date)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_market_momentum_state ON market_momentum(state, city, window_end_date)')
    # --- Lead Timing Scores ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS lead_timing_scores (
            id TEXT PRIMARY KEY,
            workspace_id TEXT,
            prospect_key TEXT NOT NULL,
            company_name TEXT NOT NULL,
            state TEXT,
            city TEXT,
            trigger_severity INTEGER DEFAULT 0,
            swim_lane_fit INTEGER,
            engagement_score INTEGER,
            market_momentum_score REAL DEFAULT 50,
            freshness_score INTEGER DEFAULT 30,
            call_timing_score REAL DEFAULT 0,
            timing_label TEXT DEFAULT 'Watch',
            reasons TEXT,
            computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(workspace_id, prospect_key)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_lead_timing_key ON lead_timing_scores(workspace_id, prospect_key)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_lead_timing_score ON lead_timing_scores(call_timing_score DESC)')
    conn.commit()
    conn.close()

init_db()


# ===================================================================
# AUTH HELPERS & MIDDLEWARE
# ===================================================================

def _hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def _check_password(password, password_hash):
    """Verify a password against its bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def _get_session_user(conn=None):
    """Look up the current user from the session cookie. Returns (user_dict, workspace_id) or (None, None)."""
    token = request.cookies.get('session_token')
    if not token:
        return None, None
    close_conn = False
    if conn is None:
        conn = sqlite3.connect('prospects.db')
        close_conn = True
    c = conn.cursor()
    c.execute('''
        SELECT s.id, s.user_id, s.expires_at, u.id, u.workspace_id, u.name, u.email, u.role
        FROM sessions s JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND s.expires_at > ?
    ''', (token, datetime.utcnow().isoformat()))
    row = c.fetchone()
    if not row:
        if close_conn:
            conn.close()
        return None, None
    # Update last_seen_at
    c.execute('UPDATE sessions SET last_seen_at = ? WHERE id = ?', (datetime.utcnow().isoformat(), row[0]))
    conn.commit()
    user = {
        'id': row[3],
        'workspace_id': row[4],
        'name': row[5],
        'email': row[6],
        'role': row[7],
    }
    if close_conn:
        conn.close()
    return user, row[4]

def _has_users():
    """Check if any users exist in the database."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    count = c.fetchone()[0]
    conn.close()
    return count > 0

def require_auth(f):
    """Decorator: require a valid session. Sets g.user and g.workspace_id."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # If no users exist yet, allow unauthenticated access (bootstrap mode)
        if not _has_users():
            g.user = None
            g.workspace_id = None
            return f(*args, **kwargs)
        user, workspace_id = _get_session_user()
        if not user:
            return jsonify({'success': False, 'message': 'Authentication required', 'auth_required': True}), 401
        g.user = user
        g.workspace_id = workspace_id
        return f(*args, **kwargs)
    return decorated

def require_role(role):
    """Decorator: require a specific role (must be used after require_auth)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.user and g.user.get('role') != role:
                return jsonify({'success': False, 'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def _check_login_rate(email):
    """Returns True if login is allowed, False if locked out."""
    info = _login_attempts.get(email)
    if not info:
        return True
    if info.get('locked_until') and datetime.utcnow() < info['locked_until']:
        return False
    if info.get('locked_until') and datetime.utcnow() >= info['locked_until']:
        # Lockout expired, reset
        _login_attempts.pop(email, None)
        return True
    return True

def _record_login_failure(email):
    """Record a failed login attempt."""
    info = _login_attempts.get(email, {'count': 0})
    info['count'] = info.get('count', 0) + 1
    if info['count'] >= _LOGIN_MAX_ATTEMPTS:
        info['locked_until'] = datetime.utcnow() + timedelta(minutes=_LOGIN_LOCKOUT_MINUTES)
    _login_attempts[email] = info

def _clear_login_failures(email):
    """Clear login failure count on success."""
    _login_attempts.pop(email, None)

def _make_prospect_key(company_name, website=None, city=None, state=None):
    """Generate a stable prospect_key for CRM matching."""
    norm_company = re.sub(r'[^a-z0-9]', '', (company_name or '').lower())
    if website:
        norm_domain = re.sub(r'^https?://(www\.)?', '', (website or '').lower()).rstrip('/')
        return f"{norm_company}|{norm_domain}"
    norm_city = re.sub(r'[^a-z0-9]', '', (city or '').lower())
    norm_state = re.sub(r'[^a-z0-9]', '', (state or '').lower())
    return f"{norm_company}|{norm_city}|{norm_state}"


# ===================================================================
# AUTH API ROUTES
# ===================================================================

def _cleanup_expired_sessions():
    """Remove expired sessions to prevent DB bloat. Called during login."""
    try:
        conn = sqlite3.connect('prospects.db')
        c = conn.cursor()
        c.execute('DELETE FROM sessions WHERE expires_at < ?', (datetime.utcnow().isoformat(),))
        conn.commit()
        conn.close()
    except Exception:
        pass

@app.route('/api/auth/bootstrap', methods=['POST'])
def api_auth_bootstrap():
    """Create the first admin user + workspace. Only works if zero users exist."""
    if _has_users():
        return jsonify({'success': False, 'message': 'Bootstrap not available. Users already exist.'}), 403
    data = request.json or {}
    workspace_name = data.get('workspace_name', '').strip()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not workspace_name or not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required: workspace_name, name, email, password'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    workspace_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password_hash = _hash_password(password)

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO workspaces (id, name) VALUES (?, ?)', (workspace_id, workspace_name))
        c.execute('INSERT INTO users (id, workspace_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)',
                  (user_id, workspace_id, name, email, password_hash, 'admin'))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    # Auto-login: create session
    session_token = secrets.token_urlsafe(48)
    session_id = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)).isoformat()
    c.execute('INSERT INTO sessions (id, user_id, session_token, expires_at) VALUES (?, ?, ?, ?)',
              (session_id, user_id, session_token, expires_at))
    conn.commit()
    conn.close()

    resp = make_response(jsonify({
        'success': True,
        'user': {'id': user_id, 'name': name, 'email': email, 'role': 'admin', 'workspace_id': workspace_id}
    }))
    resp.set_cookie('session_token', session_token, httponly=True, samesite='Lax',
                    secure=COOKIE_SECURE, path='/', max_age=SESSION_DURATION_HOURS * 3600)
    return resp


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    """Login with email + password."""
    _cleanup_expired_sessions()
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    # Rate limit check
    if not _check_login_rate(email):
        return jsonify({'success': False, 'message': 'Too many login attempts. Try again in 10 minutes.'}), 429

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT id, workspace_id, name, email, password_hash, role FROM users WHERE email = ?', (email,))
    row = c.fetchone()

    if not row or not _check_password(password, row[4]):
        conn.close()
        _record_login_failure(email)
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

    _clear_login_failures(email)
    user_id, workspace_id, name, user_email, _, role = row

    # Create session
    session_token = secrets.token_urlsafe(48)
    session_id = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)).isoformat()
    c.execute('INSERT INTO sessions (id, user_id, session_token, expires_at) VALUES (?, ?, ?, ?)',
              (session_id, user_id, session_token, expires_at))
    conn.commit()
    conn.close()

    resp = make_response(jsonify({
        'success': True,
        'user': {'id': user_id, 'name': name, 'email': user_email, 'role': role, 'workspace_id': workspace_id}
    }))
    resp.set_cookie('session_token', session_token, httponly=True, samesite='Lax',
                    secure=COOKIE_SECURE, path='/', max_age=SESSION_DURATION_HOURS * 3600)
    return resp


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    """Logout: invalidate session."""
    token = request.cookies.get('session_token')
    if token:
        conn = sqlite3.connect('prospects.db')
        c = conn.cursor()
        c.execute('DELETE FROM sessions WHERE session_token = ?', (token,))
        conn.commit()
        conn.close()
    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie('session_token', path='/')
    return resp


@app.route('/api/auth/me', methods=['GET'])
def api_auth_me():
    """Get current authenticated user."""
    has_users = _has_users()
    if not has_users:
        return jsonify({'success': True, 'user': None, 'needs_bootstrap': True})
    user, workspace_id = _get_session_user()
    if not user:
        return jsonify({'success': False, 'user': None, 'auth_required': True}), 401
    return jsonify({'success': True, 'user': user})


@app.route('/api/auth/has-users', methods=['GET'])
def api_auth_has_users():
    """Check if any users exist (determines bootstrap vs login)."""
    return jsonify({'has_users': _has_users()})


@app.route('/api/auth/users', methods=['GET'])
@require_auth
@require_role('admin')
def api_auth_list_users():
    """Admin: list all users in workspace."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT id, name, email, role, created_at FROM users WHERE workspace_id = ?', (g.workspace_id,))
    users = [{'id': r[0], 'name': r[1], 'email': r[2], 'role': r[3], 'created_at': r[4]} for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'users': users})


@app.route('/api/auth/users', methods=['POST'])
@require_auth
@require_role('admin')
def api_auth_create_user():
    """Admin: create a new user in the workspace."""
    data = request.json or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'producer')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'name, email, and password are required'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    if role not in ('admin', 'producer'):
        return jsonify({'success': False, 'message': 'Role must be admin or producer'}), 400

    user_id = str(uuid.uuid4())
    password_hash = _hash_password(password)

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (id, workspace_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)',
                  (user_id, g.workspace_id, name, email, password_hash, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Email already exists'}), 400
    conn.close()
    return jsonify({'success': True, 'user': {'id': user_id, 'name': name, 'email': email, 'role': role}})


# ===================================================================
# CRM API ROUTES
# ===================================================================

@app.route('/api/crm/lead/upsert', methods=['POST'])
@require_auth
def api_crm_upsert_lead():
    """Create or find a CRM lead by prospect_key."""
    if not g.user:
        return jsonify({'success': False, 'message': 'Auth required for CRM'}), 401
    data = request.json or {}
    prospect_key = data.get('prospect_key', '').strip()
    company_name = data.get('company_name', '').strip()
    website = data.get('website', '').strip() or None

    if not prospect_key or not company_name:
        return jsonify({'success': False, 'message': 'prospect_key and company_name are required'}), 400

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    ws = g.workspace_id

    # Find or create crm_company
    c.execute('SELECT id FROM crm_companies WHERE workspace_id = ? AND prospect_key = ?', (ws, prospect_key))
    row = c.fetchone()
    if row:
        company_id = row[0]
    else:
        company_id = str(uuid.uuid4())
        c.execute('INSERT INTO crm_companies (id, workspace_id, prospect_key, company_name, website) VALUES (?, ?, ?, ?, ?)',
                  (company_id, ws, prospect_key, company_name, website))

    # Find or create crm_lead
    c.execute('SELECT id, status, owner_user_id, next_followup_at, priority FROM crm_leads WHERE workspace_id = ? AND company_id = ?', (ws, company_id))
    lead_row = c.fetchone()
    if lead_row:
        lead = {
            'id': lead_row[0], 'status': lead_row[1], 'owner_user_id': lead_row[2],
            'next_followup_at': lead_row[3], 'priority': lead_row[4], 'company_id': company_id,
            'company_name': company_name, 'prospect_key': prospect_key,
        }
    else:
        lead_id = str(uuid.uuid4())
        c.execute('INSERT INTO crm_leads (id, workspace_id, company_id, status) VALUES (?, ?, ?, ?)',
                  (lead_id, ws, company_id, 'New'))
        lead = {
            'id': lead_id, 'status': 'New', 'owner_user_id': None,
            'next_followup_at': None, 'priority': None, 'company_id': company_id,
            'company_name': company_name, 'prospect_key': prospect_key,
        }

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'lead': lead})


@app.route('/api/crm/leads', methods=['GET'])
@require_auth
def api_crm_list_leads():
    """List CRM leads with optional filters: owner=me, status=, due=1"""
    if not g.user:
        return jsonify({'success': True, 'leads': []})
    ws = g.workspace_id
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()

    query = '''
        SELECT l.id, l.status, l.owner_user_id, l.last_touch_at, l.next_followup_at, l.priority, l.created_at,
               co.company_name, co.prospect_key, co.website,
               u.name as owner_name
        FROM crm_leads l
        JOIN crm_companies co ON l.company_id = co.id
        LEFT JOIN users u ON l.owner_user_id = u.id
        WHERE l.workspace_id = ?
    '''
    params = [ws]

    owner = request.args.get('owner')
    if owner == 'me':
        query += ' AND l.owner_user_id = ?'
        params.append(g.user['id'])
    elif owner == 'unassigned':
        query += ' AND l.owner_user_id IS NULL'

    status = request.args.get('status')
    if status:
        query += ' AND l.status = ?'
        params.append(status)

    due = request.args.get('due')
    if due == '1':
        query += ' AND l.next_followup_at IS NOT NULL AND l.next_followup_at <= ?'
        params.append(datetime.utcnow().isoformat())

    query += ' ORDER BY CASE WHEN l.next_followup_at IS NOT NULL THEN 0 ELSE 1 END, l.next_followup_at ASC, l.created_at DESC'

    c.execute(query, params)
    leads = []
    for r in c.fetchall():
        leads.append({
            'id': r[0], 'status': r[1], 'owner_user_id': r[2],
            'last_touch_at': r[3], 'next_followup_at': r[4], 'priority': r[5],
            'created_at': r[6], 'company_name': r[7], 'prospect_key': r[8],
            'website': r[9], 'owner_name': r[10],
        })
    conn.close()
    return jsonify({'success': True, 'leads': leads})


@app.route('/api/crm/leads/<lead_id>', methods=['PATCH'])
@require_auth
def api_crm_update_lead(lead_id):
    """Update a CRM lead (status, owner, followup, priority)."""
    if not g.user:
        return jsonify({'success': False, 'message': 'Auth required'}), 401
    data = request.json or {}
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()

    # Verify lead belongs to workspace
    c.execute('SELECT id, owner_user_id FROM crm_leads WHERE id = ? AND workspace_id = ?', (lead_id, g.workspace_id))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'message': 'Lead not found'}), 404

    # Producers can only update their own leads; admins can update any
    if g.user['role'] != 'admin' and row[1] and row[1] != g.user['id']:
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot update another user\'s lead'}), 403

    updates = []
    params = []
    for field in ('status', 'owner_user_id', 'next_followup_at', 'priority'):
        if field in data:
            updates.append(f'{field} = ?')
            params.append(data[field])

    if updates:
        params.append(lead_id)
        c.execute(f'UPDATE crm_leads SET {", ".join(updates)} WHERE id = ?', params)
        conn.commit()

    conn.close()
    return jsonify({'success': True})


@app.route('/api/crm/leads/<lead_id>/touchpoints', methods=['POST'])
@require_auth
def api_crm_add_touchpoint(lead_id):
    """Log a CRM touchpoint."""
    if not g.user:
        return jsonify({'success': False, 'message': 'Auth required'}), 401
    data = request.json or {}
    touch_type = data.get('type', '').strip()
    if not touch_type:
        return jsonify({'success': False, 'message': 'type is required'}), 400

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()

    # Verify lead belongs to workspace
    c.execute('SELECT id FROM crm_leads WHERE id = ? AND workspace_id = ?', (lead_id, g.workspace_id))
    if not c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Lead not found'}), 404

    tp_id = str(uuid.uuid4())
    occurred_at = data.get('occurred_at', datetime.utcnow().isoformat())
    next_followup = data.get('next_followup_at')

    c.execute('''
        INSERT INTO crm_touchpoints (id, workspace_id, lead_id, user_id, type, outcome, notes, occurred_at, next_followup_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (tp_id, g.workspace_id, lead_id, g.user['id'], touch_type,
          data.get('outcome'), data.get('notes'), occurred_at, next_followup))

    # Update lead timestamps
    update_parts = ['last_touch_at = ?']
    update_params = [occurred_at]
    if next_followup:
        update_parts.append('next_followup_at = ?')
        update_params.append(next_followup)
    update_params.append(lead_id)
    c.execute(f'UPDATE crm_leads SET {", ".join(update_parts)} WHERE id = ?', update_params)

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'touchpoint_id': tp_id})


@app.route('/api/crm/leads/<lead_id>/touchpoints', methods=['GET'])
@require_auth
def api_crm_list_touchpoints(lead_id):
    """Get all touchpoints for a lead."""
    if not g.user:
        return jsonify({'success': True, 'touchpoints': []})
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()

    c.execute('''
        SELECT tp.id, tp.type, tp.outcome, tp.notes, tp.occurred_at, tp.next_followup_at, u.name
        FROM crm_touchpoints tp
        JOIN users u ON tp.user_id = u.id
        WHERE tp.lead_id = ? AND tp.workspace_id = ?
        ORDER BY tp.occurred_at DESC
    ''', (lead_id, g.workspace_id))

    touchpoints = []
    for r in c.fetchall():
        touchpoints.append({
            'id': r[0], 'type': r[1], 'outcome': r[2], 'notes': r[3],
            'occurred_at': r[4], 'next_followup_at': r[5], 'user_name': r[6],
        })
    conn.close()
    return jsonify({'success': True, 'touchpoints': touchpoints})


@app.route('/api/crm/leads/bulk-status', methods=['GET'])
@require_auth
def api_crm_bulk_status():
    """Get CRM status for multiple prospect_keys at once (for card overlays)."""
    if not g.user:
        return jsonify({'success': True, 'statuses': {}})
    keys_param = request.args.get('keys', '')
    if not keys_param:
        return jsonify({'success': True, 'statuses': {}})
    keys = [k.strip() for k in keys_param.split(',') if k.strip()]
    if not keys:
        return jsonify({'success': True, 'statuses': {}})

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    placeholders = ','.join('?' * len(keys))
    c.execute(f'''
        SELECT co.prospect_key, l.id, l.status, l.owner_user_id, l.next_followup_at, u.name as owner_name
        FROM crm_leads l
        JOIN crm_companies co ON l.company_id = co.id
        LEFT JOIN users u ON l.owner_user_id = u.id
        WHERE l.workspace_id = ? AND co.prospect_key IN ({placeholders})
    ''', [g.workspace_id] + keys)

    statuses = {}
    for r in c.fetchall():
        statuses[r[0]] = {
            'lead_id': r[1], 'status': r[2], 'owner_user_id': r[3],
            'next_followup_at': r[4], 'owner_name': r[5],
        }
    conn.close()
    return jsonify({'success': True, 'statuses': statuses})


def search_btr_prospects(city="Texas", limit=10):
    """
    Use SerpAPI (Stage A) + Claude extraction (Stage B) to find BTR prospects.
    Returns (prospects_list, error_message) tuple.
    """
    from serpapi_client import cached_serpapi_search, SerpAPIError

    # Check API keys first
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key or api_key == 'your_anthropic_api_key_here':
        return [], "ANTHROPIC_API_KEY is not set. Add it to your .env file or Railway environment variables."

    serp_key = os.getenv('SERPAPI_API_KEY')
    use_serpapi = bool(serp_key)

    # Check in-memory cache first
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
        existing = get_existing_companies(city)
        exclude_clause = ""
        if existing:
            names = ", ".join(existing[:20])
            exclude_clause = f"\n\nIMPORTANT: I already have these companies in my database, so DO NOT include them. Find DIFFERENT companies:\n{names}\n"

        today = datetime.now().strftime('%B %d, %Y')
        ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime('%B %Y')
        ask_count = min(limit, 10)

        if use_serpapi:
            # --- Path A: SerpAPI candidate retrieval + Claude extraction ---
            from serpapi_client import cached_serpapi_search, SerpAPIError

            queries = [
                f'site:bisnow.com ("build to rent" OR BTR) "{city}"',
                f'site:multihousingnews.com ("build to rent" OR BTR) "{city}"',
                f'site:bizjournals.com ("build to rent" OR BTR) "{city}"',
                f'("build to rent" OR "single family rental community") "{city}" (acquires OR acquisition OR sells OR sale OR groundbreaking OR "under construction")',
            ]

            all_candidates = []
            seen_links = set()

            print(f"Fetching SerpAPI candidates for {city}...")

            for query in queries:
                try:
                    results = cached_serpapi_search(
                        query, num=5, feature='prospect', city=city, state=''
                    )
                    for r in results:
                        link = r.get('link', '')
                        if link and link not in seen_links:
                            seen_links.add(link)
                            all_candidates.append(r)
                except SerpAPIError as e:
                    return [], f"Search temporarily rate limited: {e}"
                except Exception as e:
                    print(f"SerpAPI query error: {e}")

                if len(all_candidates) >= 20:
                    break

            if not all_candidates:
                return [], "No search results found for this area. Try a different city or state."

            print(f"SerpAPI returned {len(all_candidates)} candidates for {city}")

            candidates_json = json.dumps([{
                'title': c['title'],
                'url': c['link'],
                'snippet': c.get('snippet', ''),
                'source': c.get('source', ''),
                'date': c.get('date', ''),
            } for c in all_candidates[:20]], indent=2)

            extraction_prompt = f"""You are a real estate intelligence researcher. Today's date is {today}.

I have search results about Build-to-Rent (BTR) / Single-Family Rental (SFR) activity in {city}.
Analyze these search results and extract BTR developer prospects.

SEARCH RESULTS:
{candidates_json}

FOCUS ON RECENT ACTIVITY from the last 90 days (since {ninety_days_ago}). Look for groundbreakings, land acquisitions, construction starts, capital raises, new projects.
{exclude_clause}
Find up to {ask_count} companies. For each extract:
- Company name
- CEO/key executive name (if mentioned)
- LinkedIn profile (if mentioned)
- City location
- Recent project details (include dates when available)
- Active signals (financing, construction, sales, expansion)
- Total Investment Value estimate (if mentioned)
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
- unit_band: classify the operator's typical project size as one of: "<40", "40-150", "150-400", "400-1000", "1000+"
- active_project_count_estimate: estimated number of active projects (integer, best guess from context)
- markets_active_estimate: estimated number of metros/markets they operate in (integer, best guess)
- swim_lane_fit_score (0-100): Start at 50, then apply modifiers:
  +25 if unit_band "40-150", +20 if "150-400", -15 if "<40", -10 if "400-1000", -25 if "1000+"
  +15 if active_project_count 2-5, +5 if 1, -10 if >10
  +10 if markets_active 2-4, +5 if 1, -5 if 5+
  Clamp result to 0-100
- competitive_difficulty: "Low" (niche/emerging operator), "Medium" (established regional), "High" (national/institutional)

Return ONLY valid JSON in this exact format:

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
      "unit_band": "40-150",
      "active_project_count_estimate": 3,
      "markets_active_estimate": 2,
      "swim_lane_fit_score": 85,
      "competitive_difficulty": "Low",
      "tiv": "$50M-200M",
      "units": "200-500 units",
      "projectName": "Project Name",
      "projectStatus": "Under construction / Pre-leasing / Recently opened",
      "signals": ["Signal 1", "Signal 2", "Signal 3"],
      "whyNow": "Why call this prospect now"
    }}
  ]
}}

CRITICAL: Return ONLY the JSON object, no other text. Only include companies clearly related to BTR/SFR development."""

            print(f"Calling Claude API for {city} extraction...")

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                messages=[{"role": "user", "content": extraction_prompt}]
            )

        else:
            # --- Path B: Claude web_search fallback (no SerpAPI key) ---
            print(f"No SERPAPI_API_KEY set, using Claude web_search for {city}...")

            search_prompt = f"""You are a real estate intelligence researcher. Today's date is {today}.

Search for Build-to-Rent (BTR) and Single-Family Rental (SFR) development activity in {city}.

Search for recent news about:
- BTR groundbreakings, land acquisitions, construction starts in {city}
- Single family rental community developments in {city}
- Build to rent developers active in {city}

FOCUS ON RECENT ACTIVITY from the last 90 days (since {ninety_days_ago}).
{exclude_clause}
Find up to {ask_count} companies actively developing BTR/SFR projects. For each extract:
- Company name
- CEO/key executive name (if mentioned)
- LinkedIn profile (if mentioned)
- City location
- Recent project details (include dates when available)
- Active signals (financing, construction, sales, expansion)
- Total Investment Value estimate (if mentioned)
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
- unit_band: classify the operator's typical project size as one of: "<40", "40-150", "150-400", "400-1000", "1000+"
- active_project_count_estimate: estimated number of active projects (integer, best guess from context)
- markets_active_estimate: estimated number of metros/markets they operate in (integer, best guess)
- swim_lane_fit_score (0-100): Start at 50, then apply modifiers:
  +25 if unit_band "40-150", +20 if "150-400", -15 if "<40", -10 if "400-1000", -25 if "1000+"
  +15 if active_project_count 2-5, +5 if 1, -10 if >10
  +10 if markets_active 2-4, +5 if 1, -5 if 5+
  Clamp result to 0-100
- competitive_difficulty: "Low" (niche/emerging operator), "Medium" (established regional), "High" (national/institutional)

Return ONLY valid JSON in this exact format:

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
      "unit_band": "40-150",
      "active_project_count_estimate": 3,
      "markets_active_estimate": 2,
      "swim_lane_fit_score": 85,
      "competitive_difficulty": "Low",
      "tiv": "$50M-200M",
      "units": "200-500 units",
      "projectName": "Project Name",
      "projectStatus": "Under construction / Pre-leasing / Recently opened",
      "signals": ["Signal 1", "Signal 2", "Signal 3"],
      "whyNow": "Why call this prospect now"
    }}
  ]
}}

CRITICAL: Return ONLY the JSON object, no other text. Only include companies clearly related to BTR/SFR development."""

            print(f"Calling Claude API with web_search for {city}...")

            max_retries = 3
            message = None
            for attempt in range(max_retries + 1):
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
                        messages=[
                            {
                                "role": "user",
                                "content": search_prompt
                            }
                        ]
                    )
                    break
                except anthropic.RateLimitError:
                    if attempt < max_retries:
                        wait_time = 2 ** (attempt + 1)
                        print(f"Rate limited (attempt {attempt + 1}/{max_retries + 1}), waiting {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        return [], "API rate limit reached after retries. Please wait 1-2 minutes and try again."

        response_text = ""
        for block in message.content:
            if block.type == "text":
                response_text += block.text

        print(f"Claude response length: {len(response_text)} chars")

        if not response_text.strip():
            return [], "Claude returned an empty response. Try again."

        # Parse JSON from response
        json_start = response_text.find('{"prospects"')
        if json_start == -1:
            json_start = response_text.find('{  "prospects"')
        if json_start == -1:
            json_start = response_text.find('{\n')

        if json_start != -1:
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
                    _search_cache[cache_key] = {
                        'prospects': prospects,
                        'timestamp': datetime.now()
                    }
                    return prospects, None
                else:
                    return [], "No BTR prospects found in search results. Try a different city or state."
            except json.JSONDecodeError as e:
                print(f"JSON parse error: {e}")
                return [], "Failed to parse AI response. Try searching again."
        else:
            print(f"No JSON found in response: {response_text[:500]}")
            return [], "AI response did not contain prospect data. Try searching again."

    except anthropic.AuthenticationError:
        return [], "Invalid ANTHROPIC_API_KEY. Check your API key in .env or Railway variables."
    except anthropic.APIConnectionError:
        return [], "Cannot connect to Claude API. Check your internet connection."
    except anthropic.RateLimitError:
        return [], "Claude API rate limit reached. Please wait 1-2 minutes and try again."
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

# Generate master CSV on startup (in background to avoid blocking)
threading.Thread(target=generate_master_csv, daemon=True).start()

# --- Daily Discovery Engine ---

def run_daily_discovery(is_scheduled=False):
    """Main daily discovery orchestrator — event signal scanner.
    Uses discovery_engine.py with adapter architecture to fetch from multiple sources."""
    global _discovery_running
    _discovery_running = True
    try:
        config = DISCOVERY_CONFIG
        from discovery_engine import run_discovery_job

        print(f"[Discovery] Starting signal scan at {datetime.now().isoformat()}")

        results, digest, total_new, adapter_stats = run_discovery_job(config, is_scheduled=is_scheduled)

        # Save run record
        conn = sqlite3.connect('prospects.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO discovery_runs (results_json, digest_text, city_count, total_new, status, adapter_stats)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            json.dumps(results),
            digest,
            len(config['cities']),
            total_new,
            'completed',
            json.dumps(adapter_stats)
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
                    'results': results,
                    'digest': digest,
                    'adapter_stats': adapter_stats
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

        print(f"[Discovery] Run complete. {total_new} new signals across {len(config['cities'])} cities.")
        return results, digest

    except Exception as e:
        print(f"[Discovery] Run failed: {e}")
        traceback.print_exc()
        return {}, ""
    finally:
        _discovery_running = False

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
@require_auth
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
@require_auth
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
@require_auth
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
@require_auth
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
@require_auth
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

# --- Async Prospecting Run Endpoints ---

@app.route('/api/prospecting/run', methods=['POST'])
@require_auth
def api_start_prospecting_run():
    """Start an async prospecting run. Returns immediately with a run_id."""
    try:
        data = request.json or {}
        raw_cities = data.get('cities', [])
        max_per_city = min(int(data.get('maxProspectsPerCity', 25)), 50)
        max_total = min(int(data.get('maxTotalProspects', 300)), 300)

        # Normalize cities: accept strings or {city, state} objects
        cities = []
        for c in raw_cities:
            if isinstance(c, str):
                cities.append({'city': c, 'state': ''})
            elif isinstance(c, dict):
                cities.append({'city': c.get('city', ''), 'state': c.get('state', '')})

        if not cities:
            return jsonify({'success': False, 'message': 'No cities provided.'}), 400

        run_id = str(uuid.uuid4())
        search_params = {
            'cities': cities,
            'maxProspectsPerCity': max_per_city,
            'maxTotalProspects': max_total,
        }

        # Create run record
        conn = sqlite3.connect('prospects.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO prospecting_runs (id, status, search_params, created_at, updated_at)
            VALUES (?, 'pending', ?, ?, ?)
        ''', (run_id, json.dumps(search_params),
              datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        # Enqueue background job
        from queue_config import enqueue
        from jobs import execute_prospecting_run
        enqueue(execute_prospecting_run, run_id, search_params, job_timeout=600)

        return jsonify({
            'success': True,
            'run_id': run_id,
            'status': 'pending'
        })

    except Exception as e:
        print(f"[Prospecting] Start error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/prospecting/run/<run_id>/status', methods=['GET'])
@require_auth
def api_prospecting_run_status(run_id):
    """Poll the status of a prospecting run."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT status, total_prospects, error, created_at, completed_at FROM prospecting_runs WHERE id = ?',
              (run_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({'success': False, 'message': 'Run not found'}), 404

    return jsonify({
        'success': True,
        'run_id': run_id,
        'status': row[0],
        'total_prospects': row[1] or 0,
        'error': row[2],
        'created_at': row[3],
        'completed_at': row[4],
    })


@app.route('/api/prospecting/run/<run_id>/results', methods=['GET'])
@require_auth
def api_prospecting_run_results(run_id):
    """Get results for a prospecting run, sorted by score DESC, with pagination."""
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()

    # Total count
    c.execute('SELECT COUNT(*) FROM run_prospects WHERE run_id = ?', (run_id,))
    total = c.fetchone()[0]

    # Fetch page
    c.execute('''
        SELECT id, company_name, city, state, score, tiv_estimate, deal_status,
               signals, why_call_now, executive, title, linkedin, units, project_name, created_at, score_meta
        FROM run_prospects
        WHERE run_id = ?
        ORDER BY score DESC
        LIMIT ? OFFSET ?
    ''', (run_id, limit, offset))

    prospects = []
    for row in c.fetchall():
        signals_raw = row[7]
        try:
            signals = json.loads(signals_raw) if signals_raw else []
        except (json.JSONDecodeError, TypeError):
            signals = [signals_raw] if signals_raw else []

        # Unpack score_meta if present
        score_meta = {}
        try:
            score_meta = json.loads(row[15]) if len(row) > 15 and row[15] else {}
        except (json.JSONDecodeError, TypeError, IndexError):
            pass

        prospect = {
            'id': row[0],
            'company': row[1],
            'city': row[2],
            'state': row[3],
            'score': row[4],
            'tiv': row[5],
            'projectStatus': row[6],
            'signals': signals,
            'whyNow': row[8],
            'executive': row[9],
            'title': row[10],
            'linkedin': row[11],
            'units': row[12],
            'projectName': row[13],
            'createdAt': row[14],
        }

        # Merge score_meta fields into prospect
        if score_meta:
            prospect['score_breakdown'] = score_meta.get('score_breakdown', {})
            prospect['score_explanation'] = score_meta.get('score_explanation', [])
            prospect['insurance_triggers'] = score_meta.get('insurance_triggers', [])
            prospect['unit_band'] = score_meta.get('unit_band', '')
            prospect['active_project_count_estimate'] = score_meta.get('active_project_count_estimate', 0)
            prospect['markets_active_estimate'] = score_meta.get('markets_active_estimate', 0)
            prospect['swim_lane_fit_score'] = score_meta.get('swim_lane_fit_score', 0)
            prospect['competitive_difficulty'] = score_meta.get('competitive_difficulty', '')

        prospects.append(prospect)

    conn.close()

    return jsonify({
        'success': True,
        'total': total,
        'prospects': prospects,
    })


# --- Daily Discovery API Routes ---

@app.route('/api/discovery/config', methods=['GET'])
@require_auth
def api_discovery_config():
    """Get current discovery configuration"""
    return jsonify({'success': True, 'config': DISCOVERY_CONFIG})


@app.route('/api/discovery/config', methods=['PUT'])
@require_auth
@require_role('admin')
def api_update_discovery_config():
    """Update discovery configuration (runtime only)"""
    data = request.json
    if 'max_signals_per_day' in data:
        DISCOVERY_CONFIG['max_signals_per_day'] = int(data['max_signals_per_day'])
    if 'icp_keywords' in data:
        DISCOVERY_CONFIG['icp_keywords'] = data['icp_keywords']
    if 'delivery_method' in data:
        DISCOVERY_CONFIG['delivery_method'] = data['delivery_method']
    if 'webhook_url' in data:
        DISCOVERY_CONFIG['webhook_url'] = data['webhook_url']
    return jsonify({'success': True, 'config': DISCOVERY_CONFIG})


@app.route('/api/discovery/latest', methods=['GET'])
@require_auth
def api_discovery_latest():
    """Get the most recent discovery run"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT * FROM discovery_runs ORDER BY run_at DESC LIMIT 1')
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': True, 'run': None, 'message': 'No discovery runs yet.'})
    adapter_stats = None
    try:
        adapter_stats = json.loads(row[7]) if len(row) > 7 and row[7] else None
    except (json.JSONDecodeError, TypeError, IndexError):
        pass
    return jsonify({
        'success': True,
        'run': {
            'id': row[0], 'run_at': row[1],
            'results': json.loads(row[2]) if row[2] else {},
            'digest': row[3], 'city_count': row[4],
            'total_new': row[5], 'status': row[6],
            'adapter_stats': adapter_stats
        }
    })


@app.route('/api/discovery/run', methods=['POST'])
@require_auth
def api_discovery_run():
    """Manually trigger a discovery run (background thread)"""
    global _discovery_running
    if _discovery_running:
        return jsonify({'success': False, 'message': 'A discovery run is already in progress.'})

    _discovery_running = True

    def run_bg():
        global _discovery_running
        try:
            run_daily_discovery(is_scheduled=False)
        except Exception as e:
            print(f"[Discovery] Background run failed: {e}")
            traceback.print_exc()
        finally:
            _discovery_running = False

    thread = threading.Thread(target=run_bg, daemon=True)
    thread.start()
    return jsonify({'success': True, 'message': 'Discovery run started. Results will appear shortly.'})


@app.route('/api/discovery/status', methods=['GET'])
@require_auth
def api_discovery_status():
    """Check if a discovery run is currently in progress"""
    return jsonify({'success': True, 'running': _discovery_running})


@app.route('/api/discovery/history', methods=['GET'])
@require_auth
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
@require_auth
def api_discovery_run_detail(run_id):
    """Get full results for a specific discovery run"""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT * FROM discovery_runs WHERE id = ?', (run_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'message': 'Run not found'}), 404
    adapter_stats = None
    try:
        adapter_stats = json.loads(row[7]) if len(row) > 7 and row[7] else None
    except (json.JSONDecodeError, TypeError, IndexError):
        pass
    return jsonify({
        'success': True,
        'run': {
            'id': row[0], 'run_at': row[1],
            'results': json.loads(row[2]) if row[2] else {},
            'digest': row[3], 'city_count': row[4],
            'total_new': row[5], 'status': row[6],
            'adapter_stats': adapter_stats
        }
    })


@app.route('/api/discovery/source-refresh', methods=['GET'])
@require_auth
def api_discovery_source_refresh():
    """Get last-refreshed timestamps for each source type"""
    from discovery_engine import get_source_refresh_times
    return jsonify({'success': True, 'sources': get_source_refresh_times()})


# ===================================================================
# STATEWIDE SEARCH + RANKINGS
# ===================================================================

STATEWIDE_STATES = {
    'TX': 'Texas',
    'AZ': 'Arizona',
    'GA': 'Georgia',
    'NC': 'North Carolina',
    'FL': 'Florida',
}

def _run_statewide_search(state_abbr):
    """
    Run statewide BTR search for a single state.
    Uses max 2 SerpAPI queries, 24h caching, Claude extraction (no web search tool).
    Returns (items_list, error_message) tuple.
    Each item: {event_type, city, state, company, units, summary, confidence, title, url, snippet, date}
    """
    from serpapi_client import cached_serpapi_search, get_cached, set_cached, SerpAPIError

    state_name = STATEWIDE_STATES.get(state_abbr, state_abbr)
    today = datetime.utcnow().strftime('%Y-%m-%d')

    # Check full-result cache first (Claude-processed output)
    result_cache_key = f"statewide_result:{state_abbr.lower()}:{today}"
    cached_result = get_cached(result_cache_key)
    if cached_result is not None:
        print(f"[Statewide] Cache hit for {state_abbr} processed results")
        return cached_result, None

    serp_key = os.getenv('SERPAPI_API_KEY', '')
    if not serp_key:
        return [], "SerpAPI key not configured. Statewide search requires SerpAPI."

    # Stage A: 2 SerpAPI queries (cached per-query for 24h via cached_serpapi_search)
    q1 = f'("build to rent" OR BTR OR "single-family rental") "{state_name}" (acquires OR acquisition OR sale OR sells OR JV OR recap OR refinancing OR "credit facility")'
    q2 = f'("build to rent" OR BTR OR "horizontal multifamily") "{state_name}" (groundbreaking OR "under construction" OR permit OR rezoning OR entitlement OR "planning commission")'

    all_candidates = []
    seen_links = set()

    for query in [q1, q2]:
        try:
            results = cached_serpapi_search(query, num=15, feature='statewide', city=state_abbr, state=state_abbr)
            for r in results:
                link = r.get('link', '')
                if link and link not in seen_links:
                    seen_links.add(link)
                    all_candidates.append(r)
        except SerpAPIError as e:
            print(f"[Statewide] SerpAPI error for {state_abbr}: {e}")
            # Continue with what we have

    if not all_candidates:
        return [], None

    # Stage B: Claude extraction (no web search tool)
    candidates_json = json.dumps([{
        'title': c.get('title', ''),
        'url': c.get('link', ''),
        'snippet': c.get('snippet', ''),
        'source': c.get('source', ''),
        'date': c.get('date', ''),
    } for c in all_candidates], indent=2)

    today_str = datetime.utcnow().strftime('%B %d, %Y')
    ninety_days_ago = (datetime.utcnow() - timedelta(days=90)).strftime('%B %Y')

    extraction_prompt = f"""You are an analyst for a Build-to-Rent (BTR) and Single-Family Rental (SFR) insurance brokerage.

Analyze these search results for BTR/SFR activity in {state_name} ({state_abbr}).

CANDIDATE RESULTS:
{candidates_json}

Today is {today_str}. Only include events from the last 90 days (since {ninety_days_ago}).

For EACH relevant result, extract:
- event_type: one of "acquisition", "sale", "groundbreaking", "permit", "rezoning", "financing", "JV", "construction", "other"
- city: infer from title/snippet. If unknown, set "Unknown"
- state: "{state_abbr}"
- company: the operator/developer/buyer involved (if identifiable)
- units: numeric estimate if mentioned, else null
- summary: one-sentence description of the event
- confidence: "high" (explicit BTR/SFR mention), "medium" (likely BTR context), "low" (possible but uncertain)
- title: the original title
- url: the original url
- date: the date from the result if available

IMPORTANT:
- Skip results that are clearly NOT about BTR/SFR real estate (e.g. other industries)
- One result may yield one item
- Do NOT fabricate data; only extract what is in the snippets/titles

Return ONLY valid JSON:
{{"items": [
  {{"event_type": "...", "city": "...", "state": "{state_abbr}", "company": "...", "units": null, "summary": "...", "confidence": "...", "title": "...", "url": "...", "date": "..."}}
]}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": extraction_prompt}]
        )
        response_text = message.content[0].text if message.content else ''

        # Parse JSON from response
        items = []
        try:
            # Try direct parse
            parsed = json.loads(response_text)
            items = parsed.get('items', [])
        except json.JSONDecodeError:
            # Find JSON block in response
            start = response_text.find('{"items"')
            if start == -1:
                start = response_text.find('```json')
                if start != -1:
                    start = response_text.find('{', start)
            if start != -1:
                depth = 0
                end = start
                for i in range(start, len(response_text)):
                    if response_text[i] == '{':
                        depth += 1
                    elif response_text[i] == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                try:
                    parsed = json.loads(response_text[start:end])
                    items = parsed.get('items', [])
                except json.JSONDecodeError:
                    print(f"[Statewide] Failed to parse Claude response for {state_abbr}")

        # Cache processed results for 24h
        set_cached(result_cache_key, items)
        return items, None

    except Exception as e:
        print(f"[Statewide] Claude extraction error for {state_abbr}: {e}")
        traceback.print_exc()
        return [], str(e)


def _compute_activity_scores(items, days=7):
    """
    Compute activity scores grouped by city from statewide items.
    Returns dict: {city: {activity_score, signals_count, dominant_event_types}}
    """
    from collections import Counter
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

    city_items = {}
    for item in items:
        city = item.get('city', 'Unknown')
        if city == 'Unknown':
            continue
        if city not in city_items:
            city_items[city] = []
        city_items[city].append(item)

    city_scores = {}
    for city, city_item_list in city_items.items():
        score = 0
        event_counts = Counter()

        for item in city_item_list:
            event_type = item.get('event_type', 'other')
            confidence = item.get('confidence', 'low')
            event_counts[event_type] += 1

            # Base point per signal
            base = 1
            # Confidence weight
            if confidence == 'high':
                base *= 2.0
            elif confidence == 'medium':
                base *= 1.5

            # Event type weight
            if event_type in ('acquisition', 'sale', 'financing', 'JV'):
                base *= 3.0  # Capital events weighted higher
            elif event_type in ('groundbreaking', 'construction', 'permit', 'rezoning'):
                base *= 2.0  # Construction activity
            else:
                base *= 1.0

            score += base

        # Dominant event types (top 3)
        dominant = [et for et, _ in event_counts.most_common(3)]

        city_scores[city] = {
            'city': city,
            'activity_score': round(score, 1),
            'signals_count': len(city_item_list),
            'dominant_event_types': dominant,
        }

    return city_scores


@app.route('/api/discovery/statewide/run', methods=['POST'])
@require_auth
def api_statewide_run():
    """Run statewide search for a single state. Returns items immediately (cached)."""
    data = request.json or {}
    state = data.get('state', '').upper()
    if state not in STATEWIDE_STATES:
        return jsonify({'success': False, 'message': f'State must be one of: {", ".join(STATEWIDE_STATES.keys())}'}), 400

    try:
        items, error = _run_statewide_search(state)
        if error:
            return jsonify({'success': False, 'message': error}), 500
        return jsonify({'success': True, 'state': state, 'items': items, 'count': len(items)})
    except Exception as e:
        print(f"[Statewide] Run error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/discovery/state-summary', methods=['GET'])
@require_auth
def api_state_summary():
    """Get activity summary for a state: top cities (7d + 30d) + items."""
    from serpapi_client import get_cached
    state = request.args.get('state', '').upper()
    if state not in STATEWIDE_STATES:
        return jsonify({'success': False, 'message': 'Invalid state'}), 400

    today = datetime.utcnow().strftime('%Y-%m-%d')
    result_cache_key = f"statewide_result:{state.lower()}:{today}"
    items = get_cached(result_cache_key) or []

    # Compute top cities
    scores_7d = _compute_activity_scores(items, days=7)
    scores_30d = _compute_activity_scores(items, days=30)

    top_7d = sorted(scores_7d.values(), key=lambda x: x['activity_score'], reverse=True)[:3]
    top_30d = sorted(scores_30d.values(), key=lambda x: x['activity_score'], reverse=True)[:3]

    return jsonify({
        'success': True,
        'state': state,
        'top_cities_7d': top_7d,
        'top_cities_30d': top_30d,
        'items': items,
        'total_signals': len(items),
    })


@app.route('/api/discovery/state-rankings', methods=['GET'])
@require_auth
def api_state_rankings():
    """Get rankings across all 5 states for the last 7 days."""
    from serpapi_client import get_cached
    today = datetime.utcnow().strftime('%Y-%m-%d')

    rankings = []
    for state_abbr in STATEWIDE_STATES:
        result_cache_key = f"statewide_result:{state_abbr.lower()}:{today}"
        items = get_cached(result_cache_key) or []

        capital_count = 0
        construction_count = 0
        for item in items:
            et = item.get('event_type', '')
            if et in ('acquisition', 'sale', 'financing', 'JV'):
                capital_count += 1
            elif et in ('groundbreaking', 'construction', 'permit', 'rezoning'):
                construction_count += 1

        scores = _compute_activity_scores(items, days=7)
        total_score = sum(s['activity_score'] for s in scores.values())
        top_cities = sorted(scores.values(), key=lambda x: x['activity_score'], reverse=True)[:3]

        rankings.append({
            'state': state_abbr,
            'state_name': STATEWIDE_STATES[state_abbr],
            'state_activity_score': round(total_score, 1),
            'total_signals': len(items),
            'capital_events_count': capital_count,
            'construction_signals_count': construction_count,
            'top_cities': top_cities,
            'last_updated': today if items else None,
        })

    rankings.sort(key=lambda x: x['state_activity_score'], reverse=True)
    return jsonify({'success': True, 'rankings': rankings})


# ===================================================================
# SIGNAL WEIGHTING + MOMENTUM + CALL TIMING ENGINE
# ===================================================================

def get_signal_weight(topic_or_text):
    """
    Return signal weight 1-5 based on event/signal type.
    Financing/capital events: 5, Acquisition/disposition: 4,
    Construction: 3, Permits/rezoning: 2, Generic: 1.
    """
    t = (topic_or_text or '').lower()
    # Weight 5: Financing / capital events
    if any(k in t for k in ('financing', 'credit facility', 'recap', 'recapitalization',
                             'jv', 'joint venture', 'preferred equity', 'capital',
                             'institutional', 'fund', 'credit')):
        return 5
    # Weight 4: Acquisitions / dispositions
    if any(k in t for k in ('acquisition', 'acquires', 'disposition', 'portfolio sale',
                             'sale', 'sells', 'purchase', 'bought')):
        return 4
    # Weight 4: Refinance / debt renewal
    if any(k in t for k in ('refinanc', 'debt facility', 'renewal', 'loan')):
        return 4
    # Weight 3: Construction activity
    if any(k in t for k in ('groundbreaking', 'under construction', 'construction',
                             'starts', 'new_build', 'new build', 'breaking ground',
                             'delivered', 'completion')):
        return 3
    # Weight 2: Permits / entitlements
    if any(k in t for k in ('permit', 'rezoning', 'entitlement', 'planning',
                             'approval', 'zoning', 'permit_rezoning')):
        return 2
    # Weight 1: Generic BTR mention
    return 1


def materialize_weighted_signals(days=90):
    """
    Materialize weighted_signals table from discovery_runs + search_cache.
    Idempotent: clears and rebuilds for the window. No SerpAPI calls.
    """
    print("[WeightedSignals] Materializing weighted signals...")
    all_items = _gather_all_signals(days=days)
    if not all_items:
        print("[WeightedSignals] No signals to materialize.")
        return 0

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    c.execute('DELETE FROM weighted_signals WHERE published_at < ? OR published_at IS NULL', (cutoff,))

    inserted = 0
    for item in all_items:
        # Compute weight from both topic and textual content
        topic_weight = get_signal_weight(item['topic'])
        text_weight = get_signal_weight(item.get('summary', '') + ' ' + item.get('title', ''))
        weight = max(topic_weight, text_weight)

        sig_id = hashlib.md5(
            f"{item['state']}:{item['city']}:{item['topic']}:{item.get('entity_name','')}:{item['date_str']}"
            .encode()
        ).hexdigest()

        try:
            c.execute('''
                INSERT OR REPLACE INTO weighted_signals
                (id, state, city, topic, signal_weight, entity_name, title, summary, source, source_type, confidence, published_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (sig_id, item['state'], item['city'], item['topic'], weight,
                  item.get('entity_name', ''), item.get('title', ''), item.get('summary', ''),
                  item.get('source', ''), item.get('source_type', ''), item.get('confidence', 'medium'),
                  item['date_str']))
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    print(f"[WeightedSignals] Materialized {inserted} weighted signals from {len(all_items)} raw items.")
    return inserted


def compute_market_momentum():
    """
    Daily job: compute market_momentum for each state+city in the 5 Sunbelt states.
    Reads from weighted_signals table. No SerpAPI calls.
    """
    print("[Momentum] Computing market momentum...")
    now = datetime.utcnow()
    window_end = now.strftime('%Y-%m-%d')
    cutoff_7d = (now - timedelta(days=7)).isoformat()
    cutoff_14d = (now - timedelta(days=14)).isoformat()
    cutoff_30d = (now - timedelta(days=30)).isoformat()

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()

    # Get all unique (state, city) pairs from weighted_signals in the 5 states
    c.execute('''
        SELECT DISTINCT state, city FROM weighted_signals
        WHERE state IN ('TX','AZ','GA','NC','FL') AND published_at >= ?
    ''', (cutoff_30d,))
    markets = c.fetchall()

    inserted = 0
    for state, city in markets:
        # Unweighted counts
        c.execute('SELECT COUNT(*) FROM weighted_signals WHERE state=? AND city=? AND published_at>=?', (state, city, cutoff_7d))
        sig_7d = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM weighted_signals WHERE state=? AND city=? AND published_at>=?', (state, city, cutoff_14d))
        sig_14d = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM weighted_signals WHERE state=? AND city=? AND published_at>=?', (state, city, cutoff_30d))
        sig_30d = c.fetchone()[0]

        # Weighted counts
        c.execute('SELECT COALESCE(SUM(signal_weight),0) FROM weighted_signals WHERE state=? AND city=? AND published_at>=?', (state, city, cutoff_7d))
        wsig_7d = c.fetchone()[0]
        c.execute('SELECT COALESCE(SUM(signal_weight),0) FROM weighted_signals WHERE state=? AND city=? AND published_at>=?', (state, city, cutoff_14d))
        wsig_14d = c.fetchone()[0]
        c.execute('SELECT COALESCE(SUM(signal_weight),0) FROM weighted_signals WHERE state=? AND city=? AND published_at>=?', (state, city, cutoff_30d))
        wsig_30d = c.fetchone()[0]

        # Momentum score
        baseline = wsig_30d / 4.0
        ratio_7d = wsig_7d / max(1, baseline)
        ratio_14d = wsig_14d / max(1, baseline * 2)
        momentum_score = max(0, min(100, ratio_7d * 60 + ratio_14d * 40))

        if momentum_score >= 65:
            momentum_label = 'Accelerating'
        elif momentum_score >= 40:
            momentum_label = 'Stable'
        else:
            momentum_label = 'Cooling'

        mid = str(uuid.uuid4())
        try:
            c.execute('''
                INSERT OR REPLACE INTO market_momentum
                (id, state, city, window_end_date, signals_7d, signals_14d, signals_30d,
                 weighted_signals_7d, weighted_signals_14d, weighted_signals_30d,
                 momentum_score, momentum_label, computed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (mid, state, city, window_end, sig_7d, sig_14d, sig_30d,
                  wsig_7d, wsig_14d, wsig_30d,
                  round(momentum_score, 1), momentum_label))
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    print(f"[Momentum] Computed momentum for {inserted} markets.")
    return inserted


def _get_momentum_for_city(state, city):
    """Lookup latest momentum_score for a city. Returns (score, label) or (50, 'Stable')."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('''
        SELECT momentum_score, momentum_label FROM market_momentum
        WHERE state=? AND city=? ORDER BY window_end_date DESC LIMIT 1
    ''', (state, city))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return 50.0, 'Stable'


def _compute_freshness_score(state, city, company_name):
    """Compute freshness (0-100) based on most recent signal for this entity/market."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    # Look for signals matching entity or city
    c.execute('''
        SELECT MAX(published_at) FROM weighted_signals
        WHERE state=? AND city=? AND (entity_name LIKE ? OR entity_name = '')
    ''', (state, city, f'%{company_name[:20]}%' if company_name else '%'))
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        return 30
    try:
        pub_date = datetime.fromisoformat(row[0].replace('Z', '+00:00')) if 'T' in row[0] else datetime.strptime(row[0][:10], '%Y-%m-%d')
        days_ago = (datetime.utcnow() - pub_date.replace(tzinfo=None)).days
    except (ValueError, TypeError):
        return 30

    if days_ago <= 14:
        return 90
    elif days_ago <= 30:
        return 70
    elif days_ago <= 90:
        return 50
    return 30


def compute_lead_timing_scores(workspace_id=None):
    """
    Daily job: compute call timing scores for all prospects in run_prospects + CRM.
    Reads precomputed market_momentum. No SerpAPI calls.
    """
    print("[CallTiming] Computing lead timing scores...")
    conn = sqlite3.connect('prospects.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Gather all prospects from recent prospecting runs (last 90 days)
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()
    c.execute('''
        SELECT rp.company_name, rp.city, rp.state, rp.score, rp.score_meta,
               rp.run_id
        FROM run_prospects rp
        JOIN prospecting_runs pr ON rp.run_id = pr.id
        WHERE pr.created_at >= ? AND rp.score > 0
    ''', (cutoff,))
    prospects = c.fetchall()

    # Also gather from the main prospects table
    c.execute('SELECT company, city, state, score FROM prospects WHERE score > 0')
    main_prospects = c.fetchall()

    conn.close()

    # Build deduped prospect list
    seen_keys = set()
    prospect_list = []

    for p in prospects:
        company = p['company_name']
        city = p['city'] or ''
        state = p['state'] or ''
        key = f"{company.lower().strip()}|{city.lower()}|{state.lower()}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        score_meta = {}
        if p['score_meta']:
            try:
                score_meta = json.loads(p['score_meta'])
            except (json.JSONDecodeError, TypeError):
                pass

        prospect_list.append({
            'company_name': company,
            'city': city,
            'state': state,
            'score': p['score'],
            'swim_lane_fit_score': score_meta.get('swim_lane_fit_score'),
            'competitive_difficulty': score_meta.get('competitive_difficulty', 'Medium'),
            'unit_band': score_meta.get('unit_band', ''),
            'prospect_key': key,
        })

    for p in main_prospects:
        company = p['company']
        city = p['city'] or ''
        state = p['state'] or ''
        key = f"{company.lower().strip()}|{city.lower()}|{state.lower()}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        prospect_list.append({
            'company_name': company,
            'city': city,
            'state': state,
            'score': p['score'],
            'swim_lane_fit_score': None,
            'competitive_difficulty': 'Medium',
            'unit_band': '',
            'prospect_key': key,
        })

    if not prospect_list:
        print("[CallTiming] No prospects to score.")
        return 0

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    scored = 0

    for p in prospect_list:
        trigger_severity = p['score'] or 0

        # Swim lane fit
        swim_lane_fit = p.get('swim_lane_fit_score')
        if swim_lane_fit is None:
            # Estimate from unit_band
            ub = (p.get('unit_band') or '').lower()
            swim_lane_fit = 50
            if '40-150' in ub:
                swim_lane_fit = 75
            elif '150-400' in ub:
                swim_lane_fit = 70
            elif '<40' in ub:
                swim_lane_fit = 35
            elif '400-1000' in ub:
                swim_lane_fit = 40
            elif '1000' in ub:
                swim_lane_fit = 25

        # Engagement score proxy
        engagement = 60
        cd = (p.get('competitive_difficulty') or 'Medium')
        if cd == 'High':
            engagement -= 15
        elif cd == 'Low':
            engagement += 10
        ub = (p.get('unit_band') or '').lower()
        if '40-150' in ub or '150-400' in ub:
            engagement += 10
        engagement = max(0, min(100, engagement))

        # Market momentum
        momentum, momentum_label = _get_momentum_for_city(p['state'], p['city'])

        # Freshness
        freshness = _compute_freshness_score(p['state'], p['city'], p['company_name'])

        # Call timing formula
        call_timing = (
            0.35 * trigger_severity +
            0.20 * swim_lane_fit +
            0.20 * engagement +
            0.15 * momentum +
            0.10 * freshness
        )
        call_timing = max(0, min(100, round(call_timing, 1)))

        if call_timing >= 75:
            timing_label = 'Call Now'
        elif call_timing >= 55:
            timing_label = 'Work'
        else:
            timing_label = 'Watch'

        # Generate reasons
        reasons = []
        if trigger_severity >= 80:
            reasons.append(f"High trigger severity ({trigger_severity}/100)")
        elif trigger_severity >= 60:
            reasons.append(f"Moderate trigger severity ({trigger_severity}/100)")
        if swim_lane_fit >= 70:
            reasons.append(f"Strong swim-lane fit ({swim_lane_fit}/100)")
        if momentum >= 65:
            reasons.append(f"Accelerating market ({p['city']}, {p['state']})")
        elif momentum < 40:
            reasons.append(f"Cooling market conditions in {p['city']}")
        if freshness >= 70:
            reasons.append("Recent activity signals detected")
        if cd == 'Low':
            reasons.append("Low competitive difficulty - easier engagement")
        elif cd == 'High':
            reasons.append("High competitive difficulty - needs differentiated approach")
        if not reasons:
            reasons.append(f"Composite score: {call_timing}")

        ws_id = workspace_id or 'default'
        lid = str(uuid.uuid4())
        try:
            c.execute('''
                INSERT OR REPLACE INTO lead_timing_scores
                (id, workspace_id, prospect_key, company_name, state, city,
                 trigger_severity, swim_lane_fit, engagement_score,
                 market_momentum_score, freshness_score, call_timing_score,
                 timing_label, reasons, computed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (lid, ws_id, p['prospect_key'], p['company_name'], p['state'], p['city'],
                  trigger_severity, swim_lane_fit, engagement, momentum, freshness,
                  call_timing, timing_label, json.dumps(reasons)))
            scored += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    print(f"[CallTiming] Scored {scored} prospects.")
    return scored


def run_daily_optimization():
    """
    Master daily job: materialize signals → compute momentum → compute timing.
    Runs after trend detection (8:00am PT). No SerpAPI calls.
    """
    print("[Optimization] Starting daily optimization pipeline...")
    try:
        materialize_weighted_signals(days=90)
        compute_market_momentum()
        compute_lead_timing_scores()
        print("[Optimization] Daily optimization complete.")
    except Exception as e:
        print(f"[Optimization] Error: {e}")
        traceback.print_exc()


# ===================================================================
# TREND DETECTION ENGINE + WEEKLY BRIEF
# ===================================================================

def _gather_all_signals(days=30):
    """
    Gather all signals from discovery_runs and statewide search_cache.
    Returns list of normalized items: {state, city, topic, date_str, source}
    No SerpAPI calls — reads only existing cached/stored data.
    """
    from serpapi_client import get_cached
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    all_items = []

    # Source 1: discovery_runs.results_json (daily discovery signals)
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT results_json, run_at FROM discovery_runs WHERE run_at >= ? AND status = ?', (cutoff, 'completed'))
    for row in c.fetchall():
        try:
            results = json.loads(row[0]) if row[0] else {}
            run_date = row[1]
            for location, data in results.items():
                for sig in (data.get('signals') or []):
                    topic = sig.get('signal_type', 'other')
                    if topic == 'not_relevant':
                        continue
                    all_items.append({
                        'state': sig.get('state', ''),
                        'city': sig.get('city', 'Unknown'),
                        'topic': topic,
                        'date_str': run_date,
                        'source': 'discovery',
                        'title': sig.get('title', ''),
                        'url': sig.get('url', ''),
                        'summary': sig.get('summary', ''),
                        'entity_name': sig.get('entity_name', ''),
                        'confidence': sig.get('confidence', 'medium'),
                        'source_type': sig.get('source_type', 'news'),
                    })
        except (json.JSONDecodeError, TypeError):
            continue
    conn.close()

    # Source 2: statewide search_cache (statewide_result:* keys)
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute("SELECT cache_key, payload_json, created_at FROM search_cache WHERE cache_key LIKE 'statewide_result:%'")
    for row in c.fetchall():
        try:
            items = json.loads(row[1]) if row[1] else []
            cache_date = row[2]
            for item in items:
                topic = item.get('event_type', 'other')
                all_items.append({
                    'state': item.get('state', ''),
                    'city': item.get('city', 'Unknown'),
                    'topic': topic,
                    'date_str': cache_date,
                    'source': 'statewide',
                    'title': item.get('title', ''),
                    'url': item.get('url', ''),
                    'summary': item.get('summary', ''),
                    'entity_name': item.get('company', ''),
                    'confidence': item.get('confidence', 'medium'),
                    'source_type': 'news',
                })
        except (json.JSONDecodeError, TypeError):
            continue
    conn.close()

    return all_items


def run_trend_detection():
    """
    Daily trend detection job. Aggregates signals, computes trends, stores results.
    No SerpAPI calls. Operates only on existing data.
    """
    print("[TrendDetection] Starting trend detection...")
    all_items = _gather_all_signals(days=30)
    if not all_items:
        print("[TrendDetection] No signals to analyze.")
        return

    now = datetime.utcnow()
    cutoff_7d = (now - timedelta(days=7)).isoformat()

    # Group by (state, city, topic)
    from collections import defaultdict
    groups = defaultdict(lambda: {'items_7d': 0, 'items_30d': 0})
    for item in all_items:
        key = (item['state'], item['city'], item['topic'])
        groups[key]['items_30d'] += 1
        if item['date_str'] and item['date_str'] >= cutoff_7d:
            groups[key]['items_7d'] += 1

    # Compute trends and insert
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    computed_at = now.strftime('%Y-%m-%d')
    inserted = 0

    for (state, city, topic), counts in groups.items():
        count_7d = counts['items_7d']
        count_30d = counts['items_30d']
        baseline_avg = count_30d / 4.0 if count_30d > 0 else 0
        trend_ratio = count_7d / baseline_avg if baseline_avg > 0 else 0

        if count_7d >= 3 and trend_ratio >= 1.8:
            # Classify
            if trend_ratio >= 2.5:
                classification = 'Accelerating'
            elif count_7d > count_30d / 2:
                classification = 'Peaking'
            else:
                classification = 'Emerging'

            trend_id = str(uuid.uuid4())
            try:
                c.execute('''
                    INSERT OR REPLACE INTO trend_signals (id, state, city, topic, count_7d, count_30d, trend_ratio, classification, computed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (trend_id, state, city, topic, count_7d, count_30d, round(trend_ratio, 2), classification, computed_at))
                inserted += 1
            except sqlite3.IntegrityError:
                pass

    conn.commit()
    conn.close()
    print(f"[TrendDetection] Completed. {inserted} trend signals detected from {len(all_items)} total items.")


def generate_weekly_brief():
    """
    Weekly Sunbelt Intelligence Brief generation.
    Pulls trend_signals + recent signals, generates report via Claude.
    No SerpAPI calls.
    """
    print("[WeeklyBrief] Generating Sunbelt Intelligence Brief...")
    now = datetime.utcnow()
    week_end = now.strftime('%Y-%m-%d')
    week_start = (now - timedelta(days=7)).strftime('%Y-%m-%d')

    # 1. Get trend signals from last 7 days
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT state, city, topic, count_7d, count_30d, trend_ratio, classification FROM trend_signals WHERE computed_at >= ? ORDER BY trend_ratio DESC', (week_start,))
    trends = [{'state': r[0], 'city': r[1], 'topic': r[2], 'count_7d': r[3], 'count_30d': r[4], 'trend_ratio': r[5], 'classification': r[6]} for r in c.fetchall()]
    conn.close()

    # 2. Get recent signal summaries
    all_items = _gather_all_signals(days=7)
    # State activity counts
    from collections import Counter
    state_counts = Counter(item['state'] for item in all_items if item['state'])
    capital_events = [i for i in all_items if i['topic'] in ('acquisition', 'sale', 'financing', 'JV', 'recapitalization')]
    construction_events = [i for i in all_items if i['topic'] in ('groundbreaking', 'construction', 'permit', 'rezoning', 'new_build', 'under_construction', 'permit_rezoning')]
    refinancing_events = [i for i in all_items if i['topic'] in ('financing', 'recapitalization', 'refinancing')]

    # Build context for Claude
    context = {
        'week': f"{week_start} to {week_end}",
        'states': ['TX', 'AZ', 'GA', 'NC', 'FL'],
        'state_signal_counts': dict(state_counts),
        'total_signals': len(all_items),
        'trend_signals': trends[:20],
        'capital_events_sample': [{'company': e.get('entity_name', ''), 'city': e['city'], 'state': e['state'], 'topic': e['topic'], 'summary': e.get('summary', e.get('title', ''))} for e in capital_events[:15]],
        'construction_sample': [{'entity': e.get('entity_name', ''), 'city': e['city'], 'state': e['state'], 'topic': e['topic'], 'summary': e.get('summary', e.get('title', ''))} for e in construction_events[:15]],
        'refinancing_sample': [{'entity': e.get('entity_name', ''), 'city': e['city'], 'state': e['state'], 'summary': e.get('summary', e.get('title', ''))} for e in refinancing_events[:10]],
    }

    prompt = f"""You are a senior market analyst for a Build-to-Rent (BTR) and Single-Family Rental (SFR) insurance brokerage covering the Sunbelt states.

Generate the Weekly Sunbelt Risk Intelligence Brief for {context['week']}.

DATA:
{json.dumps(context, indent=2)}

Write a structured report with these EXACT sections (use markdown headers):

## Most Active State
Identify the most active state by signal volume and explain why (specific deals, permits, trends).

## Top 3 Cities by Capital Movement
Rank the top 3 cities seeing the most acquisition/financing/JV activity. Include company names and deal details where available.

## Financing Themes Emerging
What financing patterns are emerging? (credit facilities, institutional capital, JV formations, etc.)

## Construction Acceleration Signals
Where is construction activity accelerating? (groundbreakings, permits, rezoning approvals)

## Refinancing Signals
Note any refinancing or recapitalization signals that indicate portfolio repositioning.

## Insurance Inflection Implications
Tie findings to insurance opportunities for 40-400 unit BTR operators. What coverage needs are emerging? (Builder's Risk transitions, portfolio scale triggers, new state expansions)

## 3 Strategic Conversation Angles
Provide 3 specific, actionable conversation starters a producer could use this week when calling BTR operators.

TONE: Professional, analytical, data-driven. Not salesy. Reference specific companies, cities, and deal details from the data.
If the data is sparse, note that and provide analysis based on what's available.

Return the brief as markdown text."""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        brief_text = message.content[0].text if message.content else ''
    except Exception as e:
        print(f"[WeeklyBrief] Claude error: {e}")
        brief_text = f"Brief generation failed: {str(e)}"

    # Store
    brief_id = str(uuid.uuid4())
    brief_data = {
        'text': brief_text,
        'stats': {
            'total_signals': context['total_signals'],
            'state_counts': context['state_signal_counts'],
            'trend_count': len(trends),
            'capital_events': len(capital_events),
            'construction_events': len(construction_events),
        }
    }

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('INSERT INTO weekly_briefs (id, brief_json, week_start, week_end) VALUES (?, ?, ?, ?)',
              (brief_id, json.dumps(brief_data), week_start, week_end))
    conn.commit()
    conn.close()
    print(f"[WeeklyBrief] Brief generated and stored (id={brief_id})")
    return brief_id


# --- Intelligence API Endpoints ---

@app.route('/api/intelligence/trends', methods=['GET'])
@require_auth
def api_intelligence_trends():
    """Get trend signals with optional state filter."""
    state = request.args.get('state', '').upper()
    topic = request.args.get('topic', '')
    days = min(int(request.args.get('days', 7)), 90)
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    query = 'SELECT id, state, city, topic, count_7d, count_30d, trend_ratio, classification, computed_at FROM trend_signals WHERE computed_at >= ?'
    params = [cutoff]

    if state:
        query += ' AND state = ?'
        params.append(state)
    if topic:
        query += ' AND topic = ?'
        params.append(topic)

    query += ' ORDER BY trend_ratio DESC'
    c.execute(query, params)

    trends = []
    for r in c.fetchall():
        trends.append({
            'id': r[0], 'state': r[1], 'city': r[2], 'topic': r[3],
            'count_7d': r[4], 'count_30d': r[5], 'trend_ratio': r[6],
            'classification': r[7], 'computed_at': r[8],
        })
    conn.close()
    return jsonify({'success': True, 'trends': trends})


@app.route('/api/intelligence/briefs', methods=['GET'])
@require_auth
def api_intelligence_briefs():
    """List weekly briefs (latest first)."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT id, generated_at, week_start, week_end FROM weekly_briefs ORDER BY generated_at DESC LIMIT 20')
    briefs = [{'id': r[0], 'generated_at': r[1], 'week_start': r[2], 'week_end': r[3]} for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'briefs': briefs})


@app.route('/api/intelligence/briefs/latest', methods=['GET'])
@require_auth
def api_intelligence_briefs_latest():
    """Get the latest weekly brief with full content."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT id, brief_json, generated_at, week_start, week_end FROM weekly_briefs ORDER BY generated_at DESC LIMIT 1')
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': True, 'brief': None})
    return jsonify({
        'success': True,
        'brief': {
            'id': row[0],
            'content': json.loads(row[1]) if row[1] else {},
            'generated_at': row[2],
            'week_start': row[3],
            'week_end': row[4],
        }
    })


@app.route('/api/intelligence/briefs/<brief_id>', methods=['GET'])
@require_auth
def api_intelligence_brief_detail(brief_id):
    """Get a specific weekly brief."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('SELECT id, brief_json, generated_at, week_start, week_end FROM weekly_briefs WHERE id = ?', (brief_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'message': 'Brief not found'}), 404
    return jsonify({
        'success': True,
        'brief': {
            'id': row[0],
            'content': json.loads(row[1]) if row[1] else {},
            'generated_at': row[2],
            'week_start': row[3],
            'week_end': row[4],
        }
    })


@app.route('/api/intelligence/briefs/generate', methods=['POST'])
@require_auth
@require_role('admin')
def api_intelligence_generate_brief():
    """Admin: manually trigger weekly brief generation."""
    try:
        # Run trend detection first
        run_trend_detection()
        brief_id = generate_weekly_brief()
        return jsonify({'success': True, 'brief_id': brief_id})
    except Exception as e:
        print(f"[Intelligence] Brief generation error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/intelligence/trends/run', methods=['POST'])
@require_auth
@require_role('admin')
def api_intelligence_run_trends():
    """Admin: manually trigger trend detection."""
    try:
        run_trend_detection()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/intelligence/state-rankings', methods=['GET'])
@require_auth
def api_intelligence_state_rankings():
    """Enhanced state rankings with trend strength included."""
    from serpapi_client import get_cached
    today = datetime.utcnow().strftime('%Y-%m-%d')

    # Get trend counts per state
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    cutoff_7d = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
    c.execute('SELECT state, COUNT(*), MAX(trend_ratio) FROM trend_signals WHERE computed_at >= ? GROUP BY state', (cutoff_7d,))
    trend_data = {r[0]: {'trend_count': r[1], 'max_trend_ratio': r[2]} for r in c.fetchall()}
    conn.close()

    rankings = []
    for state_abbr in STATEWIDE_STATES:
        result_cache_key = f"statewide_result:{state_abbr.lower()}:{today}"
        items = get_cached(result_cache_key) or []

        capital_count = sum(1 for i in items if i.get('event_type') in ('acquisition', 'sale', 'financing', 'JV'))
        construction_count = sum(1 for i in items if i.get('event_type') in ('groundbreaking', 'construction', 'permit', 'rezoning'))

        scores = _compute_activity_scores(items, days=7)
        total_score = sum(s['activity_score'] for s in scores.values())
        top_cities = sorted(scores.values(), key=lambda x: x['activity_score'], reverse=True)[:3]

        td = trend_data.get(state_abbr, {})
        rankings.append({
            'state': state_abbr,
            'state_name': STATEWIDE_STATES[state_abbr],
            'state_activity_score': round(total_score, 1),
            'total_signals': len(items),
            'capital_events_count': capital_count,
            'construction_signals_count': construction_count,
            'top_cities': top_cities,
            'trend_count': td.get('trend_count', 0),
            'max_trend_ratio': td.get('max_trend_ratio', 0),
            'last_updated': today if items else None,
        })

    rankings.sort(key=lambda x: x['state_activity_score'], reverse=True)
    return jsonify({'success': True, 'rankings': rankings})


# --- Momentum & Call Timing API Endpoints ---

@app.route('/api/intelligence/momentum', methods=['GET'])
@require_auth
def api_intelligence_momentum():
    """Get market momentum data. Optional state filter."""
    state = request.args.get('state', '').upper()
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    if state:
        c.execute('''
            SELECT state, city, momentum_score, momentum_label, signals_7d, signals_30d,
                   weighted_signals_7d, weighted_signals_30d, window_end_date
            FROM market_momentum WHERE state = ?
            ORDER BY momentum_score DESC
        ''', (state,))
    else:
        c.execute('''
            SELECT state, city, momentum_score, momentum_label, signals_7d, signals_30d,
                   weighted_signals_7d, weighted_signals_30d, window_end_date
            FROM market_momentum
            ORDER BY momentum_score DESC LIMIT 50
        ''')
    rows = c.fetchall()
    conn.close()
    markets = [{
        'state': r[0], 'city': r[1], 'momentum_score': r[2], 'momentum_label': r[3],
        'signals_7d': r[4], 'signals_30d': r[5],
        'weighted_signals_7d': r[6], 'weighted_signals_30d': r[7],
        'window_end_date': r[8]
    } for r in rows]
    return jsonify({'success': True, 'markets': markets})


@app.route('/api/intelligence/momentum/top', methods=['GET'])
@require_auth
def api_intelligence_momentum_top():
    """Get top 10 cities by momentum_score."""
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    c.execute('''
        SELECT state, city, momentum_score, momentum_label, weighted_signals_7d, weighted_signals_30d
        FROM market_momentum
        ORDER BY momentum_score DESC LIMIT 10
    ''')
    rows = c.fetchall()
    conn.close()
    cities = [{
        'state': r[0], 'city': r[1], 'momentum_score': r[2], 'momentum_label': r[3],
        'weighted_signals_7d': r[4], 'weighted_signals_30d': r[5]
    } for r in rows]
    return jsonify({'success': True, 'cities': cities})


@app.route('/api/intelligence/call-timing', methods=['GET'])
@require_auth
def api_intelligence_call_timing():
    """Get call timing scores. Optional filters: label, state, limit."""
    label = request.args.get('label', '')
    state = request.args.get('state', '').upper()
    limit = min(int(request.args.get('limit', 50)), 200)

    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    query = 'SELECT * FROM lead_timing_scores WHERE 1=1'
    params = []
    if label:
        query += ' AND timing_label = ?'
        params.append(label)
    if state:
        query += ' AND state = ?'
        params.append(state)
    query += ' ORDER BY call_timing_score DESC LIMIT ?'
    params.append(limit)

    c.execute(query, params)
    cols = [desc[0] for desc in c.description]
    rows = c.fetchall()
    conn.close()

    scores = []
    for r in rows:
        d = dict(zip(cols, r))
        d['reasons'] = json.loads(d['reasons']) if d.get('reasons') else []
        scores.append(d)
    return jsonify({'success': True, 'scores': scores})


@app.route('/api/intelligence/call-timing/lookup', methods=['GET'])
@require_auth
def api_intelligence_call_timing_lookup():
    """Lookup call timing for a specific prospect_key (or bulk via comma-separated keys)."""
    keys = request.args.get('keys', '')
    if not keys:
        return jsonify({'success': True, 'scores': {}})

    key_list = [k.strip() for k in keys.split(',') if k.strip()]
    conn = sqlite3.connect('prospects.db')
    c = conn.cursor()
    placeholders = ','.join('?' * len(key_list))
    c.execute(f'''
        SELECT prospect_key, call_timing_score, timing_label, reasons,
               trigger_severity, swim_lane_fit, engagement_score,
               market_momentum_score, freshness_score
        FROM lead_timing_scores WHERE prospect_key IN ({placeholders})
    ''', key_list)
    rows = c.fetchall()
    conn.close()

    result = {}
    for r in rows:
        result[r[0]] = {
            'call_timing_score': r[1], 'timing_label': r[2],
            'reasons': json.loads(r[3]) if r[3] else [],
            'trigger_severity': r[4], 'swim_lane_fit': r[5],
            'engagement_score': r[6], 'market_momentum_score': r[7],
            'freshness_score': r[8]
        }
    return jsonify({'success': True, 'scores': result})


@app.route('/api/intelligence/optimization/run', methods=['POST'])
@require_auth
@require_role('admin')
def api_intelligence_run_optimization():
    """Admin: manually trigger the full optimization pipeline."""
    try:
        run_daily_optimization()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# --- Scheduler Setup ---
def _scheduled_discovery():
    """Wrapper that enqueues the scheduled discovery job (runs ALL adapters including permits)."""
    from queue_config import enqueue
    enqueue(run_daily_discovery, True, job_timeout=600)  # is_scheduled=True

def _scheduled_trend_detection():
    """Daily trend detection (runs after discovery, at 7:30am PT)."""
    try:
        run_trend_detection()
    except Exception as e:
        print(f"[Scheduler] Trend detection error: {e}")

def _scheduled_weekly_brief():
    """Monday weekly brief generation (7:00am PT)."""
    try:
        run_trend_detection()  # Refresh trends first
        generate_weekly_brief()
    except Exception as e:
        print(f"[Scheduler] Weekly brief error: {e}")

def _scheduled_optimization():
    """Daily optimization: weighted signals → momentum → call timing (8:00am PT)."""
    try:
        run_daily_optimization()
    except Exception as e:
        print(f"[Scheduler] Optimization error: {e}")

_scheduler = BackgroundScheduler(daemon=True)
_scheduler.add_job(
    _scheduled_discovery,
    CronTrigger(
        hour=DISCOVERY_CONFIG['schedule_hour'],
        minute=DISCOVERY_CONFIG['schedule_minute'],
        timezone=pytz.timezone(DISCOVERY_CONFIG['timezone'])
    ),
    id='daily_discovery',
    name='Daily BTR Discovery',
    replace_existing=True
)
_scheduler.add_job(
    _scheduled_trend_detection,
    CronTrigger(hour=7, minute=30, timezone=pytz.timezone('America/Los_Angeles')),
    id='daily_trends',
    name='Daily Trend Detection',
    replace_existing=True
)
_scheduler.add_job(
    _scheduled_weekly_brief,
    CronTrigger(day_of_week='mon', hour=7, minute=0, timezone=pytz.timezone('America/Los_Angeles')),
    id='weekly_brief',
    name='Weekly Sunbelt Brief',
    replace_existing=True
)
_scheduler.add_job(
    _scheduled_optimization,
    CronTrigger(hour=8, minute=0, timezone=pytz.timezone('America/Los_Angeles')),
    id='daily_optimization',
    name='Daily Signal Optimization',
    replace_existing=True
)
_scheduler.start()
print(f"[Scheduler] Daily discovery scheduled for {DISCOVERY_CONFIG['schedule_hour']}:{DISCOVERY_CONFIG['schedule_minute']:02d} AM {DISCOVERY_CONFIG['timezone']}")
print("[Scheduler] Daily trend detection at 7:30 AM PT")
print("[Scheduler] Weekly Sunbelt Brief every Monday 7:00 AM PT")
print("[Scheduler] Daily optimization (weights + momentum + timing) at 8:00 AM PT")


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

