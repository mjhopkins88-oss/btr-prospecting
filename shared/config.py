"""
Shared configuration for the Lead Intelligence Platform.
Reads from environment variables with sensible defaults.
"""
import os

# --- Database ---
DATABASE_URL = os.getenv('DATABASE_URL', '')

# --- Redis / Queue ---
REDIS_URL = os.getenv('REDIS_URL', '')

# --- AI ---
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
AI_MODEL = os.getenv('AI_MODEL', 'claude-sonnet-4-20250514')

# --- Signal Collector APIs ---
SERPAPI_KEY = os.getenv('SERPAPI_KEY', '')
PERMITS_API_URL = os.getenv('PERMITS_API_URL', '')  # optional external permits API

# --- Lead Scoring Weights (defaults) ---
SCORE_WEIGHT_SIGNAL_STRENGTH = float(os.getenv('SCORE_WEIGHT_SIGNAL_STRENGTH', '0.30'))
SCORE_WEIGHT_ENTITY_FIT = float(os.getenv('SCORE_WEIGHT_ENTITY_FIT', '0.25'))
SCORE_WEIGHT_TIMING = float(os.getenv('SCORE_WEIGHT_TIMING', '0.20'))
SCORE_WEIGHT_MARKET = float(os.getenv('SCORE_WEIGHT_MARKET', '0.15'))
SCORE_WEIGHT_RECENCY = float(os.getenv('SCORE_WEIGHT_RECENCY', '0.10'))

# --- Routing ---
DEFAULT_ROUTE_REGION_MAP = {
    'AZ': 'west',
    'NV': 'west',
    'CA': 'west',
    'TX': 'south',
    'FL': 'south',
    'GA': 'south',
    'NC': 'east',
    'SC': 'east',
    'VA': 'east',
    'TN': 'south',
    'CO': 'west',
}

# --- Target Markets ---
TARGET_CITIES = [
    {'city': 'Phoenix', 'state': 'AZ'},
    {'city': 'Dallas', 'state': 'TX'},
    {'city': 'Atlanta', 'state': 'GA'},
    {'city': 'Charlotte', 'state': 'NC'},
    {'city': 'Nashville', 'state': 'TN'},
    {'city': 'Tampa', 'state': 'FL'},
    {'city': 'Denver', 'state': 'CO'},
    {'city': 'Raleigh', 'state': 'NC'},
    {'city': 'Austin', 'state': 'TX'},
    {'city': 'Orlando', 'state': 'FL'},
]

# --- ICP Keywords ---
ICP_KEYWORDS = [
    'build to rent',
    'single family rental',
    'BTR community',
    'horizontal multifamily',
    'residential land development',
    'homebuilder land acquisition',
]

# --- Scheduling ---
NIGHTLY_HOUR = int(os.getenv('NIGHTLY_HOUR', '2'))  # 2 AM Pacific
NIGHTLY_MINUTE = int(os.getenv('NIGHTLY_MINUTE', '0'))
TIMEZONE = 'US/Pacific'
