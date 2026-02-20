"""
Discovery configuration — target cities, monitored operators, adapter settings.

Used ONLY by Daily Discovery. Does NOT affect Prospect Search.
"""

# Target cities for Daily Discovery
DISCOVERY_CITIES = [
    {'city': 'Phoenix', 'state': 'AZ'},
    {'city': 'Dallas', 'state': 'TX'},
    {'city': 'Atlanta', 'state': 'GA'},
    {'city': 'Charlotte', 'state': 'NC'},
]

# SEC EDGAR monitored operators (CIK numbers for EDGAR full-text search)
MONITORED_OPERATORS = {
    'Invitation Homes': {'cik': '0001687229', 'ticker': 'INVH'},
    'American Homes 4 Rent': {'cik': '0001562401', 'ticker': 'AMH'},
    'Tricon Residential': {'cik': '0001635984', 'ticker': 'TCN'},
    'Progress Residential': {'cik': '', 'ticker': ''},  # private — skip EDGAR
}

# Filing types to monitor on EDGAR
EDGAR_FILING_TYPES = ['8-K', '10-Q', '10-K', '424B', 'S-3', 'D']

# Adapter run configuration
ADAPTER_CONFIG = {
    'edgar': {
        'enabled': True,
        'run_on_manual': True,   # runs on "Run Now" clicks
        'run_on_schedule': True, # runs on 7am scheduled job
    },
    'press_release': {
        'enabled': True,
        'run_on_manual': True,
        'run_on_schedule': True,
    },
    'permit': {
        'enabled': True,
        'run_on_manual': False,  # only uses cache on manual run
        'run_on_schedule': True, # full scrape on scheduled run
    },
}

# Stability guardrails
MAX_EXTERNAL_CALLS_PER_RUN = 60
MAX_ITEMS_PER_DAY = 10
GLOBAL_MIN_DELAY_SECONDS = 5  # minimum delay between any external calls
PERMIT_CACHE_TTL_HOURS = 24
