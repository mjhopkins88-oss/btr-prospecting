"""
Multifamily SERP query templates — parameterized by category and
state/city so queries are configurable DATA, not strings scattered
through the collector/route/UI code. Adding a category or a state means
editing this file only.
"""
from dataclasses import dataclass
from typing import List, Optional

SERP_CATEGORIES = [
    'acquisition', 'financing', 'construction', 'completion',
    'insurance_pressure', 'general_multifamily',
]

# v1 launch states — mirrors multifamily.types.SUPPORTED_STATES. A result
# from outside this list still scores (it just takes the existing
# PENALTY_UNKNOWN_STATE hit like any other out-of-footprint lead), so
# expanding here is a data change only, never a scoring-math change.
SERP_LAUNCH_STATES = ['CA', 'TX']

# Future expandable states — supported by the query templates already;
# not yet surfaced as launch defaults in the admin UI.
SERP_FUTURE_STATES = ['AZ', 'FL', 'GA', 'NC', 'SC', 'TN', 'CO', 'NV']

SERP_ALL_STATES = SERP_LAUNCH_STATES + SERP_FUTURE_STATES

STATE_NAMES = {
    'CA': 'California', 'TX': 'Texas', 'AZ': 'Arizona', 'FL': 'Florida',
    'GA': 'Georgia', 'NC': 'North Carolina', 'SC': 'South Carolina',
    'TN': 'Tennessee', 'CO': 'Colorado', 'NV': 'Nevada',
}

# Which existing (or SERP-specific zero-weight) signal_type a category
# maps to. acquisition/financing/construction/completion reuse the exact
# same types the rest of the scoring/timing engine already understands;
# insurance_pressure/general_multifamily use the two zero-weight types
# added in Phase A (multifamily/types.py) since no natural existing type
# fits and neither should ever carry scoring points.
CATEGORY_SIGNAL_TYPE = {
    'acquisition': 'acquisition',
    'financing': 'financing',
    'construction': 'groundbreaking',
    'completion': 'completion',
    'insurance_pressure': 'insurance_market_pressure',
    'general_multifamily': 'market_mention',
}

# Query templates per category. Only {state} is a template slot (the full
# state name, for better search-engine matching than the 2-letter code);
# an optional city is appended as its own quoted term by build_queries()
# rather than baked into every template string.
_TEMPLATES = {
    'acquisition': [
        'multifamily acquisition "{state}" apartment community',
        'apartment acquisition "{state}" purchased community',
        'acquired apartment portfolio "{state}"',
        'multifamily sale closes "{state}"',
        'new owner apartment community "{state}"',
    ],
    'financing': [
        'multifamily construction loan "{state}"',
        'apartment construction financing "{state}"',
        'multifamily refinance "{state}"',
        'bridge loan apartment community "{state}"',
        'agency financing apartment property "{state}"',
        '(HUD OR Fannie OR Freddie) multifamily financing "{state}"',
    ],
    'construction': [
        'multifamily development breaks ground "{state}"',
        'apartment project starts construction "{state}"',
        'multifamily building permit "{state}"',
        'apartment construction loan closes "{state}"',
        'mixed-use apartment development "{state}"',
    ],
    'completion': [
        'apartment community opens "{state}"',
        'multifamily development completes "{state}"',
        'apartment lease-up begins "{state}"',
        'new apartment community starts leasing "{state}"',
    ],
    'insurance_pressure': [
        'apartment portfolio insurance costs "{state}"',
        'multifamily insurance premiums "{state}"',
        'property insurance pressure multifamily "{state}"',
        'habitational insurance costs "{state}"',
        'insurance renewal issues apartment owners "{state}"',
    ],
    'general_multifamily': [
        'multifamily market "{state}" apartment news',
    ],
}


@dataclass
class SerpQueryConfig:
    category: str
    state: str
    city: Optional[str] = None
    lookback_days: int = 30
    limit: int = 10
    source_name: str = 'serp'
    confidence_threshold: float = 0.35

    def __post_init__(self):
        if self.category not in SERP_CATEGORIES:
            raise ValueError(f'category must be one of {SERP_CATEGORIES} (got {self.category!r})')
        if not self.state or self.state.upper() not in SERP_ALL_STATES:
            raise ValueError(f'state must be one of {SERP_ALL_STATES} (got {self.state!r})')
        self.state = self.state.upper()


def build_queries(config: SerpQueryConfig) -> List[str]:
    """Return the fully-parameterized query strings for one config."""
    state_name = STATE_NAMES.get(config.state, config.state)
    templates = _TEMPLATES.get(config.category, [])
    queries = []
    for template in templates:
        q = template.format(state=state_name)
        if config.city:
            q = f'{q} "{config.city}"'
        queries.append(q)
    return queries


def signal_type_for_category(category: str) -> str:
    return CATEGORY_SIGNAL_TYPE.get(category, 'market_mention')
