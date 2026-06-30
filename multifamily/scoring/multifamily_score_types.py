"""
Score category thresholds and component weight caps for the
Multifamily Lead Score (100 points total).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreCategoryThreshold:
    category: str
    label: str
    min_score: int


# Evaluated highest-first; first threshold the total score clears wins.
SCORE_CATEGORY_THRESHOLDS = [
    ScoreCategoryThreshold('call_today', 'Call Today', 90),
    ScoreCategoryThreshold('hot', 'Hot', 75),
    ScoreCategoryThreshold('warm', 'Warm', 60),
    ScoreCategoryThreshold('nurture', 'Nurture', 40),
    ScoreCategoryThreshold('watchlist', 'Watchlist', 0),
]

CATEGORY_LABELS = {t.category: t.label for t in SCORE_CATEGORY_THRESHOLDS}

# Max points per component — the 100-point model.
MAX_POINTS = {
    'inbound_intent': 40,
    'insurance_timing': 25,
    'account_fit': 20,
    'pain_potential': 10,
    'relationship_warmth': 5,
}


def category_for_score(total: int) -> str:
    for threshold in SCORE_CATEGORY_THRESHOLDS:
        if total >= threshold.min_score:
            return threshold.category
    return 'watchlist'
