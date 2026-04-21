"""
Proactive Suggestions module — orchestrator that aggregates daily mission,
quick wins, and momentum into a single compact payload for the assistant.
"""
from services.daily_mission import get_daily_mission
from services.quick_wins import get_quick_wins
from services.momentum import get_momentum_state


def get_proactive_suggestions():
    """Return a compact structured payload with mission, wins, and momentum."""
    try:
        mission = get_daily_mission()
    except Exception:
        mission = []

    try:
        wins = get_quick_wins(limit=3)
    except Exception:
        wins = []

    try:
        momentum = get_momentum_state()
    except Exception:
        momentum = {'level': 'low', 'score': 0}

    return {
        'mission': mission,
        'quick_wins': wins,
        'momentum': momentum
    }
