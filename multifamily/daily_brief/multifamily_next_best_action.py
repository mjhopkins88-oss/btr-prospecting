"""
Next-best-action logic for a single multifamily lead, driven by score
category and signal type.
"""
from multifamily.types import MultifamilyLead

_CATEGORY_ACTIONS = {
    'call_today': 'Call within the hour — this is a live inbound signal.',
    'hot': 'Send a personalized email today and follow with a LinkedIn touch.',
    'warm': 'Add to the active nurture sequence; follow up within the week.',
    'nurture': 'Add to the long-cycle nurture track; revisit in 30 days.',
    'watchlist': 'Monitor only — insufficient signal for outreach yet.',
}


def next_best_action_for_lead(lead: MultifamilyLead) -> str:
    if lead.score is None:
        return 'Score this lead before taking action.'
    if lead.score.disqualified:
        return f'Needs more info — {lead.score.disqualified_reason or "missing required data"}.'
    return _CATEGORY_ACTIONS.get(lead.score.category, _CATEGORY_ACTIONS['watchlist'])
