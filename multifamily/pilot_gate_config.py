"""
Pilot gate thresholds (Phase E) — Strategy Research §5.3's 4 pilot-launch
gates, expressed as config rather than hardcoded in the scorecard/UI code:
delivery_rate, reply_rate, positive_share, meetings-per-50-targets. One
place to tune a threshold without touching evaluate_gates()' logic.

Overridable at runtime via the MULTIFAMILY_PILOT_GATE_CONFIG_JSON env var
(a JSON object shallow-merged on top of the defaults) — same pattern as
multifamily/credibility_config.py.
"""
import json
import os
from typing import Any, Dict, Optional

DEFAULT_PILOT_GATE_CONFIG: dict = {
    # Green at or above 97% delivered (touch_1_sent - bounced). No amber
    # band called for in the strategy doc -- delivery is either healthy
    # or a data-quality problem worth flagging red.
    'delivery_rate_green_min': 0.97,
    # Green at/above 8%, amber in the 6-8% band, red below 6%.
    'reply_rate_green_min': 0.08,
    'reply_rate_amber_min': 0.06,
    # Green at or above 40% of replies being positive/referral.
    'positive_share_green_min': 0.40,
    # Meetings should land in a 1-3 per 50 targets band, prorated for
    # campaigns with a different target count (e.g. 2 meetings across
    # 100 targets == 1 per 50, still green).
    'meetings_per_50_band_min': 1.0,
    'meetings_per_50_band_max': 3.0,
}

_ENV_VAR = 'MULTIFAMILY_PILOT_GATE_CONFIG_JSON'


def _load_env_override() -> Optional[dict]:
    raw = os.environ.get(_ENV_VAR)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception as e:
        print(f"[Multifamily] pilot_gate_config: ignoring invalid {_ENV_VAR} JSON: {type(e).__name__}: {e}")
        return None
    if not isinstance(data, dict):
        return None
    return data


def _shallow_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if v is None:
            continue
        out[k] = v
    return out


def get_pilot_gate_config() -> dict:
    """Return the active pilot gate threshold config, applying env overrides."""
    override = _load_env_override()
    if not override:
        return dict(DEFAULT_PILOT_GATE_CONFIG)
    return _shallow_merge(DEFAULT_PILOT_GATE_CONFIG, override)


def _rate_status(value: Optional[float], green_min: float, amber_min: Optional[float] = None) -> Dict[str, Any]:
    """A rate gate (delivery/reply/positive) with no live data yet is
    'unknown', not 'red' -- there's nothing to fail on a campaign that
    hasn't sent anything out."""
    if value is None:
        return {'status': 'unknown', 'value': None}
    if value >= green_min:
        return {'status': 'green', 'value': value}
    if amber_min is not None and value >= amber_min:
        return {'status': 'amber', 'value': value}
    return {'status': 'red', 'value': value}


def evaluate_gates(scorecard: Dict[str, Any], config: Optional[dict] = None) -> Dict[str, Dict[str, Any]]:
    """Given one campaign's scorecard dict (as produced by
    repository.get_campaign_performance()'s conversion_rate_by_campaign
    entries -- carries delivery_rate/reply_rate/positive_share/meetings/
    targets), return a status ('green'|'amber'|'red'|'unknown') + the
    underlying value for each of the 4 pilot gates."""
    cfg = config or get_pilot_gate_config()

    delivery = _rate_status(scorecard.get('delivery_rate'), cfg['delivery_rate_green_min'])
    reply = _rate_status(scorecard.get('reply_rate'), cfg['reply_rate_green_min'], cfg['reply_rate_amber_min'])
    positive = _rate_status(scorecard.get('positive_share'), cfg['positive_share_green_min'])

    targets = scorecard.get('targets') or 0
    meetings = scorecard.get('meetings') or 0
    if targets <= 0:
        meetings_gate = {'status': 'unknown', 'value': None, 'meetings_per_50': None}
    else:
        meetings_per_50 = round(meetings * 50.0 / targets, 2)
        band_min, band_max = cfg['meetings_per_50_band_min'], cfg['meetings_per_50_band_max']
        status = 'green' if band_min <= meetings_per_50 <= band_max else 'red'
        meetings_gate = {'status': status, 'value': meetings_per_50, 'meetings_per_50': meetings_per_50}

    return {
        'delivery_rate': delivery,
        'reply_rate': reply,
        'positive_share': positive,
        'meetings': meetings_gate,
    }
