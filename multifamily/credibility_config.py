"""
Credibility block config — Section 8 item 7 of the strategy research
doc. One config the operator fills once; all six /mf-review/<slug>
offer pages render the same shared block from it (multifamily/forms/
form_variants.py already owns the per-offer deliverable/turnaround
copy from item 5 — this module owns the copy that is IDENTICAL across
every offer page: proof line, market access, license, associations,
who's behind it, and the privacy note).

Every fact that must come from the operator (figures, license number,
memberships, name/title/photo) is a clearly marked [PLACEHOLDER] string
below — never invented. Copy that describes how the *process* works
(no BOR change required, what happens next, the privacy commitment) is
authored directly since it describes this app's actual behavior, not a
claim about the operator that needs separate verification.

Overridable at runtime via the MULTIFAMILY_CREDIBILITY_CONFIG_JSON env
var (a JSON object shallow-merged on top of the defaults), so an
operator can fill in the real facts via deploy config without a code
change — mirrors signalstack/sender_persona.py's override pattern.
"""
import json
import os
from typing import Optional


DEFAULT_CREDIBILITY_CONFIG: dict = {
    "proof_line": "[PLACEHOLDER: e.g. '$XXM in multifamily TIV placed across CA/TX' — operator to confirm exact units/TIV figure]",
    "market_access_line": "[PLACEHOLDER: E&S + admitted market access — operator to confirm carrier/market list]",
    "no_bor_change_line": "No broker-of-record change required to run this.",
    "what_happens_next_steps": [
        "You share the handful of details on this page — nothing else needed to start.",
        "We put together your named deliverable and get it back to you within the promised turnaround.",
        "If it's useful, we schedule a short walkthrough — no obligation either way.",
    ],
    "ca_license_number": "[PLACEHOLDER: CA license #]",
    "association_memberships": [
        "[PLACEHOLDER: e.g. CAA supplier/industry partner — confirm actual memberships]",
    ],
    "representative_name": "[PLACEHOLDER: representative name]",
    "representative_title": "[PLACEHOLDER: representative title]",
    "representative_photo_url": "[PLACEHOLDER: representative photo URL/asset path]",
    "privacy_note": (
        "Requesting this review does not block your property from any market or carrier, "
        "and we don't share your information with third parties."
    ),
}

_ENV_VAR = "MULTIFAMILY_CREDIBILITY_CONFIG_JSON"


def _load_env_override() -> Optional[dict]:
    raw = os.getenv(_ENV_VAR)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception as e:
        print(f"[Multifamily] credibility_config: ignoring invalid {_ENV_VAR} JSON: {type(e).__name__}: {e}")
        return None
    if not isinstance(data, dict):
        return None
    return data


def _shallow_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if v in (None, ""):
            continue
        out[k] = v
    return out


def get_credibility_config() -> dict:
    """Return the active credibility block config, applying env overrides."""
    override = _load_env_override()
    if not override:
        return dict(DEFAULT_CREDIBILITY_CONFIG)
    return _shallow_merge(DEFAULT_CREDIBILITY_CONFIG, override)


def placeholder_fields() -> list:
    """Names of every field still holding a [PLACEHOLDER] value awaiting
    operator input, in the currently active (possibly env-overridden)
    config — used by the admin surface and by the build summary."""
    cfg = get_credibility_config()
    fields = []
    for key, value in cfg.items():
        values = value if isinstance(value, list) else [value]
        if any(isinstance(v, str) and '[PLACEHOLDER' in v for v in values):
            fields.append(key)
    return fields
