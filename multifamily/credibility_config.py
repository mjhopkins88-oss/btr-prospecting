"""
Credibility block config — Section 8 item 7 of the strategy research
doc, now carrying the firm's real branding (Alkeme Insurance / Max
Lyle). One config the operator fills once; all six /mf-review/<slug>
offer pages render the same shared block from it.

Every fact that still needs real input (a photo, a confirmed license
number, association memberships, the official logo asset, an approved
boilerplate line) stays EMPTY or a clearly bracketed [PLACEHOLDER]
string below — never invented — and the rendering layer (both
public_credibility_view() here and static/mf-review.html's
renderCredibilityBlock()) hides any such field entirely rather than
showing "pending"/"coming soon" language. Once a real value is added
(directly here, or via the env override), it renders automatically on
every page — no code change needed on either side.

The official ALKEME logo asset is NOT generated, drawn, or approximated
anywhere in this codebase — company_logo_path stays empty until the
real asset file is dropped into static/ and this path is pointed at it.

Overridable at runtime via the MULTIFAMILY_CREDIBILITY_CONFIG_JSON env
var (a JSON object shallow-merged on top of the defaults) — mirrors
signalstack/sender_persona.py's override pattern.
"""
import json
import os
from typing import Optional


DEFAULT_CREDIBILITY_CONFIG: dict = {
    "company_name": "Alkeme Insurance",
    # Empty until the official ALKEME logo asset is dropped into
    # static/ — never generate/draw/approximate it here.
    "company_logo_path": "",
    # Empty until Alkeme marketing approves a one-line company
    # boilerplate for use on these pages.
    "company_boilerplate": "",
    "proof_line": (
        "Part of ALKEME, a Top 25 U.S. insurance brokerage — with a dedicated "
        "build-to-rent program spanning 20+ carriers, from construction "
        "through lease-up and stabilized operations."
    ),
    "market_access_line": "Admitted and E&S market access nationwide.",
    "no_bor_change_line": "No broker-of-record change required to run this.",
    "what_happens_next_steps": [
        "You share the handful of details on this page — nothing else needed to start.",
        "We put together your named deliverable and get it back to you within the promised turnaround.",
        "If it's useful, we schedule a short walkthrough — no obligation either way.",
    ],
    # List of {"state": "..", "number": ".."}. Empty until a state's
    # license is confirmed — the license line is intentionally absent
    # from public pages until then; adding a real entry here (or via
    # the env override) makes it render with no code change.
    "licenses": [],
    # Hidden entirely while empty.
    "association_memberships": [],
    "representative_name": "Max Lyle",
    "representative_title": "Program Director, Build-to-Rent Insurance, Alkeme Insurance",
    "representative_bio": (
        "Max Lyle leads the Build-to-Rent insurance program at ALKEME — ground-up "
        "rental communities from construction through lease-up and stabilized "
        "operations — and brings the same playbook to conventional multifamily."
    ),
    "representative_photo_url": "[PLACEHOLDER: representative photo URL/asset path]",
    "privacy_note": (
        "Requesting this review does not block your property from any market or carrier, "
        "and we don't share your information with third parties."
    ),
}

_ENV_VAR = "MULTIFAMILY_CREDIBILITY_CONFIG_JSON"

# Simple string fields checked directly against public_credibility_view()'s
# visibility rule (non-empty, no bracketed placeholder token).
_TEXT_FIELDS = (
    'company_name', 'company_logo_path', 'company_boilerplate',
    'proof_line', 'market_access_line', 'no_bor_change_line',
    'representative_name', 'representative_title', 'representative_bio',
    'representative_photo_url', 'privacy_note',
)


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


def _is_visible_text(value) -> bool:
    """A string is safe to render publicly only if it's non-empty and
    carries no bracketed [PLACEHOLDER]-style token. This is the single
    rule every field in the credibility block is filtered through."""
    return isinstance(value, str) and bool(value.strip()) and '[' not in value


def public_credibility_view(cfg: Optional[dict] = None) -> dict:
    """The filtered projection actually safe to render publicly right
    now — mirrors the exact hide-when-empty/hide-when-placeholder rules
    implemented in static/mf-review.html's renderCredibilityBlock(), so
    the invariant ("nothing bracketed or empty ever reaches a public
    page") is unit-testable in Python without a browser."""
    cfg = cfg or get_credibility_config()
    view: dict = {}

    for key in _TEXT_FIELDS:
        if _is_visible_text(cfg.get(key)):
            view[key] = cfg[key]

    steps = [s for s in (cfg.get('what_happens_next_steps') or []) if _is_visible_text(s)]
    if steps:
        view['what_happens_next_steps'] = steps

    licenses = [
        lic for lic in (cfg.get('licenses') or [])
        if isinstance(lic, dict) and _is_visible_text(lic.get('state')) and _is_visible_text(lic.get('number'))
    ]
    if licenses:
        view['licenses'] = licenses

    memberships = [m for m in (cfg.get('association_memberships') or []) if _is_visible_text(m)]
    if memberships:
        view['association_memberships'] = memberships

    return view


def placeholder_fields() -> list:
    """Names of every field still awaiting real operator input — either
    a bracketed [PLACEHOLDER] string or an intentionally-empty
    still-pending value (logo, boilerplate, licenses, memberships) —
    in the currently active (possibly env-overridden) config."""
    cfg = get_credibility_config()
    view = public_credibility_view(cfg)
    fields = []
    for key in (
        'company_logo_path', 'company_boilerplate', 'representative_photo_url',
        'licenses', 'association_memberships',
    ):
        if key not in view:
            fields.append(key)
    return fields
