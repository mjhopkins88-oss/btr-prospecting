"""
Tracked-link construction for Pilot Campaign Control Center targets.
Pure — no DB access, no side effects. The tracked URL is derived fresh
from the campaign's page_variant + utm_* fields plus the target's own
tracking_token every time it's needed (never stored redundantly on the
target row), so a future URL-format change never orphans existing rows.

No PII in the URL — only the token, offer slug, and UTM parameters (all
of which are already non-sensitive marketing metadata elsewhere in this
app). Company/contact/email never appear in a generated link.
"""
from typing import Any, Dict, Optional
from urllib.parse import urlencode


def build_tracked_url(campaign: Dict[str, Any], tracking_token: str, base_url: Optional[str] = None) -> str:
    """`campaign` is a get_campaign()-shaped dict. Returns a relative
    path (e.g. /mf-review/acquisition?t=...&utm_source=...) unless
    `base_url` is given, in which case it's prefixed with an absolute
    origin (for a copy-to-clipboard link in the UI)."""
    params = {'t': tracking_token}
    for key in ('utm_source', 'utm_medium', 'utm_campaign'):
        value = campaign.get(key)
        if value:
            params[key] = value
    query = urlencode(params)
    path = f"/mf-review/{campaign['page_variant']}?{query}"
    return f'{base_url.rstrip("/")}{path}' if base_url else path
