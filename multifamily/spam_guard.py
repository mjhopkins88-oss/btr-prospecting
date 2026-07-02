"""
Spam/bot protection for the public multifamily lead intake endpoint
(POST /api/multifamily/leads).

Layered defense, in the order the route applies them:
  1. Payload size cap — reject oversized requests before parsing (event
     only, no lead built).
  2. Rate limiting by IP and email, DB-backed via
     multifamily_intake_events so it's correct across process restarts
     and multiple workers (event only, no lead built).
  3. Field validation (multifamily/intake.py) — unchanged, still returns
     clean per-field error messages for legitimate users.
  4. Honeypot + garbage-content heuristics — these do NOT block the
     submission (the bot/spammer still gets a normal-looking success
     response, so we don't tip them off), they just tag the resulting
     lead's spam_status so it's excluded from normal views.

No IP addresses are ever stored in plain text — only a salted,
truncated SHA-256 hash, just enough to correlate repeat submissions.
"""
import hashlib
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from multifamily import repository

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MAX_PAYLOAD_BYTES = 30_000  # generous for a form with a notes field

RATE_LIMIT_IP_MAX = 5
RATE_LIMIT_IP_WINDOW_MINUTES = 60
RATE_LIMIT_EMAIL_MAX = 3
RATE_LIMIT_EMAIL_WINDOW_MINUTES = 60 * 24

# Submission outcomes that count toward rate limits — every attempt that
# got far enough to be evaluated (clean/suspicious/rejected-via-content),
# not ones already blocked by rate limiting itself.
_RATE_LIMITED_EVENT_TYPES = ['accepted_clean', 'accepted_suspicious', 'rejected_honeypot', 'rejected_garbage']

HONEYPOT_FIELD = 'website_url'

_DEFAULT_IP_HASH_SALT = 'btr-multifamily-intake-v1'
_IP_HASH_SALT = os.getenv('MULTIFAMILY_IP_HASH_SALT', _DEFAULT_IP_HASH_SALT)

_URL_PATTERN = re.compile(r'https?://|www\.', re.IGNORECASE)
_REPEATED_CHAR_PATTERN = re.compile(r'(.)\1{9,}')


def ip_hash_salt_is_default() -> bool:
    """True if MULTIFAMILY_IP_HASH_SALT was never set (or was set to the
    exact hardcoded default) — since that default is public in this
    open-source repo, hash_ip()'s output is only as protected as this
    flag being False in production. Never blocks startup or shows
    anything publicly; only surfaces to admins (see the intake-stats
    endpoint) and to the server log below."""
    return _IP_HASH_SALT == _DEFAULT_IP_HASH_SALT


if ip_hash_salt_is_default():
    print(
        '[SECURITY WARNING] MULTIFAMILY_IP_HASH_SALT is not set (or matches the '
        'public repo default) — submitted_ip_hash values are reversible by anyone '
        'who has read this open-source code. Set a real secret for this env var '
        'in production.'
    )


def utc_now_iso() -> str:
    return datetime.utcnow().isoformat()


def _minutes_ago_iso(minutes: int) -> str:
    return (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()


# ---------------------------------------------------------------------------
# Request fingerprinting
# ---------------------------------------------------------------------------

def get_client_ip(headers: Dict[str, str], remote_addr: Optional[str]) -> str:
    """Best-effort real client IP behind a reverse proxy (Railway etc).
    Trusts the first hop of X-Forwarded-For if present, else falls back
    to the direct connection address."""
    forwarded = headers.get('X-Forwarded-For') or headers.get('X-Real-IP')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return remote_addr or 'unknown'


def hash_ip(ip: str) -> str:
    """Salted, truncated hash — never store raw IPs."""
    return hashlib.sha256(f'{_IP_HASH_SALT}:{ip}'.encode()).hexdigest()[:16]


def summarize_user_agent(user_agent: Optional[str]) -> Optional[str]:
    if not user_agent:
        return None
    return user_agent.strip()[:180] or None


# ---------------------------------------------------------------------------
# Payload size
# ---------------------------------------------------------------------------

def check_payload_size(content_length: Optional[int]) -> bool:
    """Return True if the payload is within the allowed size."""
    if content_length is None:
        return True  # can't tell ahead of time; field-length caps in
        # validate_intake() still bound the actual damage.
    return content_length <= MAX_PAYLOAD_BYTES


# ---------------------------------------------------------------------------
# Rate limiting (DB-backed, correct across workers/restarts)
# ---------------------------------------------------------------------------

def check_rate_limit(ip_hash: str, email: Optional[str]) -> Optional[str]:
    """Return a reason code if this IP or email is over its submission
    rate limit, else None."""
    ip_count = repository.count_recent_events(
        _RATE_LIMITED_EVENT_TYPES, _minutes_ago_iso(RATE_LIMIT_IP_WINDOW_MINUTES), ip_hash=ip_hash,
    )
    if ip_count >= RATE_LIMIT_IP_MAX:
        return 'RATE_LIMIT_IP'

    if email:
        email_count = repository.count_recent_events(
            _RATE_LIMITED_EVENT_TYPES, _minutes_ago_iso(RATE_LIMIT_EMAIL_WINDOW_MINUTES), email=email,
        )
        if email_count >= RATE_LIMIT_EMAIL_MAX:
            return 'RATE_LIMIT_EMAIL'

    return None


# ---------------------------------------------------------------------------
# Honeypot
# ---------------------------------------------------------------------------

def check_honeypot(payload: Dict[str, Any]) -> bool:
    """True if the hidden honeypot field was filled in — a near-certain
    sign of an automated submission, since real users never see it."""
    value = payload.get(HONEYPOT_FIELD)
    return bool(value and str(value).strip())


# ---------------------------------------------------------------------------
# Garbage-content heuristics
# ---------------------------------------------------------------------------

def detect_garbage(payload: Dict[str, Any]) -> List[str]:
    """Lightweight heuristics for obviously-junk submissions. Returns a
    list of reason codes (possibly empty). Each is a soft signal —
    callers decide how many of these escalate a lead to 'rejected' vs.
    just 'suspicious'."""
    codes = []
    name = str(payload.get('name') or '')
    company = str(payload.get('company') or '')
    notes = str(payload.get('notes') or '')

    if _URL_PATTERN.search(name):
        codes.append('URL_IN_NAME')
    if _URL_PATTERN.search(company):
        codes.append('URL_IN_COMPANY')
    if len(_URL_PATTERN.findall(notes)) >= 2:
        codes.append('LINK_FLOOD_IN_NOTES')
    if _REPEATED_CHAR_PATTERN.search(name) or _REPEATED_CHAR_PATTERN.search(notes):
        codes.append('REPEATED_CHARACTER_SPAM')
    if name.isupper() and len(name) > 5:
        codes.append('ALL_CAPS_NAME')
    if company.isupper() and len(company) > 5:
        codes.append('ALL_CAPS_COMPANY')

    return codes


def classify_spam(payload: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Run the content-based checks (honeypot + garbage heuristics) and
    return (spam_status, reason_codes). Does NOT check rate limits or
    payload size — those are handled earlier and block the request
    entirely rather than tagging a lead."""
    if check_honeypot(payload):
        return 'rejected', ['HONEYPOT_FILLED']

    garbage_codes = detect_garbage(payload)
    if len(garbage_codes) >= 2:
        return 'rejected', garbage_codes
    if len(garbage_codes) == 1:
        return 'suspicious', garbage_codes
    return 'clean', []
