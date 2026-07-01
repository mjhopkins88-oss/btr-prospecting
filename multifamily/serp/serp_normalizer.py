"""
Normalizes a raw SERP result ({title, link, snippet, source, date} — the
shape serpapi_client.serpapi_search()/cached_serpapi_search() already
return) into either a rejection (with reason codes explaining why) or a
contactless trigger payload compatible with
multifamily.intake_trigger.build_lead_from_trigger (used via
multifamily.ingest.ingest_trigger_signal/ingest_trigger_batch).

Deterministic, heuristic-only — no LLM call, so this is offline-testable,
free to run, and conservative: every decision (accept or reject) carries
reason codes, and company/property-name extraction is a best-effort guess
from the title, not a promise of accuracy (SERP-only leads land as
low-confidence trigger leads regardless — see resistance_risk_detector.py
and the scoring engine's existing quality gates).
"""
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from multifamily.serp.query_templates import SerpQueryConfig, STATE_NAMES, signal_type_for_category

_MULTIFAMILY_ANCHORS = [
    'multifamily', 'multi-family', 'apartment community', 'apartment communities',
    'apartments', 'apartment',
]

_CATEGORY_KEYWORDS = {
    'acquisition': ['acquisition', 'acquired', 'acquires', 'purchased', 'buys', 'bought', 'sale closes', 'new owner'],
    'financing': ['construction loan', 'financing', 'refinance', 'refinancing', 'bridge loan', 'agency financing', 'hud', 'fannie', 'freddie'],
    'construction': ['breaks ground', 'groundbreaking', 'starts construction', 'under construction', 'building permit', 'construction loan closes'],
    'completion': ['opens', 'completes', 'lease-up', 'lease up', 'starts leasing', 'now leasing', 'grand opening'],
    'insurance_pressure': ['insurance cost', 'insurance costs', 'insurance premium', 'insurance premiums', 'insurance pressure', 'habitational insurance', 'insurance renewal'],
    'general_multifamily': [],  # anchor alone is enough — no category keyword required
}

_JOB_POSTING_MARKERS = ['now hiring', 'job opening', 'apply now', "we're hiring", 'career opportunity', 'job description']
_AD_MARKERS = ['sponsored', 'advertisement']
_DIRECTORY_DOMAINS = {
    'apartments.com', 'zillow.com', 'realtor.com', 'trulia.com', 'rent.com',
    'apartmentguide.com', 'rentcafe.com', 'forrent.com',
}
_SINGLE_FAMILY_MARKERS = ['single-family home', 'single family home', 'single-family house', 'single family house']

_TITLE_SEPARATORS = re.compile(r'\s[-|:–—]\s')
_PROPERTY_NAME_PATTERN = re.compile(
    r"([A-Z][\w'&. ]{2,60}?\s(?:Apartments|Apartment Community|Residences|Commons|Gardens|Court|Village|Flats))"
)
# Real estate headlines overwhelmingly follow "<Company> <verb> <deal>"
# ("X Acquires Y", "X Secures Financing For Y", "X Breaks Ground On Y").
# When a title has no punctuation separator, splitting at the first such
# verb is a much better company-name guess than falling back to the
# entire sentence.
_ACTION_VERB_PATTERN = re.compile(
    r'\b(?:acquires|acquired|buys|bought|purchases|purchased|secures|secured|'
    r'closes|opens|breaks ground|files for|obtains|wins|refinances|refinanced|'
    r'completes|announces)\b',
    re.IGNORECASE,
)

_RELATIVE_DATE_PATTERN = re.compile(r'(\d+)\s+(day|week|month|year)s?\s+ago', re.IGNORECASE)
_ABSOLUTE_DATE_FORMATS = ('%b %d, %Y', '%B %d, %Y', '%Y-%m-%d')
_DAYS_PER_UNIT = {'day': 1, 'week': 7, 'month': 30, 'year': 365}


def _domain_from_url(url: str) -> str:
    m = re.match(r'^https?://([^/]+)', url or '')
    if not m:
        return ''
    domain = m.group(1).lower()
    return domain[4:] if domain.startswith('www.') else domain


def _text_of(raw: Dict[str, Any]) -> str:
    return f"{raw.get('title', '')} {raw.get('snippet', '')}".lower()


def _within_lookback(raw: Dict[str, Any], lookback_days: int) -> bool:
    """Best-effort — an unparseable or absent date is never used to
    reject a result (we can't verify age either way, so it isn't
    punished); only a date we can confidently parse as too old rejects."""
    date_str = (raw.get('date') or '').strip()
    if not date_str:
        return True
    m = _RELATIVE_DATE_PATTERN.match(date_str)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        return (n * _DAYS_PER_UNIT.get(unit, 30)) <= lookback_days
    for fmt in _ABSOLUTE_DATE_FORMATS:
        try:
            d = datetime.strptime(date_str, fmt)
            return (datetime.utcnow() - d) <= timedelta(days=lookback_days)
        except ValueError:
            continue
    return True


def classify_relevance(raw: Dict[str, Any], config: SerpQueryConfig) -> Tuple[bool, List[str], float]:
    """Return (accept, reason_codes, confidence). reason_codes always
    explain the decision: MATCHED_* codes for what drove acceptance,
    REJECTED_* codes for why a result was dropped."""
    text = _text_of(raw)
    url = raw.get('link') or raw.get('url') or ''
    domain = _domain_from_url(url)

    if any(m in text for m in _JOB_POSTING_MARKERS):
        return False, ['REJECTED_JOB_POSTING'], 0.0
    if any(m in text for m in _AD_MARKERS):
        return False, ['REJECTED_AD_CONTENT'], 0.0
    if domain in _DIRECTORY_DOMAINS:
        return False, ['REJECTED_DIRECTORY_DOMAIN', f'domain={domain}'], 0.0
    if any(m in text for m in _SINGLE_FAMILY_MARKERS) and not any(a in text for a in _MULTIFAMILY_ANCHORS):
        return False, ['REJECTED_SINGLE_FAMILY_ONLY'], 0.0
    if not any(a in text for a in _MULTIFAMILY_ANCHORS):
        return False, ['REJECTED_NO_MULTIFAMILY_ANCHOR'], 0.0

    reasons = ['MATCHED_MULTIFAMILY_ANCHOR']

    category_kw = _CATEGORY_KEYWORDS.get(config.category, [])
    matched_kw = next((kw for kw in category_kw if kw in text), None)
    if category_kw and not matched_kw:
        return False, ['REJECTED_NO_CATEGORY_KEYWORD_MATCH', f'category={config.category}'], 0.0
    if matched_kw:
        reasons.append(f'MATCHED_CATEGORY_KEYWORD:{matched_kw}')

    if not _within_lookback(raw, config.lookback_days):
        return False, reasons + ['REJECTED_OUTSIDE_LOOKBACK_WINDOW'], 0.0

    confidence = 0.4
    if matched_kw:
        confidence += 0.2
    state_name = STATE_NAMES.get(config.state, config.state).lower()
    if state_name in text or config.state.lower() in text:
        confidence += 0.1
        reasons.append('MATCHED_STATE_MENTION')
    confidence = round(min(confidence, 0.9), 2)

    if confidence < config.confidence_threshold:
        return False, reasons + ['REJECTED_LOW_CONFIDENCE', f'confidence={confidence}'], confidence

    return True, reasons, confidence


def _guess_company_name(title: str) -> Optional[str]:
    """Best-effort only — takes the first segment before a common title
    separator; if there isn't one, splits at the first recognized deal
    verb instead. Never treated as a confirmed identity; matching/merge
    still applies its normal fuzzy-vs-auto tiers downstream."""
    if not title:
        return None
    parts = _TITLE_SEPARATORS.split(title)
    candidate = (parts[0] if parts else title).strip()
    if candidate == title.strip():
        m = _ACTION_VERB_PATTERN.search(candidate)
        if m and m.start() > 0:
            candidate = candidate[:m.start()].strip()
    return candidate[:200] or None


def _guess_property_name(title: str) -> Optional[str]:
    """Best-effort only — looks for a common apartment-property naming
    pattern ("X Apartments", "X Gardens", etc.). None if no such pattern
    is found; build_lead_from_trigger falls back to "<company> Property"."""
    if not title:
        return None
    m = _PROPERTY_NAME_PATTERN.search(title)
    return m.group(1).strip() if m else None


def normalize_result(
    raw: Dict[str, Any], config: SerpQueryConfig, search_query: str,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Return (payload | None, reason_codes). payload is compatible with
    multifamily.intake_trigger.build_lead_from_trigger; None means
    rejected — reason_codes explains why either way."""
    accept, reasons, confidence = classify_relevance(raw, config)
    if not accept:
        return None, reasons

    title = (raw.get('title') or '').strip()
    url = raw.get('link') or raw.get('url') or ''
    domain = _domain_from_url(url)
    company_guess = _guess_company_name(title)

    payload = {
        'company': company_guess or f'Unknown company ({domain or "serp"})',
        'state': config.state,
        'city': config.city,
        'propertyName': _guess_property_name(title),
        'source': config.source_name,
        'signalType': signal_type_for_category(config.category),
        'sourceUrl': url,
        'sourcePage': title[:300] if title else None,
        'searchCategory': config.category,
        'searchQuery': search_query,
        'publishedDate': raw.get('date') or None,
        'confidence': confidence,
        'notes': (raw.get('snippet') or '')[:2000] or None,
    }
    return payload, reasons
