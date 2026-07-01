"""
Identity-key normalization for lead matching.

Pure string helpers — no DB, no scoring. Turns the messy fields on a lead
(email, phone, company name, property name, city/state, source URL,
landing page, campaign) into normalized keys the match engine can compare.
Reused by dedupe and the match engine alike.
"""
import re
from typing import List, Optional, Set

from multifamily.types import MultifamilyLead

# Free email providers are NOT company domains — two gmail users are not the
# same company, so we don't derive a domain key from these.
_FREE_EMAIL_DOMAINS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com',
    'outlook.com', 'live.com', 'aol.com', 'icloud.com', 'me.com', 'protonmail.com',
    'msn.com', 'comcast.net', 'att.net', 'verizon.net',
}

# Pure legal-entity suffixes to strip from company names (NOT distinguishing
# words like Holdings/Group/Partners/Capital/Realty/Residential).
_COMPANY_SUFFIXES = {
    'llc', 'l.l.c', 'llp', 'lp', 'l.p', 'inc', 'incorporated', 'corp',
    'corporation', 'co', 'company', 'ltd', 'limited', 'plc',
}

# Generic multifamily property nouns dropped for the *fuzzy* property key.
_PROPERTY_NOUNS = {
    'apartments', 'apartment', 'apts', 'apt', 'residences', 'residence',
    'lofts', 'flats', 'commons', 'community', 'communities', 'homes', 'place',
    'the', 'at', 'property', 'properties',
}

_WORD_RE = re.compile(r'[a-z0-9]+')


def normalize_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    e = str(email).strip().lower()
    return e if '@' in e else None


def normalize_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None
    digits = re.sub(r'\D', '', str(phone))
    if not digits:
        return None
    # US numbers: compare on the last 10 digits (drop a leading country code).
    return digits[-10:] if len(digits) >= 10 else digits


def domain_from_email(email: Optional[str]) -> Optional[str]:
    e = normalize_email(email)
    if not e:
        return None
    domain = e.split('@', 1)[1].strip()
    if not domain or domain in _FREE_EMAIL_DOMAINS:
        return None
    return domain


def _tokens(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return _WORD_RE.findall(str(text).lower())


def normalize_company(name: Optional[str]) -> Optional[str]:
    toks = [t for t in _tokens(name) if t not in _COMPANY_SUFFIXES]
    return ' '.join(toks) or None


def company_tokens(name: Optional[str]) -> Set[str]:
    return {t for t in _tokens(name) if t not in _COMPANY_SUFFIXES}


def normalize_property(name: Optional[str]) -> Optional[str]:
    toks = _tokens(name)
    return ' '.join(toks) or None


def normalize_property_fuzzy(name: Optional[str]) -> Optional[str]:
    toks = [t for t in _tokens(name) if t not in _PROPERTY_NOUNS]
    return ' '.join(toks) or None


def normalize_text(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return str(value).strip().lower() or None


def token_jaccard(a: Optional[str], b: Optional[str]) -> float:
    """Token-set Jaccard similarity of two company names (0..1)."""
    ta, tb = company_tokens(a), company_tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def lead_emails(lead: MultifamilyLead) -> Set[str]:
    return {e for e in (normalize_email(c.email) for c in (lead.contacts or [])) if e}


def lead_phones(lead: MultifamilyLead) -> Set[str]:
    return {p for p in (normalize_phone(c.phone) for c in (lead.contacts or [])) if p}


def lead_contact_names(lead: MultifamilyLead) -> Set[str]:
    return {normalize_text(c.full_name) for c in (lead.contacts or []) if normalize_text(c.full_name)}


def lead_domains(lead: MultifamilyLead) -> Set[str]:
    domains = {d for d in (domain_from_email(c.email) for c in (lead.contacts or [])) if d}
    if lead.company and lead.company.domain:
        d = normalize_text(lead.company.domain)
        if d:
            domains.add(d)
    return domains
