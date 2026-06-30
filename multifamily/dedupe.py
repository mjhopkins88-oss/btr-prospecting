"""
Duplicate-lead merging.

Quality rule: "Duplicate leads should be merged by company + property +
city + state + source." Merging combines signals, contacts, and pain/
relationship flags, and keeps the most recently verified core fields.
"""
from typing import List

from multifamily.types import MultifamilyLead


def _dedupe_key(lead: MultifamilyLead):
    return (
        (lead.company.name or '').strip().lower(),
        (lead.property.name or '').strip().lower(),
        (lead.city or '').strip().lower(),
        (lead.state or '').strip().lower(),
        lead.primary_source,
    )


def dedupe_leads(leads: List[MultifamilyLead]) -> List[MultifamilyLead]:
    merged: "dict[tuple, MultifamilyLead]" = {}

    for lead in leads:
        key = _dedupe_key(lead)
        existing = merged.get(key)
        if existing is None:
            merged[key] = lead
            continue

        existing.signals.extend(s for s in lead.signals if s.id not in {x.id for x in existing.signals})
        existing.contacts.extend(c for c in lead.contacts if c.id not in {x.id for x in existing.contacts})
        existing.pain_flags = sorted(set(existing.pain_flags) | set(lead.pain_flags))
        existing.relationship_flags = sorted(set(existing.relationship_flags) | set(lead.relationship_flags))
        existing.confidence = max(existing.confidence, lead.confidence)
        if lead.last_verified_at > existing.last_verified_at:
            existing.last_verified_at = lead.last_verified_at
        if not existing.source_url and lead.source_url:
            existing.source_url = lead.source_url

    return list(merged.values())
