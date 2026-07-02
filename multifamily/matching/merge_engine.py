"""
Merge engine — combine an incoming lead/signal into a survivor lead.

Reuses the union semantics from multifamily/dedupe.py (signals, contacts,
pain/relationship flags, max confidence, latest verified) but for the
*persisted* real-lead path, and re-runs scoring + explanations so the
survivor strengthens automatically once signals combine. NO scoring-math
change — only the inputs (the combined signals) change.

Two paths:
  - merge_incoming_on_intake(): the incoming lead was built but never
    inserted; fold it into the survivor (no tombstone — it never existed
    as a row).
  - merge_existing(): two persisted rows; fold the loser into the survivor
    and tombstone the loser (reversible via merged_into_id).
"""
from typing import List, Optional, Tuple

from multifamily.types import MultifamilyLead, MultifamilySignal
from multifamily.matching import identity_keys as ik
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.scoring.multifamily_score_explanations import explain_why_warm, explain_likely_pain
from multifamily.daily_brief.multifamily_next_best_action import next_best_action_for_lead
from multifamily.pipeline import build_opener
from multifamily import repository


def _contact_already_present(survivor: MultifamilyLead, contact) -> bool:
    c_email = ik.normalize_email(contact.email)
    c_name = ik.normalize_text(contact.full_name)
    for existing in survivor.contacts or []:
        if c_email and c_email == ik.normalize_email(existing.email):
            return True
        if c_name and c_name == ik.normalize_text(existing.full_name) and not c_email:
            return True
    return False


def _reenrich(lead: MultifamilyLead) -> None:
    """Re-run scoring + timing-aware explanations after the inputs change.
    Mirrors pipeline's per-lead enrichment; scoring math is unchanged."""
    lead.score = score_lead(lead)
    lead.why_warm = explain_why_warm(lead)
    lead.likely_pain = explain_likely_pain(lead)
    lead.suggested_opener = build_opener(lead)
    lead.next_best_action = next_best_action_for_lead(lead)


def apply_merge(survivor: MultifamilyLead, incoming: MultifamilyLead) -> List[MultifamilySignal]:
    """Mutate `survivor` to absorb `incoming`. Returns the list of NEW
    signals added to the survivor (for persistence). Re-scores in place."""
    existing_sig_ids = {s.id for s in survivor.signals}
    new_signals = [s for s in incoming.signals if s.id not in existing_sig_ids]
    survivor.signals.extend(new_signals)

    for contact in (incoming.contacts or []):
        if not _contact_already_present(survivor, contact):
            survivor.contacts.append(contact)

    survivor.pain_flags = sorted(set(survivor.pain_flags) | set(incoming.pain_flags))
    survivor.relationship_flags = sorted(set(survivor.relationship_flags) | set(incoming.relationship_flags))
    survivor.confidence = max(survivor.confidence, incoming.confidence)
    if (incoming.last_verified_at or '') > (survivor.last_verified_at or ''):
        survivor.last_verified_at = incoming.last_verified_at

    # Fill gaps only — keep the survivor's original identity/source.
    # page_variant/campaign_id included per audit finding F5: without
    # them, get_source_performance()'s leads_by_page_variant/
    # leads_by_campaign_id (which read these lead-row columns, not the
    # attribution touch history) could undercount a page-variant/
    # campaign attributed only through a merged-in touch.
    for fld in ('source_url', 'source_page', 'utm_source', 'utm_medium', 'utm_campaign',
                'utm_term', 'utm_content', 'referrer', 'landing_page', 'offer_type', 'notes',
                'page_variant', 'campaign_id'):
        if not getattr(survivor, fld, None) and getattr(incoming, fld, None):
            setattr(survivor, fld, getattr(incoming, fld))
    if (survivor.property.unit_count is None) and incoming.property.unit_count is not None:
        survivor.property.unit_count = incoming.property.unit_count
    if (not survivor.property.asset_type) and incoming.property.asset_type:
        survivor.property.asset_type = incoming.property.asset_type

    _reenrich(survivor)
    return new_signals


def merge_incoming_on_intake(survivor: MultifamilyLead, incoming: MultifamilyLead, touch_type: str = 'touch') -> MultifamilyLead:
    """Auto-merge path: incoming was never persisted. Fold it into the
    survivor, persist the survivor + its new signals + an attribution
    touch (the survivor id, with the incoming's source context). No
    tombstone (incoming never became a row). `touch_type` defaults to
    'touch' (fuzzy/auto identity match); the outbound-link merge-back
    path (Funnel Phase 3) passes 'conversion' since that merge is a
    known, deliberate conversion event, not an incidental identity match."""
    new_signals = apply_merge(survivor, incoming)
    repository.update_lead(survivor)
    for sig in new_signals:
        repository.insert_signal(survivor.id, sig, is_demo=survivor.is_demo, spam_status=survivor.spam_status)
    repository.record_attribution(
        survivor.id, touch_type, source=incoming.primary_source,
        utm_source=incoming.utm_source, utm_medium=incoming.utm_medium, utm_campaign=incoming.utm_campaign,
        utm_term=incoming.utm_term, utm_content=incoming.utm_content, referrer=incoming.referrer,
        landing_page=incoming.landing_page, offer_type=incoming.offer_type,
        page_variant=getattr(incoming, 'page_variant', None), campaign_id=getattr(incoming, 'campaign_id', None),
        occurred_at=incoming.last_verified_at,
    )
    return survivor


def merge_existing(survivor_id: str, loser_id: str) -> Optional[MultifamilyLead]:
    """Manual/confirmed merge of two persisted leads. Folds loser into
    survivor, moves the loser's signals + attribution onto the survivor,
    and tombstones the loser. Returns the re-scored survivor (or None)."""
    survivor = repository.get_lead_by_id(survivor_id)
    loser = repository.get_lead_by_id(loser_id)
    if not survivor or not loser or survivor_id == loser_id:
        return None
    apply_merge(survivor, loser)
    repository.update_lead(survivor)
    repository.reassign_signals(loser_id, survivor_id)
    repository.reassign_attribution(loser_id, survivor_id)
    repository.mark_lead_merged(loser_id, survivor_id)
    return survivor
