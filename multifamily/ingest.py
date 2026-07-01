"""
Multifamily Command — generic signal ingest (integration readiness, Phase E).

`ingest_signal(payload, source=...)` is the single headless entry point a
future automated collector (ads lead forms, Search Console, permits, news,
CRM renewals, a webhook, a manual-note tool) calls to push one signal into
the real-lead layer. It runs the exact same build → spam/quality gate →
match → merge-or-create pipeline as the public `POST /api/multifamily/leads`
route, but without any Flask request context, and wraps every call in a
persisted source-run so the ingest is auditable.

Hard boundaries (identical to the intake route):
  * Rejected / honeypot / garbage signals are persisted for audit but NEVER
    matched, merged, or used to strengthen an existing lead.
  * Only high-confidence exact matches auto-merge; everything fuzzy creates
    the lead and raises a manual-review match candidate.
  * Scoring math is untouched — signals merely combine as inputs.
  * No external calls, no scraping, no paid APIs — a collector is responsible
    for producing the `payload` dict; this module only persists/merges it.

`ingest_batch(...)` runs many payloads under ONE source-run (the shape a
scheduled collector uses). `dry_run_collector(...)` routes an existing mock
collector's output through the pipeline once to prove the path end-to-end.
"""
from typing import Any, Dict, List, Optional, Tuple

from multifamily import repository, matching as mf_matching, spam_guard
from multifamily.intake import build_lead_from_intake
from multifamily.snapshots import snapshot_lead


def _ingest_one(payload: Dict[str, Any], *, default_source: str) -> Dict[str, Any]:
    """Build + gate + match + merge/create a single payload. Returns a
    per-record result dict (no source-run bookkeeping — the caller owns that
    so a batch can share one run)."""
    result = {
        'action': None,          # 'created' | 'merged' | 'rejected' | 'invalid'
        'lead_id': None,
        'merged_into': None,
        'review_candidates': 0,
        'spam_status': None,
        'errors': [],
    }

    # Server-side spam/quality gate — same classifier the public route uses.
    spam_status, spam_reason_codes = spam_guard.classify_spam(payload)
    result['spam_status'] = spam_status

    lead, errors = build_lead_from_intake(
        payload, spam_status=spam_status, spam_reason_codes=spam_reason_codes,
    )
    if errors:
        result['action'] = 'invalid'
        result['errors'] = errors
        return result

    # Make sure the signal carries a source label so the timeline/attribution
    # is attributable even when the collector didn't set one explicitly.
    src = (payload.get('source') or default_source)
    for sig in (lead.signals or []):
        if not sig.source:
            sig.source = src
    if not lead.primary_source:
        lead.primary_source = src

    if spam_status == 'rejected':
        # Persisted for audit only — never matched/merged/strengthened.
        repository.insert_lead(lead)
        repository.persist_lead_signals(lead)
        repository.record_lead_attribution_touch(lead, touch_type='first')
        result.update(action='rejected', lead_id=lead.id)
        return result

    classified = mf_matching.classify(lead, repository.get_real_leads())
    auto = classified.get('auto')
    if auto:
        mf_matching.merge_incoming_on_intake(auto.lead, lead)
        # An automated collector folding a new signal onto an already-known
        # lead is a distinct snapshot moment from a human-facing dedupe
        # merge (create_lead's auto-merge / admin-confirmed merge) — both
        # re-score the survivor the same way, just via different callers.
        snapshot_lead(auto.lead, 'signal_added')
        result.update(action='merged', lead_id=auto.lead.id, merged_into=auto.lead.id)
        return result

    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    primary_sig_id = lead.signals[0].id if lead.signals else None
    for cand in classified.get('review', []):
        repository.insert_match_candidate(
            incoming_signal_id=primary_sig_id, candidate_lead_id=cand.lead.id,
            match_tier='review', match_reasons=cand.reasons, score=cand.score,
            incoming_lead_id=lead.id,
        )
        result['review_candidates'] += 1
    snapshot_lead(lead, 'created')
    result.update(action='created', lead_id=lead.id)
    return result


def ingest_signal(payload: Dict[str, Any], *, source: str = 'ingest') -> Dict[str, Any]:
    """Ingest a single signal payload under its own persisted source-run.

    Returns the per-record result plus `run_id`/`run_db_id` so a caller can
    correlate it with the row in `multifamily_source_runs`."""
    run = repository.start_source_run(source)
    try:
        rec = _ingest_one(payload, default_source=source)
        status = 'success' if rec['action'] in ('created', 'merged') else 'partial'
        repository.finish_source_run(
            run['id'], status=status,
            records_found=1,
            records_created=1 if rec['action'] == 'created' else 0,
            records_merged=1 if rec['action'] == 'merged' else 0,
            records_rejected=1 if rec['action'] in ('rejected', 'invalid') else 0,
            errors=rec['errors'] or None,
        )
    except Exception as exc:  # a bad payload must never leave a dangling 'running' run
        repository.finish_source_run(run['id'], status='error', records_found=1,
                                     records_rejected=1, errors=[str(exc)])
        raise
    rec['run_db_id'] = run['id']
    rec['run_id'] = run['run_id']
    return rec


def ingest_batch(payloads: List[Dict[str, Any]], *, source: str = 'ingest') -> Dict[str, Any]:
    """Ingest many payloads under ONE source-run (the shape a scheduled
    collector uses). Individual bad payloads are counted, not fatal."""
    run = repository.start_source_run(source)
    created = merged = rejected = 0
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    for payload in payloads:
        try:
            rec = _ingest_one(payload, default_source=source)
        except Exception as exc:
            rejected += 1
            errors.append(str(exc))
            records.append({'action': 'error', 'errors': [str(exc)]})
            continue
        records.append(rec)
        if rec['action'] == 'created':
            created += 1
        elif rec['action'] == 'merged':
            merged += 1
        elif rec['action'] in ('rejected', 'invalid'):
            rejected += 1
            errors.extend(rec['errors'])
    status = 'success' if not errors else 'partial'
    repository.finish_source_run(
        run['id'], status=status, records_found=len(payloads),
        records_created=created, records_merged=merged, records_rejected=rejected,
        errors=errors or None,
    )
    return {
        'run_db_id': run['id'], 'run_id': run['run_id'], 'source': source,
        'records_found': len(payloads), 'records_created': created,
        'records_merged': merged, 'records_rejected': rejected,
        'records': records,
    }


def _lead_to_ingest_payload(lead) -> Dict[str, Any]:
    """Flatten an in-memory MultifamilyLead (e.g. a mock-collector output)
    into the flat intake payload shape `build_lead_from_intake` expects.
    Used only by the dry-run harness — real collectors emit payloads
    directly."""
    contact = (lead.contacts or [None])[0]
    sig = (lead.signals or [None])[0]
    situation = None
    if sig and (sig.detail or {}).get('lead_situation'):
        situation = sig.detail['lead_situation']
    return {
        'name': (contact.full_name if contact else None) or 'Unknown',
        'company': lead.company.name,
        'email': (contact.email if contact else None),
        'phone': (contact.phone if contact else None),
        'role': (contact.title if contact else None),
        'state': lead.state or (lead.property.state if lead.property else None),
        'city': lead.city or (lead.property.city if lead.property else None),
        'assetType': lead.property.asset_type if lead.property else None,
        'numberOfUnits': lead.property.unit_count if lead.property else None,
        'leadSituation': situation or 'benchmark',
        'source': lead.primary_source or 'ingest',
        'sourcePage': lead.source_page,
        'sourceUrl': lead.source_url,
    }


def dry_run_collector(collector_fn, *, source: str) -> Dict[str, Any]:
    """Route a collector's output through the ingest pipeline once, as a
    proof-of-path. `collector_fn` returns a list of in-memory
    MultifamilyLead objects (the existing mock collectors' contract). Returns
    the batch summary. NOTE: this persists real leads — callers in tests must
    clean up. No external calls are made here; the collector is responsible
    for whatever it does to produce leads."""
    leads = collector_fn() or []
    payloads = [_lead_to_ingest_payload(l) for l in leads]
    return ingest_batch(payloads, source=source)
