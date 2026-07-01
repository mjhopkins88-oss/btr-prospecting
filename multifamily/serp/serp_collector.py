"""
Multifamily SERP collector — runs every query template for one
(category, state[, city]) search via the shared BTR SerpAPI client
(serpapi_client.cached_serpapi_search), normalizes + filters results, and
routes accepted ones through the real ingest pipeline
(multifamily.ingest.ingest_trigger_batch) under ONE persisted source-run.

Every result — accepted or rejected — is reported back with its reason
codes; nothing is silently dropped. `search_fn` is injectable (default
cached_serpapi_search) so tests never touch the network / SerpAPI budget,
and so a caller can inject canned fixtures for a proof-of-path run.

No LinkedIn scraping, no other external APIs, nothing auto-sent — this
only calls the same SerpAPI client BTR's discovery already uses, with
`manual=True` (bypasses the shared daily automated-search budget; there is
no scheduling in this phase, only the admin-triggered manual runner).
"""
from typing import Any, Callable, Dict, List, Optional

from multifamily import repository
from multifamily.ingest import ingest_trigger_batch
from multifamily.serp.query_templates import SerpQueryConfig, build_queries
from multifamily.serp.serp_normalizer import normalize_result

try:
    from serpapi_client import cached_serpapi_search as _default_search_fn
    import serpapi_client as _serpapi_client_module
except Exception:  # pragma: no cover - serpapi_client.py is always present in this repo
    _default_search_fn = None
    _serpapi_client_module = None


def _serpapi_key_configured() -> bool:
    """True if serpapi_client has a non-empty SERPAPI_KEY. Checked up
    front so a missing key produces ONE clean error instead of one
    duplicate 'query failed' warning per query template."""
    return bool(_serpapi_client_module is not None and getattr(_serpapi_client_module, 'SERPAPI_KEY', ''))


def _run_query(search_fn: Callable, query: str, config: SerpQueryConfig):
    """Call search_fn defensively — a missing SERPAPI_API_KEY or a
    SerpAPI/network error must never crash a manual admin run; it's
    surfaced as a warning on the run instead."""
    try:
        results = search_fn(
            query, num=config.limit, feature='multifamily_serp',
            city=config.city or '', state=config.state, manual=True,
        )
        return results, None
    except Exception as exc:
        return [], str(exc)


def run_serp_collection(
    config: SerpQueryConfig, *, search_fn: Optional[Callable] = None, dry_run: bool = False,
) -> Dict[str, Any]:
    """Run every query template for `config`, normalize + filter results,
    and (unless dry_run) ingest accepted ones as contactless trigger
    signals under one source-run. Returns a summary an admin UI can
    render directly: found/created/merged/rejected/review_candidates plus
    a per-result breakdown with reason codes for every accept/reject
    decision."""
    search_fn = search_fn or _default_search_fn
    using_default_search_fn = (search_fn is _default_search_fn)
    if search_fn is None or (using_default_search_fn and not _serpapi_key_configured()):
        return {
            'error': 'SERP search is not configured (SERPAPI_API_KEY is not set).',
            'dry_run': dry_run, 'found': 0, 'created': 0, 'merged': 0, 'rejected': 0,
            'review_candidates': 0, 'results': [], 'warnings': [],
            'run_db_id': None, 'run_id': None,
        }

    queries = build_queries(config)
    seen_urls_this_run = set()
    accepted = []  # list of (payload, url)
    result_rows: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for query in queries:
        raw_results, err = _run_query(search_fn, query, config)
        if err:
            warnings.append(f'query failed ({query!r}): {err}')
            continue
        for raw in (raw_results or []):
            url = raw.get('link') or raw.get('url') or ''
            row = {'title': raw.get('title'), 'url': url, 'query': query, 'category': config.category}
            if not url:
                result_rows.append({**row, 'accepted': False, 'reason_codes': ['REJECTED_NO_URL']})
                continue
            if url in seen_urls_this_run:
                # Query templates for the same category routinely overlap
                # and surface the exact same article — this isn't new
                # information (unlike REJECTED_ALREADY_SEEN, a genuinely
                # useful "why nothing happened" signal), so it isn't
                # reported as its own row; it's silently skipped.
                continue
            if repository.is_serp_url_seen(url):
                result_rows.append({**row, 'accepted': False, 'reason_codes': ['REJECTED_ALREADY_SEEN']})
                continue
            seen_urls_this_run.add(url)

            payload, reasons = normalize_result(raw, config, query)
            if payload is None:
                result_rows.append({**row, 'accepted': False, 'reason_codes': reasons})
                continue
            result_rows.append({**row, 'accepted': True, 'reason_codes': reasons, 'confidence': payload['confidence']})
            accepted.append((payload, url))

    if dry_run:
        return {
            'error': None, 'dry_run': True,
            'found': len(result_rows), 'created': 0, 'merged': 0,
            'rejected': len(result_rows) - len(accepted),
            'accepted_would_ingest': len(accepted), 'review_candidates': 0,
            'results': result_rows, 'warnings': warnings,
            'run_db_id': None, 'run_id': None,
        }

    payloads = [p for p, _ in accepted]
    summary = ingest_trigger_batch(payloads, source=config.source_name)

    # Mark every accepted URL seen only AFTER ingest completes, and attach
    # SERP-specific run metadata (category/state/query, plus the TOTAL raw
    # result count — ingest_batch only knows the accepted-for-ingest count).
    for _, url in accepted:
        repository.mark_serp_url_seen(url, category=config.category, state=config.state)
    repository.set_source_run_query_metadata(
        summary['run_db_id'], category=config.category, state=config.state,
        query='; '.join(queries), records_found=len(result_rows),
    )

    review_candidates = sum(r.get('review_candidates', 0) for r in summary['records'])
    return {
        'error': None, 'dry_run': False,
        'found': len(result_rows),
        'created': summary['records_created'], 'merged': summary['records_merged'],
        'rejected': (len(result_rows) - len(payloads)) + summary['records_rejected'],
        'review_candidates': review_candidates,
        'results': result_rows, 'warnings': warnings,
        'run_db_id': summary['run_db_id'], 'run_id': summary['run_id'],
    }
