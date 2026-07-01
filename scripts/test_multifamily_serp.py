#!/usr/bin/env python
"""
SERP Phase B tests: query templates, result normalizer/relevance filter,
and the collector (multifamily/serp/). All offline — every test injects a
fake search_fn; nothing ever calls the network or SerpAPI.

Covers: query templates generate expected queries per category/state;
the normalizer maps an accepted result to a valid trigger payload and
rejects junk (job postings, ads, directory domains, single-family-only,
off-topic, low confidence) with reason codes for both outcomes; the
collector's own seen-URL ledger prevents duplicate ingestion (both across
runs and across query templates within one run); same company/property
strengthens an existing lead via the existing matching engine; a fuzzy
near-match raises a review candidate; the collector logs one source-run
with category/state/query metadata and the TOTAL raw-result count; dry
run persists nothing; and a missing SERPAPI_API_KEY degrades gracefully.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.serp.query_templates import SerpQueryConfig, build_queries, SERP_CATEGORIES, SERP_LAUNCH_STATES
from multifamily.serp.serp_normalizer import classify_relevance, normalize_result
from multifamily.serp.serp_collector import run_serp_collection

_FAILURES = []
_M = '(SERP TEST)'
_urls_to_clean = set()
_run_ids_to_clean = set()
_lead_ids_to_clean = set()


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _track(result):
    if result.get('run_db_id'):
        _run_ids_to_clean.add(result['run_db_id'])
    for row in result.get('results', []):
        if row.get('url'):
            _urls_to_clean.add(row['url'])
    return result


def _raw(title, url, snippet='', date='', source='example.com'):
    return {'title': title, 'link': url, 'snippet': snippet, 'source': source, 'date': date}


def _company_marker(company):
    return f'{company} {_M}'


# ---- 1. Query templates ----

def test_query_templates_generate_expected_queries():
    for category in SERP_CATEGORIES:
        for state in SERP_LAUNCH_STATES:
            cfg = SerpQueryConfig(category=category, state=state)
            queries = build_queries(cfg)
            check(f'{category}/{state} produces at least one query', len(queries) >= 1)
            check(f'{category}/{state} queries mention the full state name',
                  all(('Texas' in q or 'California' in q) for q in queries))


def test_query_templates_include_city_when_given():
    cfg = SerpQueryConfig(category='acquisition', state='TX', city='Austin')
    queries = build_queries(cfg)
    check('city is appended to every query when provided', all('"Austin"' in q for q in queries))


def test_query_config_rejects_bad_category_or_state():
    try:
        SerpQueryConfig(category='not_a_category', state='TX')
        check('bad category raises', False)
    except ValueError:
        check('bad category raises', True)
    try:
        SerpQueryConfig(category='acquisition', state='ZZ')
        check('bad state raises', False)
    except ValueError:
        check('bad state raises', True)


# ---- 2. Normalizer: accept + relevance filtering ----

def test_normalizer_accepts_a_relevant_acquisition_result():
    cfg = SerpQueryConfig(category='acquisition', state='TX')
    raw = _raw(
        f'Sunbelt Capital acquires {_company_marker("Meridian")} Apartments in Austin',
        'https://example.com/serp-normalize-1',
        snippet='Sunbelt Capital acquired a 250-unit multifamily community in Austin, Texas.',
        date='2 days ago',
    )
    payload, reasons = normalize_result(raw, cfg, 'test query')
    check('relevant acquisition result is accepted', payload is not None)
    check('accepted payload carries the acquisition signal type', payload and payload['signalType'] == 'acquisition')
    check('accepted payload carries source=serp', payload and payload['source'] == 'serp')
    check('accepted payload carries the source URL', payload and payload['sourceUrl'] == raw['link'])
    check('acceptance reasons explain why', any(r.startswith('MATCHED_') for r in reasons))


def test_normalizer_rejects_job_posting():
    cfg = SerpQueryConfig(category='acquisition', state='TX')
    raw = _raw('Now Hiring: Leasing Agent for Apartment Community', 'https://example.com/serp-job',
                snippet='Apply now for this apartment position.')
    payload, reasons = normalize_result(raw, cfg, 'q')
    check('job posting is rejected', payload is None)
    check('rejection reason explains why (job posting)', 'REJECTED_JOB_POSTING' in reasons)


def test_normalizer_rejects_directory_domain():
    cfg = SerpQueryConfig(category='completion', state='TX')
    raw = _raw('Apartment listings now leasing', 'https://www.apartments.com/some-listing',
                snippet='Browse apartment listings now leasing.')
    payload, reasons = normalize_result(raw, cfg, 'q')
    check('generic directory listing page is rejected', payload is None)
    check('rejection reason explains why (directory domain)', any('REJECTED_DIRECTORY_DOMAIN' in r for r in reasons))


def test_normalizer_rejects_single_family_only():
    cfg = SerpQueryConfig(category='acquisition', state='TX')
    raw = _raw('Investor acquires single-family home in Austin', 'https://example.com/serp-sfh',
                snippet='A single-family home was purchased by an investor.')
    payload, reasons = normalize_result(raw, cfg, 'q')
    check('single-family-only article is rejected', payload is None)
    check('rejection reason explains why (single-family only)', 'REJECTED_SINGLE_FAMILY_ONLY' in reasons)


def test_normalizer_rejects_no_multifamily_anchor():
    cfg = SerpQueryConfig(category='acquisition', state='TX')
    raw = _raw('Local restaurant chain acquires competitor', 'https://example.com/serp-unrelated',
                snippet='A restaurant chain acquired a competitor in a merger deal.')
    payload, reasons = normalize_result(raw, cfg, 'q')
    check('unrelated (non-multifamily) result is rejected', payload is None)
    check('rejection reason explains why (no multifamily anchor)', 'REJECTED_NO_MULTIFAMILY_ANCHOR' in reasons)


def test_normalizer_rejects_multifamily_mention_wrong_category():
    # Multifamily is mentioned, but nothing ties it to "acquisition" specifically.
    cfg = SerpQueryConfig(category='acquisition', state='TX')
    raw = _raw('Multifamily market outlook for next year', 'https://example.com/serp-outlook',
                snippet='Analysts discuss the multifamily apartment market outlook.')
    payload, reasons = normalize_result(raw, cfg, 'q')
    check('multifamily mention with no category keyword match is rejected', payload is None)
    check('rejection reason explains why (no category keyword match)',
          any('REJECTED_NO_CATEGORY_KEYWORD_MATCH' in r for r in reasons))


def test_normalizer_rejects_low_confidence():
    cfg = SerpQueryConfig(category='acquisition', state='TX', confidence_threshold=0.95)
    raw = _raw('Apartment community acquired', 'https://example.com/serp-lowconf',
                snippet='An apartment community was acquired.')
    payload, reasons = normalize_result(raw, cfg, 'q')
    check('result below the confidence threshold is rejected', payload is None)
    check('rejection reason explains why (low confidence)', any('REJECTED_LOW_CONFIDENCE' in r for r in reasons))


# ---- 3. Collector: dedupe, dry-run, strengthening, review candidates, run logging ----

def _fixture_search_fn(results_by_call):
    """Returns a fake search_fn that yields `results_by_call` (a list) on
    every query call — used to simulate the SAME result reappearing across
    every query template in one run (proves in-run + seen-ledger dedupe)."""
    def _fn(query, num=10, feature='general', city='', state='', manual=False):
        return list(results_by_call)
    return _fn


def test_collector_dedupes_same_url_across_queries_in_one_run():
    company = _company_marker('Dedupflow Partners')
    url = 'https://example.com/serp-dedupe-1'
    raw = _raw(f'{company} acquires apartment community', url,
                snippet=f'{company} acquired a multifamily apartment community.', date='1 day ago')
    cfg = SerpQueryConfig(category='acquisition', state='TX', limit=5)
    result = _track(run_serp_collection(cfg, search_fn=_fixture_search_fn([raw])))
    check('collector created exactly one lead despite the URL repeating across every query template',
          result['created'] == 1)
    accepted_rows = [r for r in result['results'] if r['accepted']]
    check('only the first occurrence of the URL was accepted', len(accepted_rows) == 1)
    check('later in-run occurrences of the same URL are not reported as separate noisy rows',
          len(result['results']) == 1)
    for lead in repository.get_real_leads():
        if company in lead.company.name:
            _lead_ids_to_clean.add(lead.id)


def test_collector_seen_ledger_prevents_recreation_on_a_second_run():
    company = _company_marker('Seenledger Group')
    url = 'https://example.com/serp-seenledger-1'
    raw = _raw(f'{company} acquires apartment portfolio', url,
                snippet=f'{company} acquired an apartment portfolio.', date='1 day ago')
    cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)

    first = _track(run_serp_collection(cfg, search_fn=_fixture_search_fn([raw])))
    check('first run created a lead', first['created'] == 1)

    second = _track(run_serp_collection(cfg, search_fn=_fixture_search_fn([raw])))
    check('second run (same URL) creates nothing new', second['created'] == 0 and second['merged'] == 0)
    already_seen_rows = [r for r in second['results'] if r['url'] == url]
    check('second run rejects the URL as already seen',
          already_seen_rows and all('REJECTED_ALREADY_SEEN' in r['reason_codes'] for r in already_seen_rows))
    for lead in repository.get_real_leads():
        if company in lead.company.name:
            _lead_ids_to_clean.add(lead.id)


def test_collector_same_company_property_strengthens_existing_lead():
    company = _company_marker('Strengthenflow Holdings')
    property_name = f'{company} Gardens'
    raw1 = {'title': f'{company} acquires {property_name}', 'link': 'https://example.com/serp-strengthen-1',
            'snippet': f'{company} acquired {property_name}, a multifamily community.', 'source': 'a.com', 'date': ''}
    raw2 = {'title': f'{company} secures financing for {property_name}', 'link': 'https://example.com/serp-strengthen-2',
            'snippet': f'{company} secured construction financing for {property_name}, a multifamily property.',
            'source': 'b.com', 'date': ''}

    acq_cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    first = _track(run_serp_collection(acq_cfg, search_fn=_fixture_search_fn([raw1])))
    check('first (acquisition) run created a lead', first['created'] == 1)

    fin_cfg = SerpQueryConfig(category='financing', state='TX', limit=1)
    second = _track(run_serp_collection(fin_cfg, search_fn=_fixture_search_fn([raw2])))
    check('second (financing, same company+property) run merges rather than creating a new card',
          second['merged'] == 1 and second['created'] == 0)

    active = [l for l in repository.get_real_leads() if company in l.company.name]
    check('exactly one active lead exists for the company (no duplicate card)', len(active) == 1)
    if active:
        _lead_ids_to_clean.add(active[0].id)
        check('the surviving lead carries both signal types',
              {'acquisition', 'financing'} <= {s.signal_type for s in active[0].signals})


def test_collector_fuzzy_match_creates_review_candidate():
    base = _company_marker('Fuzzyserp Holdings Group')
    variant = _company_marker('Fuzzyserp Holdings')
    raw1 = _raw(f'{base} acquires apartment community', 'https://example.com/serp-fuzzy-1',
                snippet=f'{base} acquired an apartment community.', date='')
    raw2 = _raw(f'{variant} acquires another apartment community', 'https://example.com/serp-fuzzy-2',
                snippet=f'{variant} acquired another apartment community.', date='')
    cfg1 = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    first = _track(run_serp_collection(cfg1, search_fn=_fixture_search_fn([raw1])))
    check('first fuzzy-test run created a lead', first['created'] == 1)

    cfg2 = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    second = _track(run_serp_collection(cfg2, search_fn=_fixture_search_fn([raw2])))
    check('similarly-named company creates a separate lead (not auto-merged)', second['created'] == 1)
    check('similarly-named company raises a review candidate', second['review_candidates'] >= 1)
    for lead in repository.get_real_leads():
        if base in lead.company.name or variant in lead.company.name:
            _lead_ids_to_clean.add(lead.id)


def test_collector_logs_run_metadata_and_total_found_count():
    company = _company_marker('Runmeta Partners')
    raw_hit = _raw(f'{company} acquires apartment community', 'https://example.com/serp-runmeta-1',
                    snippet=f'{company} acquired an apartment community.', date='')
    raw_reject = _raw('Now Hiring: Leasing Agent', 'https://example.com/serp-runmeta-2',
                       snippet='Apply now for this apartment job.', date='')
    cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    result = _track(run_serp_collection(cfg, search_fn=_fixture_search_fn([raw_hit, raw_reject])))
    check('collector reports the total raw result count (accepted + rejected)', result['found'] == 2)

    run = next((r for r in repository.get_source_runs(limit=200) if r['id'] == result['run_db_id']), None)
    check('the logged run exists', run is not None)
    check("the run's category/state/query metadata was attached",
          run and run['category'] == 'acquisition' and run['state'] == 'TX' and run['query'])
    check("the run's records_found reflects the TOTAL raw result count, not just accepted",
          run and run['records_found'] == 2)
    for lead in repository.get_real_leads():
        if company in lead.company.name:
            _lead_ids_to_clean.add(lead.id)


def test_dry_run_persists_nothing():
    company = _company_marker('Dryrunflow Estates')
    raw = _raw(f'{company} acquires apartment community', 'https://example.com/serp-dryrun-1',
                snippet=f'{company} acquired an apartment community.', date='')
    cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    leads_before = len(repository.get_real_leads())
    result = run_serp_collection(cfg, search_fn=_fixture_search_fn([raw]), dry_run=True)
    check('dry run reports what it would have ingested', result['dry_run'] is True and result['accepted_would_ingest'] == 1)
    check('dry run creates no source-run', result['run_db_id'] is None)
    check('dry run does not persist any lead', len(repository.get_real_leads()) == leads_before)
    check('dry run does not mark the URL seen', not repository.is_serp_url_seen('https://example.com/serp-dryrun-1'))


def test_missing_api_key_degrades_gracefully():
    # No search_fn injected and no _default_search_fn configured in this
    # sandbox (SERPAPI_API_KEY unset) — must return a clean error, never raise.
    cfg = SerpQueryConfig(category='acquisition', state='TX')
    result = run_serp_collection(cfg, search_fn=None)
    check('missing SERPAPI_API_KEY returns a clean error, not an exception',
          result.get('error') is not None and 'SERPAPI_API_KEY' in result['error'])
    check('missing-key result has zero counts', result['found'] == 0 and result['created'] == 0)


def main():
    try:
        test_query_templates_generate_expected_queries()
        test_query_templates_include_city_when_given()
        test_query_config_rejects_bad_category_or_state()
        test_normalizer_accepts_a_relevant_acquisition_result()
        test_normalizer_rejects_job_posting()
        test_normalizer_rejects_directory_domain()
        test_normalizer_rejects_single_family_only()
        test_normalizer_rejects_no_multifamily_anchor()
        test_normalizer_rejects_multifamily_mention_wrong_category()
        test_normalizer_rejects_low_confidence()
        test_collector_dedupes_same_url_across_queries_in_one_run()
        test_collector_seen_ledger_prevents_recreation_on_a_second_run()
        test_collector_same_company_property_strengthens_existing_lead()
        test_collector_fuzzy_match_creates_review_candidate()
        test_collector_logs_run_metadata_and_total_found_count()
        test_dry_run_persists_nothing()
        test_missing_api_key_degrades_gracefully()
    finally:
        for lid in list(_lead_ids_to_clean):
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            repository.delete_snapshots_for_lead(lid)
            repository.delete_outcomes_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        for url in _urls_to_clean:
            try:
                repository.delete_serp_seen_url(url)
            except Exception:
                pass
        for run_id in _run_ids_to_clean:
            try:
                repository.delete_source_run(run_id)
            except Exception:
                pass
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(SERP TEST)%'")
            conn.execute("DELETE FROM multifamily_serp_seen WHERE url LIKE '%serp-%'")
            conn.commit()
            conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_lead_ids_to_clean)} tracked lead(s), '
              f'{len(_urls_to_clean)} seen-URL row(s), {len(_run_ids_to_clean)} source-run(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All SERP (Phase B) tests passed.')


if __name__ == '__main__':
    main()
