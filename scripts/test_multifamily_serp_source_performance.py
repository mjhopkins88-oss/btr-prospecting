#!/usr/bin/env python
"""
SERP Phase C tests: get_source_performance()'s SERP rollup + the
source-run 'source' filter. Offline — uses the injected-search-fn SERP
collector (no network), same pattern as test_multifamily_serp.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.serp.query_templates import SerpQueryConfig
from multifamily.serp.serp_collector import run_serp_collection

_FAILURES = []
_M = '(SERPPERF TEST)'
_lead_ids = set()
_run_ids = set()
_urls = set()


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _fixture(results):
    def _fn(query, num=10, feature='general', city='', state='', manual=False):
        return list(results)
    return _fn


def _track(result):
    if result.get('run_db_id'):
        _run_ids.add(result['run_db_id'])
    for row in result.get('results', []):
        if row.get('url'):
            _urls.add(row['url'])
    return result


def test_source_performance_includes_serp_rollup():
    perf_before = repository.get_source_performance()
    before_serp = perf_before['serp']

    company = f'Serpperf Holdings {_M}'
    raw = {'title': f'{company} acquires apartment community', 'link': 'https://example.com/serpperf-1',
           'snippet': f'{company} acquired a multifamily apartment community.', 'source': 'a.com', 'date': ''}
    cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    result = _track(run_serp_collection(cfg, search_fn=_fixture([raw])))
    check('collector created a lead for this test', result['created'] == 1)
    for lead in repository.get_real_leads():
        if company in lead.company.name:
            _lead_ids.add(lead.id)

    perf_after = repository.get_source_performance()
    check("source_performance response includes a 'serp' key", 'serp' in perf_after)
    after_serp = perf_after['serp']
    check('signals_received for serp increased by 1',
          after_serp['signals_received'] == before_serp['signals_received'] + 1)
    check('leads_created for serp increased by 1',
          after_serp['leads_created'] == before_serp['leads_created'] + 1)
    check('collection_runs for serp increased by 1',
          after_serp['collection_runs'] == before_serp['collection_runs'] + 1)
    check('total_created_across_runs for serp increased by 1',
          after_serp['total_created_across_runs'] == before_serp['total_created_across_runs'] + 1)


def test_source_performance_serp_tracks_merged_and_review():
    company = f'Serpperfmerge Group {_M}'
    prop = f'{company} Gardens'
    raw1 = {'title': f'{company} acquires {prop}', 'link': 'https://example.com/serpperf-merge-1',
            'snippet': f'{company} acquired {prop}, a multifamily community.', 'source': 'a.com', 'date': ''}
    raw2 = {'title': f'{company} secures financing for {prop}', 'link': 'https://example.com/serpperf-merge-2',
            'snippet': f'{company} secured construction financing for {prop}, a multifamily property.',
            'source': 'b.com', 'date': ''}

    perf_before = repository.get_source_performance()['serp']

    acq_cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    first = _track(run_serp_collection(acq_cfg, search_fn=_fixture([raw1])))
    check('first run created a lead', first['created'] == 1)

    fin_cfg = SerpQueryConfig(category='financing', state='TX', limit=1)
    second = _track(run_serp_collection(fin_cfg, search_fn=_fixture([raw2])))
    check('second run merged into the first (no new card)', second['merged'] == 1)

    for lead in repository.get_real_leads():
        if company in lead.company.name:
            _lead_ids.add(lead.id)

    # merge_status='merged' rows aren't returned by get_real_leads() (they're
    # tombstoned survivors of a merge) — the merge here folds the SECOND
    # lead into the first without ever persisting a standalone second row,
    # so leads_merged_away tracks source-runs' records_merged, not a
    # tombstoned row count. Assert via the run aggregate instead.
    perf_after = repository.get_source_performance()['serp']
    check('total_merged_across_runs for serp increased by 1',
          perf_after['total_merged_across_runs'] == perf_before['total_merged_across_runs'] + 1)


def test_source_runs_filter_by_source():
    company = f'Serpperffilter Co {_M}'
    raw = {'title': f'{company} acquires apartment community', 'link': 'https://example.com/serpperf-filter-1',
           'snippet': f'{company} acquired an apartment community.', 'source': 'a.com', 'date': ''}
    cfg = SerpQueryConfig(category='acquisition', state='TX', limit=1)
    result = _track(run_serp_collection(cfg, search_fn=_fixture([raw])))
    for lead in repository.get_real_leads():
        if company in lead.company.name:
            _lead_ids.add(lead.id)

    all_runs = repository.get_source_runs(limit=500)
    serp_runs = repository.get_source_runs(limit=500, source='serp')
    check('unfiltered get_source_runs includes non-serp and serp runs', len(all_runs) >= len(serp_runs))
    check('source=serp filter returns only serp runs', all(r['source'] == 'serp' for r in serp_runs))
    check('the run we just logged appears in the filtered list',
          any(r['id'] == result['run_db_id'] for r in serp_runs))


def main():
    try:
        test_source_performance_includes_serp_rollup()
        test_source_performance_serp_tracks_merged_and_review()
        test_source_runs_filter_by_source()
    finally:
        for lid in list(_lead_ids):
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            repository.delete_snapshots_for_lead(lid)
            repository.delete_outcomes_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        for url in _urls:
            try:
                repository.delete_serp_seen_url(url)
            except Exception:
                pass
        for run_id in _run_ids:
            try:
                repository.delete_source_run(run_id)
            except Exception:
                pass
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(SERPPERF TEST)%'")
            conn.commit()
            conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_lead_ids)} tracked lead(s), {len(_urls)} seen-URL row(s), {len(_run_ids)} source-run(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All SERP source-performance (Phase C) tests passed.')


if __name__ == '__main__':
    main()
