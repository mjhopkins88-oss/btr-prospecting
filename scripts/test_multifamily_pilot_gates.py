#!/usr/bin/env python
"""
Phase E — Pilot gates on the scorecard. Thresholds live in
multifamily/pilot_gate_config.py (config, not code); evaluate_gates()
turns a campaign's scorecard numbers into green/amber/red/unknown status
per gate; get_campaign_performance() attaches a `gates` dict to every
campaign's scorecard entry plus a cross-campaign `pilot_gates_summary`.
"""
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

_FAILURES = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def test_gate_thresholds():
    from multifamily.pilot_gate_config import evaluate_gates, get_pilot_gate_config

    cfg = get_pilot_gate_config()
    check('default config has all 4 gate thresholds', all(
        k in cfg for k in ('delivery_rate_green_min', 'reply_rate_green_min', 'reply_rate_amber_min',
                           'positive_share_green_min', 'meetings_per_50_band_min', 'meetings_per_50_band_max')
    ))

    green = evaluate_gates({'delivery_rate': 0.98, 'reply_rate': 0.09, 'positive_share': 0.5, 'meetings': 2, 'targets': 50})
    check('delivery_rate 98% is green (>=97%)', green['delivery_rate']['status'] == 'green')
    check('reply_rate 9% is green (>=8%)', green['reply_rate']['status'] == 'green')
    check('positive_share 50% is green (>=40%)', green['positive_share']['status'] == 'green')
    check('meetings 2/50 targets is green (in 1-3 band)', green['meetings']['status'] == 'green')

    amber = evaluate_gates({'delivery_rate': 0.98, 'reply_rate': 0.07, 'positive_share': 0.5, 'meetings': 2, 'targets': 50})
    check('reply_rate 7% is amber (6-8% band)', amber['reply_rate']['status'] == 'amber')

    red = evaluate_gates({'delivery_rate': 0.90, 'reply_rate': 0.03, 'positive_share': 0.1, 'meetings': 10, 'targets': 50})
    check('delivery_rate 90% is red (<97%)', red['delivery_rate']['status'] == 'red')
    check('reply_rate 3% is red (<6%)', red['reply_rate']['status'] == 'red')
    check('positive_share 10% is red (<40%)', red['positive_share']['status'] == 'red')
    check('meetings 10/50 targets is red (above the 1-3 band)', red['meetings']['status'] == 'red')

    zero_meetings = evaluate_gates({'delivery_rate': 0.98, 'reply_rate': 0.09, 'positive_share': 0.5, 'meetings': 0, 'targets': 50})
    check('0 meetings per 50 targets is red (below the 1-3 band, not green)', zero_meetings['meetings']['status'] == 'red')

    unknown = evaluate_gates({'delivery_rate': None, 'reply_rate': None, 'positive_share': None, 'meetings': 0, 'targets': 0})
    check("no data yet -> 'unknown', not 'red' (nothing to fail on an unlaunched campaign)",
          all(g['status'] == 'unknown' for g in unknown.values()))

    # Prorated meetings band -- 3 meetings across 100 targets == 1.5 per 50, still green.
    prorated = evaluate_gates({'delivery_rate': 0.98, 'reply_rate': 0.09, 'positive_share': 0.5, 'meetings': 3, 'targets': 100})
    check('meetings prorate correctly (3/100 targets == 1.5 per 50, green)',
          prorated['meetings']['status'] == 'green' and prorated['meetings']['meetings_per_50'] == 1.5)


def test_env_override():
    from multifamily import pilot_gate_config
    os.environ['MULTIFAMILY_PILOT_GATE_CONFIG_JSON'] = json.dumps({'reply_rate_green_min': 0.5})
    try:
        cfg = pilot_gate_config.get_pilot_gate_config()
        check('env override raises the reply_rate green threshold', cfg['reply_rate_green_min'] == 0.5)
        check('env override leaves other thresholds at their defaults', cfg['delivery_rate_green_min'] == 0.97)
        result = pilot_gate_config.evaluate_gates({'reply_rate': 0.09, 'delivery_rate': None, 'positive_share': None, 'meetings': 0, 'targets': 0}, config=cfg)
        check('a 9% reply rate is no longer green once the override raises the bar to 50%', result['reply_rate']['status'] != 'green')
    finally:
        del os.environ['MULTIFAMILY_PILOT_GATE_CONFIG_JSON']


def test_campaign_performance_integration():
    """Live fixture through the real repository, cleaned up afterward --
    same convention as sibling scripts/test_multifamily_campaign_*.py."""
    from multifamily import repository

    marker = f'PilotGateTest_{os.getpid()}'
    campaign = repository.create_campaign(
        name=f'{marker} Campaign', page_variant='renewal-pressure', offer_type='renewal_pressure_test',
    )
    campaign_id = campaign['id']
    target_ids = []
    try:
        # 2 targets: one delivered+replied+positive+meeting, one bounced.
        t1 = repository.create_campaign_target(campaign_id, company=f'{marker} Co1', contact_name='C1')
        t2 = repository.create_campaign_target(campaign_id, company=f'{marker} Co2', contact_name='C2')
        target_ids = [t1['id'], t2['id']]

        repository.mark_campaign_target_touch(t1['id'], 'touch_1_sent')
        repository.update_campaign_target_status(t1['id'], 'meeting_booked')
        repository.mark_campaign_target_touch(t2['id'], 'touch_1_sent')
        repository.mark_campaign_target_touch(t2['id'], 'bounced')

        perf = repository.get_campaign_performance()
        row = perf['conversion_rate_by_campaign'].get(campaign_id)
        check('the test campaign appears in conversion_rate_by_campaign', row is not None)
        check("the row carries a 'gates' dict with all 4 gates", row is not None and all(
            k in row['gates'] for k in ('delivery_rate', 'reply_rate', 'positive_share', 'meetings')
        ))
        check('delivery_rate reflects 1 delivered / 2 sent (50%, red)', row['gates']['delivery_rate']['status'] == 'red')
        check("'pilot_gates_summary' is present at the top level", 'pilot_gates_summary' in perf)
        check("this campaign is counted under 'needs_attention' (delivery is red)",
              perf['pilot_gates_summary']['needs_attention'] >= 1)
    finally:
        for tid in target_ids:
            try:
                repository.execute('DELETE FROM multifamily_campaign_targets WHERE id = ?', [tid])
            except Exception:
                pass
        try:
            repository.execute('DELETE FROM multifamily_campaigns WHERE id = ?', [campaign_id])
        except Exception:
            pass


def test_ui_wiring_present():
    app_js = open(os.path.join(REPO_ROOT, 'static/vendor/app.js'), encoding='utf-8').read()
    check("gate chip helper _mfGateChip present", 'function _mfGateChip(' in app_js)
    check("gate status color helper present", 'function _mfGateStatusColor(' in app_js)
    check("Pilot Gates column header added to the scorecard table", '"Pilot Gates"' in app_js)
    check("scorecard rows render all 4 gate chips", "_mfGateChip('Delivery'" in app_js and "_mfGateChip('Meetings'" in app_js)
    check("Overview funnel widget surfaces pilot_gates_summary", 'pilot_gates_summary' in app_js)


def main():
    print('== gate threshold math ==')
    test_gate_thresholds()
    print('\n== env-var override ==')
    test_env_override()
    print('\n== get_campaign_performance() integration (live, cleaned up) ==')
    test_campaign_performance_integration()
    print('\n== UI wiring present in app.js ==')
    test_ui_wiring_present()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Pilot Gates (Phase E) tests passed.')


if __name__ == '__main__':
    main()
