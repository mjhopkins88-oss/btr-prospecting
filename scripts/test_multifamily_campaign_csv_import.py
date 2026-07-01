#!/usr/bin/env python
"""
Section 8 items 1-3, Phase 2 tests: CSV prospect import
(multifamily/campaigns/csv_import.py) connected to leads/signals.

Covers: pure parsing (rows missing company are skipped with a clear
per-row error, not silently dropped or aborting the file); a row with
a real email builds/links a lead through the SAME create-or-match path
every other submission uses (an exact-match email auto-merges into an
existing lead instead of duplicating it); a row with no email still
creates a cold-prospect target with no lead; a row with close_date is
ingested with acquisition context and reaches
multifamily.timing-shaped signal detail (target_close_date) REGARDLESS
of the campaign's own offer; year_built rides in signal detail, never
touching scoring; and a totally invalid row (e.g. bad state) degrades
to a target-only result rather than raising or aborting the batch.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.campaigns.csv_import import (
    parse_csv_rows, import_row_as_target_and_lead, import_targets_from_csv, MAX_IMPORT_ROWS,
)
from multifamily.forms.form_variants import FORM_VARIANTS

_FAILURES = []
_M = '(CSVIMPORT TEST)'
_campaign_ids = []
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_campaign(name_suffix, page_variant='renewal-pressure'):
    variant = FORM_VARIANTS[page_variant]
    campaign = repository.create_campaign(
        name=f'{name_suffix} {_M}', page_variant=page_variant, offer_type=variant.offer_type,
    )
    _campaign_ids.append(campaign['id'])
    return campaign


def _cleanup_lead(lead_id):
    if lead_id and lead_id not in _lead_ids:
        _lead_ids.append(lead_id)


def test_parse_csv_rows_skips_missing_company_with_clear_error():
    csv_text = (
        'company,contact_name,email\n'
        f'Good Co {_M},Jane Doe,jane@example.com\n'
        ',No Company Here,noco@example.com\n'
        f'Second Good Co {_M},John Doe,john@example.com\n'
    )
    rows, errors = parse_csv_rows(csv_text)
    check('2 valid rows parsed (the company-less row is skipped)', len(rows) == 2)
    check('a clear per-row error is reported for the skipped row', any('row 2' in e and 'company is required' in e for e in errors))
    check('column values keep their original case (only column NAMES are lowercased)',
          rows[0]['company'] == f'Good Co {_M}')


def test_parse_csv_rows_empty_and_no_header():
    rows, errors = parse_csv_rows('')
    check('empty file returns no rows', rows == [])
    check('empty file reports an error', len(errors) == 1 and 'empty' in errors[0].lower())


def test_row_with_email_builds_and_links_a_new_lead():
    campaign = _make_campaign('CsvNewLeadCampaign', page_variant='renewal-pressure')
    row = {
        '_row_number': 1, 'company': f'Csv New Lead Co {_M}', 'contact_name': 'Csv Contact',
        'email': 'csvnewlead@example.com', 'state': 'TX', 'city': 'Austin',
    }
    result = import_row_as_target_and_lead(campaign, row)
    check('target is created', bool(result.get('target_id')))
    check('lead_linked is True for a row with a real email', result['lead_linked'] is True)
    check('lead_id is present', bool(result.get('lead_id')))
    _cleanup_lead(result.get('lead_id'))

    target = repository.get_campaign_target(result['target_id'])
    check("target's lead_id matches the created lead", target['lead_id'] == result['lead_id'])
    check("target status stays 'planned' (linking a lead is not a conversion)", target['status'] == 'planned')

    lead = repository.get_lead_by_id(result['lead_id'])
    check('the lead is real (not demo)', lead is not None and lead.is_demo is False)
    check("lead's page_variant/offer_type match the campaign", lead.page_variant == 'renewal-pressure')


def test_row_with_no_email_stays_a_cold_prospect():
    campaign = _make_campaign('CsvNoEmailCampaign')
    row = {'_row_number': 1, 'company': f'Csv No Email Co {_M}', 'contact_name': 'No Email Contact'}
    result = import_row_as_target_and_lead(campaign, row)
    check('target is still created with no email', bool(result.get('target_id')))
    check('lead_linked is False when there is no email', result['lead_linked'] is False)
    check("reason explains why (no email)", 'no email' in (result.get('reason') or '').lower())
    target = repository.get_campaign_target(result['target_id'])
    check('target has no lead_id', target['lead_id'] is None)


def test_row_with_close_date_is_acquisition_context_regardless_of_campaign_offer():
    # This campaign's OWN offer is renewal-pressure, not acquisition —
    # proving the close_date override works independent of campaign offer.
    campaign = _make_campaign('CsvAcqOverrideCampaign', page_variant='renewal-pressure')
    row = {
        '_row_number': 1, 'company': f'Csv Acq Override Co {_M}', 'contact_name': 'Acq Contact',
        'email': 'csvacqoverride@example.com', 'state': 'CA', 'close_date': '2026-11-01',
        'units': '180', 'property_name': 'Test Acquisition Property', 'year_built': '1998',
    }
    result = import_row_as_target_and_lead(campaign, row)
    check('lead is linked despite the campaign not being an acquisition offer', result['lead_linked'] is True)
    _cleanup_lead(result.get('lead_id'))

    lead = repository.get_lead_by_id(result['lead_id'])
    acquisition_signal = next((s for s in lead.signals if s.signal_type == 'acquisition'), None)
    check('an acquisition signal was created', acquisition_signal is not None)
    check('target_close_date reached the signal detail', acquisition_signal.detail.get('target_close_date') == '2026-11-01')
    check('year_built reached the signal detail', acquisition_signal.detail.get('year_built') == '1998')
    check('property_name reached the signal detail', acquisition_signal.detail.get('acquisition_property_name') == 'Test Acquisition Property')
    check('units flowed into the lead property unit_count', lead.property.unit_count == 180)

    benchmark_signal = next((s for s in lead.signals if s.signal_type == 'benchmark_form_submit'), None)
    check('the primary signal carries leadSituation=acquisition', benchmark_signal is not None and
          benchmark_signal.detail.get('lead_situation') == 'acquisition')


def test_row_without_close_date_uses_campaign_situation():
    campaign = _make_campaign('CsvCampaignSituationCampaign', page_variant='builders-risk')
    row = {
        '_row_number': 1, 'company': f'Csv Campaign Situation Co {_M}', 'email': 'csvcampaignsituation@example.com',
        'state': 'TX',
    }
    result = import_row_as_target_and_lead(campaign, row)
    check('lead is linked', result['lead_linked'] is True)
    _cleanup_lead(result.get('lead_id'))
    lead = repository.get_lead_by_id(result['lead_id'])
    benchmark_signal = next((s for s in lead.signals if s.signal_type == 'benchmark_form_submit'), None)
    check("no close_date -> falls back to the campaign's own offer situation (construction)",
          benchmark_signal is not None and benchmark_signal.detail.get('lead_situation') == 'construction')


def test_invalid_row_degrades_to_target_only_not_a_crash():
    campaign = _make_campaign('CsvInvalidRowCampaign')
    row = {
        '_row_number': 1, 'company': f'Csv Invalid Row Co {_M}', 'email': 'csvinvalid@example.com',
        'state': 'ZZ',  # not a supported state -> build_lead_from_intake returns errors
    }
    result = import_row_as_target_and_lead(campaign, row)
    check('target is still created even though the lead build failed', bool(result.get('target_id')))
    check('lead_linked is False for an invalid row', result['lead_linked'] is False)
    check('reason explains the lead could not be built', 'could not build a lead' in (result.get('reason') or ''))


def test_matching_engine_reused_exact_email_merges_not_duplicates():
    campaign = _make_campaign('CsvExactMatchCampaign')
    shared_email = 'csvexactmatch@example.com'
    row_a = {'_row_number': 1, 'company': f'Csv Exact Match Co A {_M}', 'email': shared_email, 'state': 'TX'}
    row_b = {'_row_number': 2, 'company': f'Csv Exact Match Co A {_M}', 'email': shared_email, 'state': 'TX'}

    result_a = import_row_as_target_and_lead(campaign, row_a)
    _cleanup_lead(result_a.get('lead_id'))
    result_b = import_row_as_target_and_lead(campaign, row_b)
    if result_b.get('lead_id') and result_b['lead_id'] != result_a.get('lead_id'):
        _cleanup_lead(result_b.get('lead_id'))

    check('both rows created their own campaign target', result_a['target_id'] != result_b['target_id'])
    check('the second row with an identical email/company merges into the SAME lead (no duplicate)',
          result_a.get('lead_id') == result_b.get('lead_id'))


def test_import_targets_from_csv_end_to_end_summary():
    campaign = _make_campaign('CsvEndToEndCampaign', page_variant='acquisition')
    csv_text = (
        'company,contact_name,email,state,close_date\n'
        f'End To End Co A {_M},Contact A,endtoenda@example.com,TX,2026-10-01\n'
        f'End To End Co B {_M},Contact B,,TX,\n'
        ',Missing Company,missing@example.com,TX,\n'
    )
    summary = import_targets_from_csv(campaign, csv_text)
    check('2 rows created (the company-less row was skipped at parse time)', summary['created'] == 2)
    check('exactly 1 lead linked (the row with an email)', summary['leads_linked'] == 1)
    check('parse errors report the skipped row', any('company is required' in e for e in summary['errors']))
    for r in summary['results']:
        if r.get('lead_id'):
            _cleanup_lead(r['lead_id'])


def test_max_import_rows_is_enforced():
    header = 'company,email\n'
    body = ''.join(f'Row {i} Co {_M},row{i}@example.com\n' for i in range(MAX_IMPORT_ROWS + 50))
    rows, errors = parse_csv_rows(header + body)
    check(f'no more than {MAX_IMPORT_ROWS} rows are parsed', len(rows) <= MAX_IMPORT_ROWS)
    check('a truncation warning is reported', any('Only the first' in e for e in errors))


def main():
    try:
        test_parse_csv_rows_skips_missing_company_with_clear_error()
        test_parse_csv_rows_empty_and_no_header()
        test_row_with_email_builds_and_links_a_new_lead()
        test_row_with_no_email_stays_a_cold_prospect()
        test_row_with_close_date_is_acquisition_context_regardless_of_campaign_offer()
        test_row_without_close_date_uses_campaign_situation()
        test_invalid_row_degrades_to_target_only_not_a_crash()
        test_matching_engine_reused_exact_email_merges_not_duplicates()
        test_import_targets_from_csv_end_to_end_summary()
        test_max_import_rows_is_enforced()
    finally:
        for lid in _lead_ids:
            repository.delete_outbound_links_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        for cid in _campaign_ids:
            try:
                repository.delete_campaign(cid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} lead(s), {len(_campaign_ids)} campaign(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All CSV import (Section 8 items 1-3, Phase 2) tests passed.')


if __name__ == '__main__':
    main()
