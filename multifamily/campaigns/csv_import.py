"""
CSV prospect import for Pilot Campaign Control Center targets
(Section 8 item 1's CSV import, extended so imports actually reach the
timing engine rather than sitting as orphaned rows).

Every row becomes a campaign target (always — company is the only
required column, matching create_campaign_target's own optionality).
When a row also carries enough data to pass intake validation (a real
email), it ADDITIONALLY builds a lead through the exact same
create-or-match path every other real submission uses
(multifamily.intake.build_lead_from_intake + multifamily.matching —
never a bespoke shortcut), so an imported prospect that matches an
existing lead strengthens it (a new signal, not a duplicate card),
exactly like a manual add or a public form submission. A row with no
email still creates a target — it just stays a cold prospect with no
lead until it converts or is linked manually later.

When a row carries close_date, it's ingested with acquisition context
(leadSituation='acquisition', targetCloseDate=close_date) REGARDLESS of
the campaign's own offer/situation — this is what lets
multifamily.timing.first_renewal_estimator see it later, which is the
whole point of connecting CSV import to the lead/signal layer at all
(the pilot's core "First Renewal" campaign is built entirely from
imported acquisition-origin prospects).
"""
import csv
import io
from typing import Any, Dict, List, Optional, Tuple

from multifamily import repository
from multifamily import matching as mf_matching
from multifamily.intake import build_lead_from_intake
from multifamily.forms.form_variants import FORM_VARIANTS
from multifamily.snapshots import snapshot_lead

MAX_IMPORT_ROWS = 500

OPTIONAL_CSV_COLUMNS = [
    'contact_name', 'email', 'phone', 'linkedin_url', 'city', 'state', 'segment', 'notes',
    'property_name', 'units', 'year_built', 'close_date',
]


def parse_csv_rows(file_content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Pure parsing — no DB access, no lead creation. Returns
    (rows, parse_errors). Column names are matched case-insensitively;
    unknown columns are ignored rather than rejected (forward-compatible
    with a slightly different export format). A row missing `company`
    is skipped with a 1-indexed (against data rows, excluding the
    header) error rather than aborting the whole file."""
    errors: List[str] = []
    if not (file_content or '').strip():
        return [], ['CSV file is empty.']

    reader = csv.DictReader(io.StringIO(file_content))
    if not reader.fieldnames:
        return [], ['CSV has no header row.']

    rows: List[Dict[str, Any]] = []
    for i, raw_row in enumerate(reader, start=1):
        if i > MAX_IMPORT_ROWS:
            errors.append(f'Only the first {MAX_IMPORT_ROWS} rows were processed; the rest were skipped.')
            break
        row = {(k or '').strip().lower(): (v or '').strip() for k, v in raw_row.items() if k}
        if not row.get('company'):
            errors.append(f'row {i}: company is required — skipped')
            continue
        rows.append({'_row_number': i, **row})
    return rows, errors


def _situation_for_row(campaign: Dict[str, Any], row: Dict[str, Any]) -> str:
    """A row with a close_date is always acquisition-context, regardless
    of which campaign/offer it was imported under — this is what makes
    the first-renewal routing work even for a non-acquisition-offer
    campaign that happens to import a row with a known close date."""
    if row.get('close_date'):
        return 'acquisition'
    variant = FORM_VARIANTS.get(campaign.get('page_variant'))
    return variant.lead_situation if variant else 'benchmark'


def import_row_as_target_and_lead(campaign: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    """Always creates a campaign target. Additionally builds/links a
    lead through the normal intake + matching path when the row has a
    real email — otherwise the target stays a cold prospect with no
    lead, same as a manual single-target add with no leadId. Never
    raises — a row that can't build a valid lead degrades to a
    target-only result rather than aborting the import."""
    target = repository.create_campaign_target(
        campaign['id'], company=row.get('company') or None, contact_name=row.get('contact_name') or None,
        email=row.get('email') or None, phone=row.get('phone') or None, linkedin_url=row.get('linkedin_url') or None,
        city=row.get('city') or None, state=row.get('state') or None, segment=row.get('segment') or None,
        notes=row.get('notes') or None,
    )
    # `outcome` is the machine-readable classification the aggregate
    # summary counts by; `reason` is the human-readable explanation for
    # the same event — kept in sync so neither drifts from the other.
    result: Dict[str, Any] = {
        'row': row.get('_row_number'), 'target_id': target['id'], 'company': row.get('company'),
        'lead_linked': False, 'outcome': None, 'reason': None,
    }

    if not row.get('email'):
        result['outcome'] = 'no_email'
        result['reason'] = 'no email — created as a cold prospect target, no lead yet'
        return result

    payload: Dict[str, Any] = {
        'name': row.get('contact_name') or row.get('company'), 'company': row.get('company'),
        'email': row.get('email'), 'state': row.get('state'), 'city': row.get('city'),
        'phone': row.get('phone'), 'source': 'manual',
        'leadSituation': _situation_for_row(campaign, row),
        'offerType': campaign.get('offer_type'), 'pageVariant': campaign.get('page_variant'),
        'campaignId': campaign.get('id'),
    }
    if row.get('units'):
        payload['numberOfUnits'] = row['units']
    if row.get('property_name'):
        payload['propertyName'] = row['property_name']
    if row.get('close_date'):
        payload['targetCloseDate'] = row['close_date']
    if row.get('year_built'):
        payload['yearBuilt'] = row['year_built']

    lead, errors = build_lead_from_intake(payload)
    if errors:
        result['outcome'] = 'lead_build_failed'
        result['reason'] = f'could not build a lead ({"; ".join(errors)}) — created as a cold prospect target'
        return result

    match_result = mf_matching.classify(lead, repository.get_real_leads())
    auto = match_result.get('auto')
    if auto:
        mf_matching.merge_incoming_on_intake(auto.lead, lead)
        final_lead_id = auto.lead.id
        snapshot_lead(repository.get_lead_by_id(final_lead_id), 'merged')
    else:
        repository.insert_lead(lead)
        repository.persist_lead_signals(lead)
        repository.record_lead_attribution_touch(lead, touch_type='first')
        final_lead_id = lead.id
        snapshot_lead(lead, 'created')

    repository.set_campaign_target_lead(target['id'], final_lead_id)
    result['lead_linked'] = True
    result['outcome'] = 'lead_linked'
    result['lead_id'] = final_lead_id
    return result


def import_targets_from_csv(campaign: Dict[str, Any], file_content: str) -> Dict[str, Any]:
    """End-to-end: parse + import every row. Returns a summary the API
    route hands back verbatim — never partial-fails the whole file for
    one bad row. The three outcome counts below make enrichment gaps
    visible to the operator: `no_email_count` is expected/fine (the
    pilot cadence is email-first — no email just means no sequence yet),
    while `lead_build_failed_count` flags rows that need a data fix
    (bad state, etc.) before they can ever reach the timing engine."""
    rows, parse_errors = parse_csv_rows(file_content)
    results = [import_row_as_target_and_lead(campaign, row) for row in rows]
    return {
        'created': len(results),
        'leads_linked': sum(1 for r in results if r['outcome'] == 'lead_linked'),
        'no_email_count': sum(1 for r in results if r['outcome'] == 'no_email'),
        'lead_build_failed_count': sum(1 for r in results if r['outcome'] == 'lead_build_failed'),
        'results': results,
        'errors': parse_errors,
    }
