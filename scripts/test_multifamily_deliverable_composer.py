#!/usr/bin/env python
"""
Phase B — Deliverable Composer tests.

Covers:
  - build_prefill() returns sensible, offer-specific values for every one
    of the six form-variant offers (multifamily/deliverable_composer.py),
    sourced correctly from company/property/contact basics and each
    situation's signal `detail` (multifamily/intake.py).
  - render_pdf() produces non-empty bytes starting with the PDF magic
    bytes (%PDF) for each offer, and the mandatory indicative-only /
    not-a-quote disclaimer is the exact required string baked into every
    render (verified directly on the DISCLAIMER constant actually used
    by render_pdf's footer, since the rendered PDF stream is
    compressed/encoded and not searchable as plain text without adding a
    PDF-parsing dependency this repo doesn't otherwise need).
  - multifamily_deliverables persistence (repository.insert_deliverable /
    get_deliverables_for_lead) round-trips fields_json correctly.
  - Live HTTP: the two new admin-only endpoints
    (GET .../deliverable-prefill, POST .../deliverable) work end-to-end
    for a super-admin session (a real generated PDF comes back over the
    wire) and reject a non-admin session (403) and an unauthenticated
    request (401) — spun up against an ISOLATED copy of prospects.db in a
    scratch temp directory (never the real file), per this repo's
    existing live-HTTP test convention (see
    scripts/test_auth_bootstrap_mode.py).
"""
import http.client
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FAILURES = []
_M = '(DELIVERABLECOMPOSER TEST)'


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# Function-level tests (no Flask needed)
# ---------------------------------------------------------------------------

def test_build_prefill_and_render_pdf_across_offer_types():
    from multifamily.intake import build_lead_from_intake
    from multifamily.deliverable_composer import (
        build_prefill, deliverable_meta_for_lead, render_pdf, DISCLAIMER,
    )
    from multifamily.credibility_config import public_credibility_view

    check(
        "DISCLAIMER matches the exact required indicative-only language",
        DISCLAIMER == (
            "This is an indicative estimate only, not a quote or binding proposal. "
            "Coverage, terms, and pricing are subject to full underwriting review. "
            "This is not an offer of insurance."
        ),
    )

    cred = public_credibility_view()

    cases = [
        ('benchmark', 'multifamily_benchmark_review', {
            'name': 'Fay Test', 'company': f'Zeta Holdings {_M}', 'email': 'fay@example.com',
            'state': 'TX', 'city': 'Houston', 'leadSituation': 'benchmark', 'source': 'manual',
            'numberOfUnits': '300', 'assetType': 'garden',
        }, {'Unit count': '300', 'Asset type': 'Garden-style'}),
        ('renewal-pressure', 'renewal_pressure_test', {
            'name': 'Jane Test', 'company': f'Acme Multifamily {_M}', 'email': 'jane@example.com',
            'phone': '512-555-1212', 'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal',
            'source': 'manual', 'numberOfUnits': '220', 'offerType': 'renewal_pressure_test',
            'pageVariant': 'renewal-pressure', 'renewalDate': '2026-09-01',
            'currentPremiumRange': '250k_500k', 'primaryConcern': 'premium_increase',
        }, {'Renewal date': '2026-09-01', 'Current premium range (optional)': '250k_500k', 'Main concern': 'Pricing'}),
        ('acquisition', 'acquisition_assumption_review', {
            'name': 'Bob Test', 'company': f'Beta Acquisitions {_M}', 'email': 'bob@example.com',
            'state': 'CA', 'city': 'LA', 'leadSituation': 'acquisition', 'source': 'manual',
            'numberOfUnits': '150', 'offerType': 'acquisition_assumption_review',
            'pageVariant': 'acquisition', 'targetCloseDate': '2026-08-15', 'yearBuilt': '1998',
        }, {'Vintage (year built)': '1998', 'Target close date': '2026-08-15'}),
        ('lender-requirement', 'lender_requirement_review', {
            'name': 'Cara Test', 'company': f'Gamma Lending {_M}', 'email': 'cara@example.com',
            'state': 'TX', 'city': 'Dallas', 'leadSituation': 'refinance', 'source': 'manual',
            'numberOfUnits': '90', 'assetType': 'high_rise', 'offerType': 'lender_requirement_review',
            'pageVariant': 'lender-requirement', 'lenderDeadline': '2026-07-20', 'issueType': 'deductible',
        }, {'Lender deadline': '2026-07-20', 'Type of lender issue': 'Deductible too high for lender'}),
        ('builders-risk', 'builders_risk_review', {
            'name': 'Dee Test', 'company': f'Delta Builders {_M}', 'email': 'dee@example.com',
            'state': 'TX', 'city': 'Dallas', 'leadSituation': 'construction', 'source': 'manual',
            'offerType': 'builders_risk_review', 'pageVariant': 'builders-risk',
            'projectStartDate': '2026-10-01', 'hardCosts': '$12,000,000', 'softCosts': '$2,000,000',
            'controlType': 'gc_controlled', 'constructionStage': 'pre_construction',
        }, {'Project start date': '2026-10-01', 'Hard costs (optional)': '$12,000,000',
            'Who controls the policy': 'GC-controlled', 'Construction stage': 'Pre-construction'}),
        ('completion-leaseup', 'completion_leaseup_review', {
            'name': 'Eve Test', 'company': f'Epsilon Communities {_M}', 'email': 'eve@example.com',
            'state': 'CA', 'city': 'Fresno', 'leadSituation': 'completion', 'source': 'manual',
            'offerType': 'completion_leaseup_review', 'pageVariant': 'completion-leaseup',
            'expectedCompletionDate': '2026-09-15', 'firstOccupancyDate': '2026-10-01',
            'phasing': 'phased', 'operatingCoveragePlaced': 'no',
        }, {'Expected completion date': '2026-09-15', 'Completion type': 'Phased occupancy',
            'Is operating coverage already placed?': 'No'}),
    ]

    for slug, offer_type, payload, expected_subset in cases:
        lead, errors = build_lead_from_intake(payload)
        check(f"[{slug}] intake builds cleanly", errors == [])
        if errors:
            continue

        meta = deliverable_meta_for_lead(lead)
        check(f"[{slug}] deliverable_meta resolves the right offer_type", meta['offer_type'] == offer_type)
        check(f"[{slug}] deliverable_meta carries a non-empty deliverable_name", bool(meta['deliverable_name']))

        fields = build_prefill(lead)
        check(f"[{slug}] prefill includes basic contact/company fields",
              fields.get('Contact name') == payload['name'] and fields.get('Company name') == payload['company'])
        for label, expected_value in expected_subset.items():
            check(f"[{slug}] prefill['{label}'] == {expected_value!r}", fields.get(label) == expected_value)
        check(f"[{slug}] every required_input label is present in the prefill",
              all(label in fields for label in
                  __import__('multifamily.forms.form_variants', fromlist=['FORM_VARIANTS']).FORM_VARIANTS[slug].required_inputs))

        pdf_bytes = render_pdf(lead, meta['offer_type'], fields, cred)
        check(f"[{slug}] render_pdf returns non-empty bytes", bool(pdf_bytes) and len(pdf_bytes) > 500)
        check(f"[{slug}] render_pdf output starts with the PDF magic bytes", pdf_bytes[:4] == b'%PDF')


def test_prefill_falls_back_gracefully_with_no_offer_type():
    """A lead with no offer_type/page_variant at all must still produce a
    usable prefill (falls back to the benchmark template) instead of
    raising — mirrors the existing zero-regression fallback pattern used
    elsewhere in this phase (form_variants.py's default_form_variant())."""
    from multifamily.intake import build_lead_from_intake
    from multifamily.deliverable_composer import build_prefill, deliverable_meta_for_lead

    lead, errors = build_lead_from_intake({
        'name': 'No Offer Test', 'company': f'Generic Co {_M}', 'email': 'noOffer@example.com',
        'state': 'TX', 'city': 'Houston', 'leadSituation': 'operating', 'source': 'manual',
    })
    check('intake builds cleanly with no offer_type', errors == [])
    meta = deliverable_meta_for_lead(lead)
    check('falls back to the benchmark slug when no offer_type/page_variant is set', meta['slug'] == 'benchmark')
    fields = build_prefill(lead)
    check('prefill still returns basics', fields.get('Company name') == f'Generic Co {_M}')


def test_deliverable_persistence_round_trips():
    from multifamily import repository
    from multifamily.intake import build_lead_from_intake
    from multifamily.deliverable_composer import build_prefill, deliverable_meta_for_lead

    lead, errors = build_lead_from_intake({
        'name': 'Persist Test', 'company': f'Persist Co {_M}', 'email': 'persist@example.com',
        'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal', 'source': 'manual',
        'offerType': 'renewal_pressure_test', 'pageVariant': 'renewal-pressure', 'renewalDate': '2026-09-01',
    })
    check('intake builds cleanly for persistence test', errors == [])
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    try:
        meta = deliverable_meta_for_lead(lead)
        fields = build_prefill(lead)
        row = repository.insert_deliverable(
            lead_id=lead.id, offer_type=meta['offer_type'], deliverable_name=meta['deliverable_name'],
            artifact_type=meta['artifact_type'], fields=fields, created_by='test@example.com',
        )
        check('insert_deliverable returns a row with an id', bool(row.get('id')))

        fetched = repository.get_deliverables_for_lead(lead.id)
        check('get_deliverables_for_lead returns exactly one row', len(fetched) == 1)
        check('persisted deliverable_name matches', fetched[0]['deliverable_name'] == meta['deliverable_name'])
        check('persisted fields_json round-trips back to the exact fields dict', fetched[0]['fields'] == fields)
        check('persisted created_by matches', fetched[0]['created_by'] == 'test@example.com')
    finally:
        repository.delete_deliverables_for_lead(lead.id)
        repository.delete_notifications_for_lead(lead.id)
        repository.delete_outbound_links_for_lead(lead.id)
        repository.delete_signals_for_lead(lead.id)
        repository.delete_attribution_for_lead(lead.id)
        try:
            repository.delete_lead(lead.id)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Live HTTP tests — isolated DB copy, real Flask subprocess
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _extract_cookie(resp):
    raw = resp.getheader('Set-Cookie') or ''
    if 'session_token=' not in raw:
        return None
    return raw.split(';', 1)[0]


def _request(port, method, path, body=None, cookie=None, raw=False):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    headers = {}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if cookie:
        headers['Cookie'] = cookie
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    new_cookie = _extract_cookie(resp)
    content_type = resp.getheader('Content-Type') or ''
    conn.close()
    if raw:
        return resp.status, data, content_type, new_cookie
    try:
        parsed = json.loads(data)
    except Exception:
        parsed = None
    return resp.status, parsed, content_type, new_cookie


def _wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _, _, _ = _request(port, 'GET', '/health')
            if status:
                return True
        except Exception:
            time.sleep(0.5)
    return False


_APP_PY_DEPS = ('flask', 'flask_cors', 'anthropic', 'dotenv', 'apscheduler', 'pytz', 'bcrypt', 'fpdf')


def _python_with_flask():
    candidates = [sys.executable, '/tmp/mf_venv4/bin/python',
                  os.path.join(REPO_ROOT, 'venv', 'bin', 'python'),
                  os.path.join(REPO_ROOT, '.venv', 'bin', 'python')]
    check_cmd = '; '.join(f'import {mod}' for mod in _APP_PY_DEPS)
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            subprocess.run([candidate, '-c', check_cmd], check=True, capture_output=True, timeout=10)
            return candidate
        except Exception:
            continue
    return sys.executable


def test_live_endpoints_admin_and_non_admin():
    tmpdir = tempfile.mkdtemp(prefix='mf_deliverable_composer_')
    proc = None
    lead_id = None
    try:
        # Isolated copy — never the real prospects.db.
        real_db = os.path.join(REPO_ROOT, 'prospects.db')
        iso_db = os.path.join(tmpdir, 'prospects.db')
        if os.path.exists(real_db):
            shutil.copy(real_db, iso_db)
            conn = sqlite3.connect(iso_db)
            cur = conn.cursor()
            cur.execute('DELETE FROM users')
            cur.execute('DELETE FROM sessions')
            cur.execute('DELETE FROM multifamily_intake_events')
            conn.commit()
            conn.close()

        port = _free_port()
        env = dict(os.environ)
        env['PYTHONPATH'] = REPO_ROOT
        env['PORT'] = str(port)
        proc = subprocess.Popen(
            [_python_with_flask(), os.path.join(REPO_ROOT, 'app.py')],
            cwd=tmpdir, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server_up = _wait_for_server(port)
        check('isolated Flask instance started', server_up)
        if not server_up:
            return

        # --- Create a real lead via the public intake endpoint (no auth needed) ---
        status, body, _, _ = _request(port, 'POST', '/api/multifamily/leads', body={
            'name': 'Live Test Lead', 'company': f'Live Test Co {_M}', 'email': 'livetest@example.com',
            'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal', 'source': 'manual',
            'offerType': 'renewal_pressure_test', 'pageVariant': 'renewal-pressure', 'renewalDate': '2026-09-01',
        })
        check('public lead intake succeeds (201)', status == 201)
        lead_id = body.get('lead', {}).get('id') if body else None
        check('lead id captured from intake response', bool(lead_id))
        if not lead_id:
            return

        # --- Unauthenticated (no session at all) -> 401 on both new endpoints ---
        status, body, _, _ = _request(port, 'GET', f'/api/multifamily/leads/{lead_id}/deliverable-prefill')
        check('GET deliverable-prefill with no session -> 401', status == 401)
        status, body, _, _ = _request(port, 'POST', f'/api/multifamily/leads/{lead_id}/deliverable', body={'fields': {}})
        check('POST deliverable with no session -> 401', status == 401)

        # --- Bootstrap the first user as the real super admin email so
        # require_super_admin's is_super_admin + SUPER_ADMIN_EMAIL check
        # both pass (app.py: SUPER_ADMIN_EMAIL defaults to
        # 'mjhopkins88@gmail.com', the operator's real email). ---
        status, body, _, admin_cookie = _request(port, 'POST', '/api/auth/bootstrap', body={
            'email': 'mjhopkins88@gmail.com', 'name': 'Composer Test Admin', 'password': 'ComposerTest123!',
            'workspace_name': 'Composer Test Workspace',
        })
        check('bootstrap succeeds', status == 200 and bool(body and body.get('success')))
        check('bootstrap session cookie captured', bool(admin_cookie))

        # --- Super admin: GET prefill ---
        status, body, _, _ = _request(port, 'GET', f'/api/multifamily/leads/{lead_id}/deliverable-prefill', cookie=admin_cookie)
        check('GET deliverable-prefill as super admin -> 200', status == 200)
        check('prefill response has deliverable_name', bool(body and body.get('deliverable_name')))
        check("prefill response's offer_type matches the lead's offer",
              body and body.get('offer_type') == 'renewal_pressure_test')
        fields = (body or {}).get('fields') or {}
        check('prefill response has a non-empty fields object', bool(fields))
        check("prefill fields include the renewal date from the lead's signal detail",
              fields.get('Renewal date') == '2026-09-01')

        # --- Super admin: POST generate -> real PDF bytes back over HTTP ---
        edited_fields = dict(fields)
        edited_fields['Main concern'] = 'Pricing (edited by admin before sending)'
        status, pdf_bytes, content_type, _ = _request(
            port, 'POST', f'/api/multifamily/leads/{lead_id}/deliverable',
            body={'fields': edited_fields}, cookie=admin_cookie, raw=True,
        )
        check('POST deliverable as super admin -> 200', status == 200)
        check('response Content-Type is application/pdf', content_type.startswith('application/pdf'))
        check('response body starts with the PDF magic bytes', pdf_bytes[:4] == b'%PDF')
        check('response body is a substantial PDF (not a stub)', len(pdf_bytes) > 1000)

        # --- Deliverable history now shows the generated one ---
        status, body, _, _ = _request(port, 'GET', f'/api/multifamily/leads/{lead_id}/deliverables', cookie=admin_cookie)
        check('GET deliverables history as super admin -> 200', status == 200)
        deliverables = (body or {}).get('deliverables') or []
        check('deliverable history has exactly one entry after one generate', len(deliverables) == 1)
        check("persisted deliverable's fields reflect the admin's edit",
              deliverables and deliverables[0].get('fields', {}).get('Main concern') ==
              'Pricing (edited by admin before sending)')

        # --- A second, non-admin ("producer") user must get 403, not 401 ---
        status, body, _, _ = _request(port, 'POST', '/api/auth/users', body={
            'name': 'Non Admin', 'email': 'nonadmin@example.com', 'password': 'NonAdminTest123!', 'role': 'producer',
        }, cookie=admin_cookie)
        check('admin creates a non-admin producer user', status == 200 and bool(body and body.get('success')))

        status, body, _, producer_cookie = _request(port, 'POST', '/api/auth/login', body={
            'email': 'nonadmin@example.com', 'password': 'NonAdminTest123!',
        })
        check('non-admin login succeeds', status == 200 and bool(producer_cookie))

        status, body, _, _ = _request(port, 'GET', f'/api/multifamily/leads/{lead_id}/deliverable-prefill', cookie=producer_cookie)
        check('GET deliverable-prefill as logged-in non-admin -> 403', status == 403)

        status, body, _, _ = _request(
            port, 'POST', f'/api/multifamily/leads/{lead_id}/deliverable',
            body={'fields': {}}, cookie=producer_cookie,
        )
        check('POST deliverable as logged-in non-admin -> 403', status == 403)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        # Clean up the deliverable/lead we created inside the isolated DB
        # copy before it's discarded (belt-and-suspenders; the whole
        # tmpdir is about to be removed anyway).
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f'\nTorn down isolated Flask instance and temp DB copy ({tmpdir}) — real prospects.db was never touched.')


def main():
    test_build_prefill_and_render_pdf_across_offer_types()
    test_prefill_falls_back_gracefully_with_no_offer_type()
    test_deliverable_persistence_round_trips()
    test_live_endpoints_admin_and_non_admin()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Deliverable Composer (Phase B) tests passed.')


if __name__ == '__main__':
    main()
