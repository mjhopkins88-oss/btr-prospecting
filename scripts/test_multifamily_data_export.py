#!/usr/bin/env python
"""
Phase F — Multifamily Command data export ("Export all data").

Covers: the zip contains one CSV per multifamily_* table with correct
headers/rows, the export is admin-only (401 unauthenticated, 403 for a
logged-in non-admin), and the response carries a timestamped .zip
filename. Live checks run against an isolated copy of prospects.db in a
temp directory — the real prospects.db is never touched.
"""
import http.client
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

_FAILURES = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def test_export_module():
    from multifamily.data_export import MULTIFAMILY_TABLES, build_export_zip, export_filename

    check('MULTIFAMILY_TABLES includes leads/signals/activities/campaigns/targets/deliverables', all(
        t in MULTIFAMILY_TABLES for t in (
            'multifamily_leads', 'multifamily_signals', 'multifamily_activities',
            'multifamily_campaigns', 'multifamily_campaign_targets', 'multifamily_deliverables',
        )
    ))
    check('no duplicate table names', len(MULTIFAMILY_TABLES) == len(set(MULTIFAMILY_TABLES)))

    zip_bytes = build_export_zip()
    check('build_export_zip() returns non-empty bytes', bool(zip_bytes))
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = set(zf.namelist())
    check('zip has exactly one CSV per table, no more/fewer', names == {f'{t}.csv' for t in MULTIFAMILY_TABLES})
    check('zip integrity check passes (testzip finds no bad entries)', zf.testzip() is None)

    filename = export_filename()
    check('filename ends in .zip', filename.endswith('.zip'))
    check("filename starts with 'multifamily-export-'", filename.startswith('multifamily-export-'))
    check('filename carries a YYYYMMDD-HHMMSS-shaped timestamp', len(filename) == len('multifamily-export-YYYYMMDD-HHMMSS.zip'))


def test_export_reflects_real_rows():
    """A row inserted into a real table shows up as a real CSV row in the
    export, with the right column headers -- not just an empty stub."""
    from multifamily import repository
    from multifamily.data_export import build_export_zip

    marker = f'DataExportTest_{os.getpid()}'
    campaign = repository.create_campaign(
        name=f'{marker} Campaign', page_variant='renewal-pressure', offer_type='renewal_pressure_test',
    )
    campaign_id = campaign['id']
    try:
        zip_bytes = build_export_zip()
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        csv_text = zf.read('multifamily_campaigns.csv').decode('utf-8')
        check("the campaigns CSV has an 'id,name,...' header row", csv_text.splitlines()[0].split(',')[0] == 'id')
        check('the just-created campaign row appears in the export', marker in csv_text)
    finally:
        from shared.database import execute
        execute('DELETE FROM multifamily_campaigns WHERE id = ?', [campaign_id])


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _python_with_flask():
    _APP_PY_DEPS = ('flask', 'flask_cors', 'anthropic', 'dotenv', 'apscheduler', 'pytz', 'bcrypt')
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


def _request(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    headers = {'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    set_cookie = resp.getheader('Set-Cookie')
    cookie_out = set_cookie.split(';')[0] if set_cookie else cookie
    content_disposition = resp.getheader('Content-Disposition')
    content_type = resp.getheader('Content-Type')
    try:
        parsed = json.loads(raw) if content_type and 'json' in content_type else None
    except Exception:
        parsed = None
    conn.close()
    return resp.status, parsed, raw, cookie_out, content_disposition, content_type


def _wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, *_ = _request(port, 'GET', '/health')
            if status:
                return True
        except Exception:
            time.sleep(0.5)
    return False


def test_export_endpoint_live():
    tmpdir = tempfile.mkdtemp(prefix='mf_data_export_')
    real_db = os.path.join(REPO_ROOT, 'prospects.db')
    iso_db = os.path.join(tmpdir, 'prospects.db')
    if os.path.exists(real_db):
        shutil.copy(real_db, iso_db)

    proc = None
    try:
        port = _free_port()
        env = dict(os.environ)
        env['PYTHONPATH'] = REPO_ROOT
        env['PORT'] = str(port)
        env['SUPER_ADMIN_EMAIL'] = 'data-export-test-super@example.com'
        proc = subprocess.Popen(
            [_python_with_flask(), os.path.join(REPO_ROOT, 'app.py')],
            cwd=tmpdir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        check('isolated Flask instance started', _wait_for_server(port))

        status, _, _, _, _, _ = _request(port, 'GET', '/api/multifamily/admin/export')
        check('GET /admin/export requires auth (401 unauthenticated)', status == 401)

        _, _, _, admin_cookie, _, _ = _request(port, 'POST', '/api/auth/bootstrap', body={
            'email': 'data-export-test-super@example.com', 'password': 'TestPass123!',
            'name': 'Export Test', 'workspace_name': 'ExportTestWS',
        })
        check('super-admin bootstrap session cookie captured', bool(admin_cookie))

        status2, _, raw, _, disposition, ctype = _request(port, 'GET', '/api/multifamily/admin/export', cookie=admin_cookie)
        check('GET /admin/export succeeds for the super admin (200)', status2 == 200)
        check('Content-Type is application/zip', ctype == 'application/zip')
        check("Content-Disposition is an attachment with a .zip filename", bool(disposition) and 'attachment' in disposition and '.zip' in disposition)
        zf = zipfile.ZipFile(io.BytesIO(raw))
        check('the downloaded zip is well-formed (testzip finds no bad entries)', zf.testzip() is None)
        check('the downloaded zip has at least the 16 known tables', len(zf.namelist()) >= 16)

        status3, body3, _, _, _, _ = _request(port, 'POST', '/api/auth/users', body={
            'name': 'Non Admin', 'email': 'data-export-nonadmin@example.com',
            'password': 'NonAdminTest123!', 'role': 'producer',
        }, cookie=admin_cookie)
        check('admin creates a non-admin producer user', status3 == 200 and bool(body3 and body3.get('success')))

        status4, _, _, non_admin_cookie, _, _ = _request(port, 'POST', '/api/auth/login', body={
            'email': 'data-export-nonadmin@example.com', 'password': 'NonAdminTest123!',
        })
        check('non-admin login succeeds', status4 == 200 and bool(non_admin_cookie))

        status5, _, _, _, _, _ = _request(port, 'GET', '/api/multifamily/admin/export', cookie=non_admin_cookie)
        check('GET /admin/export is forbidden for a logged-in non-admin (403)', status5 == 403)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f'\nTorn down isolated Flask instance and temp DB copy ({tmpdir}) — real prospects.db was never touched.')


def main():
    print('== export module (zip contents/shape) ==')
    test_export_module()
    print('\n== export reflects real repository rows ==')
    test_export_reflects_real_rows()
    print('\n== live endpoint (auth gate, response shape) ==')
    test_export_endpoint_live()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Data Export (Phase F) tests passed.')


if __name__ == '__main__':
    main()
