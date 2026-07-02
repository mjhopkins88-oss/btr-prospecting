#!/usr/bin/env python
"""
Pre-launch audit finding F1: the zero-users "bootstrap mode" auth bypass
in app.py's `_enforce_auth()` must expose ONLY the initial setup path
(/api/auth/bootstrap, /api/auth/has-users, /api/auth/login,
/api/auth/logout, /api/auth/me) — every other route must 401 even when
the `users` table is empty, so a botched migration or accidental
user-table wipe can never leave the whole API open to anonymous
callers.

This spins up the real Flask app as a subprocess against an ISOLATED
copy of prospects.db (in a scratch temp directory, never the real
file — db.py resolves 'prospects.db' relative to the process's current
working directory, so running the subprocess with cwd=<tempdir> is
sufficient isolation) with the `users` table emptied, so the test
exercises the actual HTTP/middleware layer rather than mocking it out.
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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FAILURES = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _request(port, method, path, body=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    headers = {'Content-Type': 'application/json'} if body is not None else {}
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    try:
        parsed = json.loads(data)
    except Exception:
        parsed = None
    return resp.status, parsed


def _wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = _request(port, 'GET', '/health')
            if status:
                return True
        except Exception:
            time.sleep(0.5)
    return False


_APP_PY_DEPS = ('flask', 'flask_cors', 'anthropic', 'dotenv', 'apscheduler', 'pytz', 'bcrypt')


def _python_with_flask():
    """Prefer the interpreter already running this script (correct in any
    normal deploy where app.py's dependencies are installed for that same
    python3) — fall back to a local dev venv only if this sandbox's
    default interpreter is missing one of app.py's actual third-party
    imports. Checks each module by name rather than importing app.py
    itself, since app.py has import-time side effects (writes a CSV
    export, starts a background scheduler) that a mere dependency check
    shouldn't trigger."""
    candidates = [sys.executable, '/tmp/mf_venv4/bin/python',
                  os.path.join(REPO_ROOT, 'venv', 'bin', 'python'),
                  os.path.join(REPO_ROOT, '.venv', 'bin', 'python')]
    check = '; '.join(f'import {mod}' for mod in _APP_PY_DEPS)
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            subprocess.run([candidate, '-c', check], check=True, capture_output=True, timeout=10)
            return candidate
        except Exception:
            continue
    return sys.executable


def main():
    tmpdir = tempfile.mkdtemp(prefix='mf_audit_bootstrap_')
    proc = None
    try:
        # Isolated copy — never the real prospects.db.
        shutil.copy(os.path.join(REPO_ROOT, 'prospects.db'), os.path.join(tmpdir, 'prospects.db'))
        conn = sqlite3.connect(os.path.join(tmpdir, 'prospects.db'))
        cur = conn.cursor()
        cur.execute('DELETE FROM users')
        cur.execute('DELETE FROM sessions')
        # This copy inherits real intake-rate-limit history from whatever
        # machine/IP has been hitting the real dev DB — clear it so this
        # test's own POST /leads isn't spuriously 429'd by unrelated
        # earlier activity (spam_guard's rate limiter is a separate,
        # already-verified concern; this test only cares that auth
        # doesn't block the public route).
        cur.execute('DELETE FROM multifamily_intake_events')
        conn.commit()
        cur.execute('SELECT COUNT(*) FROM users')
        zero_users_confirmed = cur.fetchone()[0] == 0
        conn.close()
        check('isolated DB copy starts with zero users', zero_users_confirmed)

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

        # --- With zero users: protected routes must 401, setup paths must work ---
        status, body = _request(port, 'GET', '/api/multifamily/leads')
        check('GET /api/multifamily/leads with zero users -> 401 (not bypassed)', status == 401)
        check('401 response carries auth_required flag', bool(body and body.get('auth_required')))

        status, body = _request(port, 'GET', '/api/multifamily/campaigns')
        check('GET /api/multifamily/campaigns with zero users -> 401 (not bypassed)', status == 401)

        status, body = _request(port, 'GET', '/api/auth/has-users')
        check('GET /api/auth/has-users (setup path) still works with zero users', status == 200)
        check('has-users correctly reports False', body is not None and body.get('has_users') is False)

        status, body = _request(port, 'GET', '/api/auth/me')
        check('GET /api/auth/me (setup path) still works with zero users', status == 200)
        check('me reports needs_bootstrap', body is not None and body.get('needs_bootstrap') is True)

        status, body = _request(port, 'GET', '/api/multifamily/form-variants')
        check('public marketing route /api/multifamily/form-variants still works (unaffected)', status == 200)

        status, body = _request(port, 'POST', '/api/multifamily/leads', body={
            'name': 'F1 Test', 'company': 'F1 Test Co (AUDIT_F1_TEST)', 'email': 'f1test@example.com',
            'state': 'TX', 'leadSituation': 'benchmark', 'source': 'manual',
        })
        check('public intake POST /api/multifamily/leads still works (unaffected)', status == 201)

        # --- The setup route itself must still work with zero users ---
        status, body = _request(port, 'POST', '/api/auth/bootstrap', body={
            'email': 'f1audit@example.com', 'name': 'F1 Audit', 'password': 'AuditF1Test123!',
            'workspace_name': 'F1 Audit Workspace',
        })
        check('POST /api/auth/bootstrap (setup path) succeeds with zero users', status == 200)
        check('bootstrap created a real user', bool(body and body.get('success')))

        # --- After bootstrap, a user now exists -- protected routes must
        # still require an actual session (no lingering bypass). ---
        status, body = _request(port, 'GET', '/api/multifamily/leads')
        check('GET /api/multifamily/leads with a user now present, no session -> 401', status == 401)

        status, body = _request(port, 'POST', '/api/auth/bootstrap', body={
            'email': 'someoneelse@example.com', 'name': 'X', 'password': 'AnotherPass123!',
            'workspace_name': 'Second Workspace',
        })
        check('a second bootstrap attempt is rejected once a user exists', status == 403)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f'\nTorn down isolated Flask instance and temp DB copy ({tmpdir}) — real prospects.db was never touched.')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All zero-users auth-bootstrap-mode (audit finding F1) tests passed.')


if __name__ == '__main__':
    main()
