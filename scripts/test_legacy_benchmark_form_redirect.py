#!/usr/bin/env python
"""
Phase A visual overhaul + audit 1b disposition: the legacy dark-theme
benchmark form (static/multifamily-benchmark-form.html) is retired.
Both in-app links (static/vendor/app.js's shared MultifamilyHeader
component) now point directly at /mf-review/benchmark, and the old
route itself 302-redirects there too (for any already-shared/bookmarked
link), preserving the full query string so UTM/tracking params still
reach the new page.

This spins up the real Flask app as a subprocess (no DB isolation
needed — this route touches no database) and hits the real HTTP layer,
since a redirect + query-string-preservation is exactly the kind of
thing that only means something proven end-to-end over real HTTP.
"""
import http.client
import os
import socket
import subprocess
import sys
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


def _get_no_redirect(port, path):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', path)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status, resp.getheader('Location')


def _wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = _get_no_redirect(port, '/health')
            if status:
                return True
        except Exception:
            time.sleep(0.5)
    return False


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


def main():
    proc = None
    try:
        port = _free_port()
        env = dict(os.environ)
        env['PYTHONPATH'] = REPO_ROOT
        env['PORT'] = str(port)
        proc = subprocess.Popen(
            [_python_with_flask(), os.path.join(REPO_ROOT, 'app.py')],
            cwd=REPO_ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server_up = _wait_for_server(port)
        check('Flask instance started', server_up)
        if not server_up:
            return

        status, location = _get_no_redirect(
            port, '/static/multifamily-benchmark-form.html?utm_source=email&utm_campaign=spring&mf_ref=abc123')
        check('legacy route returns 302 (not the old static file)', status == 302)
        check('redirect target is /mf-review/benchmark with query string preserved',
              location == '/mf-review/benchmark?utm_source=email&utm_campaign=spring&mf_ref=abc123')

        status2, location2 = _get_no_redirect(port, '/static/multifamily-benchmark-form.html')
        check('legacy route with no query string still redirects cleanly', status2 == 302)
        check('redirect target with no query string has no trailing "?"', location2 == '/mf-review/benchmark')

        status3, _ = _get_no_redirect(port, '/mf-review/benchmark')
        check('the new destination page itself is reachable (200)', status3 == 200)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All legacy-benchmark-form-redirect (Phase A) tests passed.')


if __name__ == '__main__':
    main()
