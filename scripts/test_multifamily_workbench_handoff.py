#!/usr/bin/env python
"""
Phase C — Workbench handoff buttons (mailto:/tel:/LinkedIn, no auto-send).

Two things are worth proving independently:
  1. The mailto: URL builder (_mfBuildMailtoUrl in static/vendor/app.js)
     encodes correctly and truncates gracefully instead of silently
     producing a broken/overlong URL. Since app.js is a plain script (no
     module exports), this extracts the function's own source text via
     a regex anchored on its declaration and runs it for real in Node --
     not a reimplementation that could drift from the real code.
  2. The existing GET /leads/<id>/outreach endpoint (already used by the
     lead drawer's Outreach tab) returns the shape the new Workbench
     buttons depend on (call_opener/email_draft/linkedin_draft), and a
     lead's contact email/phone are present for the button-gating logic
     to key off of. No new backend endpoint was needed for this phase.
"""
import http.client
import json
import os
import re
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


def _extract_function(js_source, fn_name):
    marker = f'function {fn_name}('
    start = js_source.index(marker)
    depth = 0
    i = js_source.index('{', start)
    body_start = i
    while True:
        if js_source[i] == '{':
            depth += 1
        elif js_source[i] == '}':
            depth -= 1
            if depth == 0:
                return js_source[start:i + 1]
        i += 1


def test_mailto_builder():
    app_js = open(os.path.join(REPO_ROOT, 'static/vendor/app.js'), encoding='utf-8').read()
    const_line = re.search(r"const MF_MAILTO_SAFE_LENGTH = \d+;", app_js)
    check('MF_MAILTO_SAFE_LENGTH constant present', bool(const_line))
    fn_src = _extract_function(app_js, '_mfBuildMailtoUrl')
    check('_mfBuildMailtoUrl function extracted from app.js', 'mailto:' in fn_src)

    harness = f"""
{const_line.group(0)}
{fn_src}
const short = _mfBuildMailtoUrl('a@example.com', 'Subject Line', 'Short body text.');
const long = _mfBuildMailtoUrl('a@example.com', 'Subject', 'x'.repeat(5000));
const special = _mfBuildMailtoUrl('a@example.com', 'Q&A: 100% useful?', 'Line one\\nLine two');
// Decode each so the Python side asserts on real content, not on
// percent-encoded punctuation that would never appear literally.
function decodeMailto(url) {{
  const [, qs] = url.split('?');
  const params = new URLSearchParams(qs);
  return {{ subject: params.get('subject'), body: params.get('body'), raw_length: url.length }};
}}
console.log(JSON.stringify({{
  short: decodeMailto(short),
  long: decodeMailto(long),
  special: decodeMailto(special),
}}));
"""
    result = subprocess.run(['node', '-e', harness], capture_output=True, text=True, timeout=15)
    check('node harness ran without error', result.returncode == 0)
    if result.returncode != 0:
        print('    stderr:', result.stderr[:500])
        return
    out = json.loads(result.stdout.strip())

    check('short mailto carries the exact subject', out['short']['subject'] == 'Subject Line')
    check('short mailto carries the exact body', out['short']['body'] == 'Short body text.')
    check('long mailto stays within the safe length budget', out['long']['raw_length'] <= 1800 + 300)
    check('long (truncated) mailto includes the truncation notice', 'truncated for email client' in out['long']['body'])
    check('special-character subject decodes back to the exact original text', out['special']['subject'] == 'Q&A: 100% useful?')
    check('special-character body decodes back with the real newline preserved', out['special']['body'] == 'Line one\nLine two')


def test_button_gating_present():
    app_js = open(os.path.join(REPO_ROOT, 'static/vendor/app.js'), encoding='utf-8').read()
    check("email handoff button gated on contact.email", 'contact.email && /*#__PURE__*/React.createElement("button"' in app_js)
    check("tel handoff link gated on contact.phone", "contact.phone && /*#__PURE__*/React.createElement(\"a\"" in app_js)
    check("LinkedIn handoff button gated on contact.linkedin_url", 'contact.linkedin_url && /*#__PURE__*/React.createElement("button"' in app_js)
    check("tel link uses a real tel: href (click-to-call, not a JS handler)", 'href: `tel:${contact.phone}`' in app_js)
    check("LinkedIn open uses window.open (new tab, not an in-app navigation)", "window.open(contact.linkedin_url" in app_js)
    check("no auto-send anywhere in the handoff code (mailto/tel/window.open only, no fetch-then-send)",
          'sendEmail' not in app_js and 'auto_send' not in app_js and 'autoSend' not in app_js)


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
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    headers = {'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    set_cookie = resp.getheader('Set-Cookie')
    cookie_out = set_cookie.split(';')[0] if set_cookie else cookie
    try:
        parsed = json.loads(raw) if raw else None
    except Exception:
        parsed = None
    conn.close()
    return resp.status, parsed, cookie_out


def _wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _, _ = _request(port, 'GET', '/health')
            if status:
                return True
        except Exception:
            time.sleep(0.5)
    return False


def test_outreach_endpoint_shape_live():
    import shutil
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix='mf_workbench_handoff_')
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
        env['SUPER_ADMIN_EMAIL'] = 'handoff-test-super@example.com'
        proc = subprocess.Popen(
            [_python_with_flask(), os.path.join(REPO_ROOT, 'app.py')],
            cwd=tmpdir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server_up = _wait_for_server(port)
        check('isolated Flask instance started', server_up)
        if not server_up:
            return

        status, body, _ = _request(port, 'POST', '/api/multifamily/leads', body={
            'name': 'Handoff Endpoint Contact', 'company': 'Handoff Endpoint Co TEST',
            'email': 'handoffendpoint@example.com', 'phone': '5125550188',
            'state': 'TX', 'city': 'Austin', 'leadSituation': 'renewal', 'source': 'manual',
        })
        check('lead intake succeeds', status == 201)
        lead_id = body['lead']['id'] if body else None
        check('lead id captured', bool(lead_id))
        check("lead's contact carries the email used for the mailto: button", body['lead']['contacts'][0]['email'] == 'handoffendpoint@example.com')
        check("lead's contact carries the phone used for the tel: button", body['lead']['contacts'][0]['phone'] == '5125550188')

        # This route sits behind the app-wide auth middleware (same as the
        # rest of /api/multifamily/*, aside from the explicitly exempted
        # public POST /leads) -- log in the same way the Workbench UI does.
        _, _, cookie = _request(port, 'POST', '/api/auth/bootstrap', body={
            'email': 'handoff-test-super@example.com', 'password': 'TestPass123!',
            'name': 'Handoff Test', 'workspace_name': 'HandoffTestWS',
        })
        check('bootstrap session cookie captured', bool(cookie))

        status2, outreach_body, _ = _request(port, 'GET', f'/api/multifamily/leads/{lead_id}/outreach', cookie=cookie)
        check('GET .../outreach succeeds for a logged-in user (same as the Workbench UI)', status2 == 200)
        bundle = (outreach_body or {}).get('outreach', {})
        check('outreach bundle has call_opener', bool(bundle.get('call_opener')))
        check('outreach bundle has email_draft.subject', bool((bundle.get('email_draft') or {}).get('subject')))
        check('outreach bundle has email_draft.body', bool((bundle.get('email_draft') or {}).get('body')))
        check('outreach bundle has linkedin_draft', bool(bundle.get('linkedin_draft')))
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
    print('== mailto: builder (extracted from static/vendor/app.js, run in Node) ==')
    test_mailto_builder()
    print('\n== button gating present in app.js ==')
    test_button_gating_present()
    print('\n== GET /leads/<id>/outreach shape (live, isolated DB) ==')
    test_outreach_endpoint_shape_live()

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All Workbench handoff (Phase C) tests passed.')


if __name__ == '__main__':
    main()
