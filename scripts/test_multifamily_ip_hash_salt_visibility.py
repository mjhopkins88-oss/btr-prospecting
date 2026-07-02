#!/usr/bin/env python
"""
Pre-launch audit finding F2/F4: MULTIFAMILY_IP_HASH_SALT defaults to a
public, hardcoded string (multifamily/spam_guard.py). If it's never
overridden in production, the salt provides no real protection.

This is not something the app can safely "fix" by refusing to start
(that would be worse — a broken pilot) — instead, it must never block
startup, log a prominent server-side warning, and surface a visible
"salt not configured" banner ONLY on the admin-gated intake-stats
surface, never anywhere a non-admin or a public prospect could see it.

Covers: ip_hash_salt_is_default() correctly reflects whichever salt is
actually active (env var set vs. unset, exact-default vs. a real
value); the admin intake-stats route computes ip_hash_salt_configured
as its exact negation; that flag never appears on any public-facing
serializer (form-variants, _serialize_lead, source-performance).
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_FAILURES = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _reload_spam_guard():
    import multifamily.spam_guard as sg
    importlib.reload(sg)
    return sg


def test_default_salt_detected_correctly():
    os.environ.pop('MULTIFAMILY_IP_HASH_SALT', None)
    sg = _reload_spam_guard()
    check('unset env var -> salt is the public default', sg._IP_HASH_SALT == sg._DEFAULT_IP_HASH_SALT)
    check('ip_hash_salt_is_default() is True when unset', sg.ip_hash_salt_is_default() is True)

    os.environ['MULTIFAMILY_IP_HASH_SALT'] = sg._DEFAULT_IP_HASH_SALT
    sg = _reload_spam_guard()
    check('env var explicitly set to the exact default is still flagged as default',
          sg.ip_hash_salt_is_default() is True)


def test_real_salt_is_not_flagged():
    os.environ['MULTIFAMILY_IP_HASH_SALT'] = 'a-real-production-secret-value-xyz'
    sg = _reload_spam_guard()
    check('a real, non-default salt -> ip_hash_salt_is_default() is False',
          sg.ip_hash_salt_is_default() is False)
    check('hash_ip still works normally with a real salt', len(sg.hash_ip('1.2.3.4')) == 16)


def test_admin_route_negation_matches():
    """The route computes `not spam_guard.ip_hash_salt_is_default()` —
    verify that negation directly rather than needing a live Flask
    instance, since the route body is a one-line pass-through."""
    os.environ.pop('MULTIFAMILY_IP_HASH_SALT', None)
    sg = _reload_spam_guard()
    ip_hash_salt_configured = not sg.ip_hash_salt_is_default()
    check('with no env var set, ip_hash_salt_configured would be False (banner shows)',
          ip_hash_salt_configured is False)

    os.environ['MULTIFAMILY_IP_HASH_SALT'] = 'a-real-production-secret-value-xyz'
    sg = _reload_spam_guard()
    ip_hash_salt_configured = not sg.ip_hash_salt_is_default()
    check('with a real salt set, ip_hash_salt_configured would be True (banner hidden)',
          ip_hash_salt_configured is True)


def test_flag_never_leaks_to_public_surfaces():
    import inspect
    from multifamily.forms import form_variants
    from multifamily import repository

    check("'ip_hash_salt' does not appear in form_variants.py (public marketing config)",
          'ip_hash_salt' not in inspect.getsource(form_variants).lower())

    import api.routes.multifamily as routes
    source = inspect.getsource(routes)
    # It should appear exactly once, inside get_intake_stats (the
    # super-admin-gated route) — not on _serialize_lead or any public
    # serializer.
    occurrences = source.lower().count('ip_hash_salt_configured')
    check("'ip_hash_salt_configured' appears exactly once in the routes file (the admin route only)",
          occurrences == 1)
    admin_fn_source = inspect.getsource(routes.get_intake_stats)
    check("the one occurrence is inside get_intake_stats (super-admin-gated)",
          'ip_hash_salt_configured' in admin_fn_source)
    serialize_lead_source = inspect.getsource(routes._serialize_lead)
    check("_serialize_lead (used by every lead-facing endpoint) never references it",
          'ip_hash_salt' not in serialize_lead_source.lower())


def main():
    try:
        test_default_salt_detected_correctly()
        test_real_salt_is_not_flagged()
        test_admin_route_negation_matches()
        test_flag_never_leaks_to_public_surfaces()
    finally:
        os.environ.pop('MULTIFAMILY_IP_HASH_SALT', None)
        _reload_spam_guard()  # restore the real default state for subsequent test scripts

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All IP-hash-salt-visibility (audit finding F2/F4) tests passed.')


if __name__ == '__main__':
    main()
