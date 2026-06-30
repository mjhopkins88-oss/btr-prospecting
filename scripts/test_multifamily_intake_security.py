#!/usr/bin/env python
"""
Tests for the public-intake hardening layer: honeypot detection,
garbage-content heuristics, DB-backed rate limiting, UTM/attribution
persistence, and rejected/suspicious lead visibility rules.

Exercises the same units api/routes/multifamily.py's POST handler wires
together (spam_guard.* -> intake.build_lead_from_intake -> repository.*),
without needing Flask installed — matches the no-Node/no-extra-deps
style of the other scripts/test_multifamily_*.py scripts. The actual
HTTP layer (rate-limit 429, honeypot 201-with-internal-rejection, etc.)
was verified separately against a live Flask instance in this session.

Inserts real test rows/events tagged with a unique marker and always
cleans them up, so it's safe to run repeatedly against the shared dev
database.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import spam_guard, repository
from multifamily.intake import build_lead_from_intake
from multifamily.pipeline import with_demo_fallback, inbound_leads

_FAILURES = []
_MARKER = '(SECURITY TEST)'
_inserted_ids = []
_event_ip_hashes = []
_event_emails = []


def check(name, condition):
    if condition:
        print(f'  PASS  {name}')
    else:
        print(f'  FAIL  {name}')
        _FAILURES.append(name)


def _base_payload(**overrides):
    payload = {
        'name': 'Security Test Contact', 'company': f'Security Test Co {_MARKER}',
        'email': 'securitytest@example.com', 'state': 'TX', 'leadSituation': 'benchmark',
        'source': 'benchmark_form',
    }
    payload.update(overrides)
    return payload


def _insert(payload, **spam_kwargs):
    lead, errors = build_lead_from_intake(payload, **spam_kwargs)
    assert not errors, errors
    repository.insert_lead(lead)
    _inserted_ids.append(lead.id)
    return lead


def test_normal_benchmark_submission_creates_scored_lead():
    payload = _base_payload(
        utmSource='google', utmMedium='cpc', utmCampaign='q3-push',
    )
    spam_status, reason_codes = spam_guard.classify_spam(payload)
    check('Clean payload classifies as clean', spam_status == 'clean' and reason_codes == [])

    lead = _insert(payload, spam_status=spam_status, spam_reason_codes=reason_codes)
    check('Lead is built', lead is not None)
    check('Lead is scored', lead.score is not None and isinstance(lead.score.total, int))
    check('Lead has a category', lead.score.category in ('call_today', 'hot', 'warm', 'nurture', 'watchlist'))
    check('Lead is not demo', lead.is_demo is False)


def test_honeypot_submission_is_marked_spam():
    payload = _base_payload(
        company=f'Honeypot Bot Co {_MARKER}', email='honeypot-securitytest@example.com',
        website_url='http://bot-filled-this.example.com',
    )
    spam_status, reason_codes = spam_guard.classify_spam(payload)
    check('Honeypot-filled payload classifies as rejected', spam_status == 'rejected')
    check('Honeypot reason code recorded', reason_codes == ['HONEYPOT_FILLED'])

    lead = _insert(payload, spam_status=spam_status, spam_reason_codes=reason_codes)
    check('Honeypot lead is still persisted for audit', lead is not None and lead.spam_status == 'rejected')

    stored_all = repository.get_real_leads(include_rejected=True)
    stored_normal = repository.get_real_leads(include_rejected=False)
    check('Honeypot lead is retrievable via admin (include_rejected=True)',
          any(l.id == lead.id for l in stored_all))
    check('Honeypot lead is excluded from normal views (include_rejected=False)',
          not any(l.id == lead.id for l in stored_normal))


def test_missing_required_fields_still_rejected():
    incomplete = {'name': 'Only A Name'}
    spam_status, reason_codes = spam_guard.classify_spam(incomplete)
    lead, errors = build_lead_from_intake(incomplete, spam_status=spam_status, spam_reason_codes=reason_codes)
    check('Incomplete submission still returns no lead', lead is None)
    check('Incomplete submission still returns clean validation errors', len(errors) > 0 and all(isinstance(e, str) for e in errors))
    check('Validation errors do not mention spam', not any('spam' in e.lower() for e in errors))


def test_repeated_submissions_trigger_rate_limit():
    ip_hash = spam_guard.hash_ip('203.0.113.55')
    email = 'ratelimit-securitytest@example.com'
    _event_ip_hashes.append(ip_hash)
    _event_emails.append(email)

    check('No rate limit before any submissions', spam_guard.check_rate_limit(ip_hash, email) is None)

    for _ in range(spam_guard.RATE_LIMIT_EMAIL_MAX):
        repository.record_intake_event('accepted_clean', ip_hash, email)

    reason = spam_guard.check_rate_limit(ip_hash, email)
    check(f'Rate limit trips after {spam_guard.RATE_LIMIT_EMAIL_MAX} submissions from the same email',
          reason in ('RATE_LIMIT_EMAIL', 'RATE_LIMIT_IP'))


def test_utm_and_attribution_fields_persist():
    payload = _base_payload(
        company=f'UTM Persist Co {_MARKER}', email='utm-persist-securitytest@example.com',
        utmSource='linkedin', utmMedium='social', utmCampaign='fall-launch',
        utmTerm='multifamily insurance', utmContent='variant-b',
        referrer='https://www.linkedin.com/feed', landingPage='https://example.com/benchmark?utm_source=linkedin',
        offerType='benchmark_review',
    )
    lead = _insert(payload, ip_hash='test-ip-hash-utm', user_agent_summary='Mozilla/5.0 (Security Test)')

    stored = [l for l in repository.get_real_leads() if l.id == lead.id]
    check('Lead with UTM fields is retrievable', len(stored) == 1)
    if stored:
        r = stored[0]
        check('utm_source persists', r.utm_source == 'linkedin')
        check('utm_medium persists', r.utm_medium == 'social')
        check('utm_campaign persists', r.utm_campaign == 'fall-launch')
        check('utm_term persists', r.utm_term == 'multifamily insurance')
        check('utm_content persists', r.utm_content == 'variant-b')
        check('referrer persists', r.referrer == 'https://www.linkedin.com/feed')
        check('landing_page persists', r.landing_page == 'https://example.com/benchmark?utm_source=linkedin')
        check('offer_type persists', r.offer_type == 'benchmark_review')
        check('submitted_ip_hash persists', r.submitted_ip_hash == 'test-ip-hash-utm')
        check('user_agent_summary persists', r.user_agent_summary == 'Mozilla/5.0 (Security Test)')


def test_rejected_spam_does_not_appear_in_inbound_view():
    clean_lead = _insert(_base_payload(company=f'Inbound Clean Co {_MARKER}', email='inbound-clean-securitytest@example.com'))
    rejected_payload = _base_payload(
        company=f'Inbound Rejected Co {_MARKER}', email='inbound-rejected-securitytest@example.com',
        website_url='filled-by-bot',
    )
    spam_status, reason_codes = spam_guard.classify_spam(rejected_payload)
    rejected_lead = _insert(rejected_payload, spam_status=spam_status, spam_reason_codes=reason_codes)
    check('Rejected lead fixture is actually rejected', rejected_lead.spam_status == 'rejected')

    real_leads = repository.get_real_leads()  # default: excludes rejected
    combined = with_demo_fallback(real_leads, [], inbound_leads)
    ids = {l.id for l in combined}
    check('Clean lead appears in the inbound view', clean_lead.id in ids)
    check('Rejected (spam) lead does NOT appear in the inbound view', rejected_lead.id not in ids)


def test_suspicious_lead_can_still_be_reviewed():
    payload = _base_payload(
        company=f'www.suspicious-but-real-co.com {_MARKER}', email='suspicious-securitytest@example.com',
    )
    spam_status, reason_codes = spam_guard.classify_spam(payload)
    check('Single garbage signal classifies as suspicious (not rejected)', spam_status == 'suspicious')

    lead = _insert(payload, spam_status=spam_status, spam_reason_codes=reason_codes)
    normal_view = repository.get_real_leads()
    check('Suspicious lead IS visible in normal views (only rejected is excluded)',
          any(l.id == lead.id for l in normal_view))
    check('Suspicious lead retains its reason codes for review', any(l.spam_reason_codes for l in normal_view if l.id == lead.id))


def main():
    try:
        test_normal_benchmark_submission_creates_scored_lead()
        test_honeypot_submission_is_marked_spam()
        test_missing_required_fields_still_rejected()
        test_repeated_submissions_trigger_rate_limit()
        test_utm_and_attribution_fields_persist()
        test_rejected_spam_does_not_appear_in_inbound_view()
        test_suspicious_lead_can_still_be_reviewed()
    finally:
        for lead_id in _inserted_ids:
            try:
                repository.delete_lead(lead_id)
            except Exception:
                pass
        for ip_hash in _event_ip_hashes:
            repository.delete_events_for(ip_hash=ip_hash)
        for email in _event_emails:
            repository.delete_events_for(email=email)
        print(f'\nCleaned up {len(_inserted_ids)} test lead(s) and rate-limit event(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All intake security tests passed.')


if __name__ == '__main__':
    main()
