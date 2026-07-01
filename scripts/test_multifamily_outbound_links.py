#!/usr/bin/env python
"""
Funnel Phase 3 tests: outbound-to-form merge-back
(multifamily_outbound_links, matching.merge_engine.merge_incoming_on_intake
touch_type, repository.get_active_lead_by_id, form_variants recommendation
helpers).

Covers: minting/reading/listing/marking-converted an outbound link; the
deterministic merge-back path (an incoming, never-persisted submission
folds into the SPECIFIC lead the token points at, exactly mirroring what
api/routes/multifamily.py::create_lead does when a payload carries
mf_ref) with a 'conversion' attribution touch and no duplicate lead
created; get_active_lead_by_id following a merged-away lead's
merged_into_id chain (the token's original target may have been folded
into a survivor by an unrelated fuzzy/auto match since the link was
minted); and the page-recommendation helpers used by the Outreach
Workbench.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository
from multifamily.intake import build_lead_from_intake
from multifamily.matching.merge_engine import merge_incoming_on_intake
from multifamily.forms.form_variants import (
    recommend_form_variant_for_situation, recommendation_reason_for_slug,
)

_FAILURES = []
_M = '(OUTBOUNDLINK TEST)'
_lead_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def _make_and_persist_lead(company_suffix, email, **extra):
    payload = {
        'name': 'Outbound Tester', 'company': f'Outboundflow Co {company_suffix} {_M}',
        'email': email, 'state': 'TX', 'city': 'Austin',
        'leadSituation': 'benchmark', 'source': 'manual',
    }
    payload.update(extra)
    lead, errors = build_lead_from_intake(payload)
    assert errors == [], errors
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    _lead_ids.append(lead.id)
    return lead


def test_mint_and_read_outbound_link():
    lead = _make_and_persist_lead('Mint', 'outboundmint@example.com')
    row = repository.create_outbound_link(
        lead_id=lead.id, offer_type='acquisition_assumption_review', page_variant='acquisition',
        campaign_id='q3-push', source='outbound_email', created_by='rep@example.com',
    )
    check('create_outbound_link returns a token', bool(row.get('token')))
    check('create_outbound_link stores lead_id', row['lead_id'] == lead.id)
    check('create_outbound_link stores page_variant', row['page_variant'] == 'acquisition')
    check('create_outbound_link stores campaign_id', row['campaign_id'] == 'q3-push')
    check('create_outbound_link starts unconverted', row['converted_at'] is None and row['converted_lead_id'] is None)

    fetched = repository.get_outbound_link(row['token'])
    check('get_outbound_link finds the link by token', fetched is not None and fetched['token'] == row['token'])

    listed = repository.get_outbound_links_for_lead(lead.id)
    check('get_outbound_links_for_lead lists the link', any(l['token'] == row['token'] for l in listed))

    check('unknown token returns None', repository.get_outbound_link('not-a-real-token') is None)

    repository.mark_outbound_link_converted(row['token'], lead.id)
    reconverted = repository.get_outbound_link(row['token'])
    check('mark_outbound_link_converted sets converted_at', reconverted['converted_at'] is not None)
    check('mark_outbound_link_converted sets converted_lead_id', reconverted['converted_lead_id'] == lead.id)

    repository.delete_outbound_links_for_lead(lead.id)
    check('cleanup: no outbound links remain for this lead', repository.get_outbound_links_for_lead(lead.id) == [])


def test_deterministic_merge_back_via_token():
    # The survivor: an existing lead an operator is working, generated a
    # link for.
    survivor = _make_and_persist_lead('Survivor', 'outboundsurvivor@example.com')
    link = repository.create_outbound_link(
        lead_id=survivor.id, offer_type='acquisition_assumption_review',
        page_variant='acquisition', source='outbound_email',
    )

    # The incoming submission: built but NEVER persisted — this mirrors
    # create_lead()'s state right before the merge decision.
    incoming_payload = {
        'name': 'Different Name Entirely', 'company': f'Totally Different Co {_M}',
        'email': 'a-different-email-entirely@example.com', 'state': 'CA', 'city': 'Los Angeles',
        'leadSituation': 'acquisition', 'source': 'benchmark_form',
        'offerType': 'acquisition_assumption_review', 'pageVariant': 'acquisition',
        'targetCloseDate': '2026-08-15', 'mfRef': link['token'],
    }
    incoming, errors = build_lead_from_intake(incoming_payload)
    check('incoming lead builds with no errors', errors == [] and incoming is not None)
    incoming_id_never_persisted = incoming.id

    resolved_target = repository.get_active_lead_by_id(link['lead_id'])
    check('token resolves to the survivor lead', resolved_target is not None and resolved_target.id == survivor.id)

    merge_incoming_on_intake(resolved_target, incoming, touch_type='conversion')
    repository.mark_outbound_link_converted(link['token'], resolved_target.id)

    check('the incoming submission was never inserted as its own lead',
          repository.get_lead_by_id(incoming_id_never_persisted) is None)

    reloaded = repository.get_lead_by_id(survivor.id)
    check('survivor absorbed the acquisition signal', any(s.signal_type == 'acquisition' for s in reloaded.signals))
    check('survivor absorbed the incoming benchmark_form_submit signal',
          any(s.signal_type == 'benchmark_form_submit' and (s.detail or {}).get('lead_situation') == 'acquisition'
              for s in reloaded.signals))

    touches = repository.get_attribution_for_lead(survivor.id)
    conversion_touches = [t for t in touches if t.get('touch_type') == 'conversion']
    check('a conversion attribution touch was recorded', len(conversion_touches) == 1)
    check('the conversion touch carries the offer_type', conversion_touches[0].get('offer_type') == 'acquisition_assumption_review')
    check('the conversion touch carries the page_variant', conversion_touches[0].get('page_variant') == 'acquisition')

    link_after = repository.get_outbound_link(link['token'])
    check('the link is marked converted', link_after['converted_at'] is not None)
    check('the link records which lead it converted into', link_after['converted_lead_id'] == survivor.id)

    repository.delete_outbound_links_for_lead(survivor.id)


def test_get_active_lead_by_id_follows_merge_chain():
    loser = _make_and_persist_lead('Loser', 'outboundloser@example.com')
    survivor = _make_and_persist_lead('Chainsurvivor', 'outboundchainsurvivor@example.com')

    # Simulate an unrelated fuzzy/auto match merging `loser` away AFTER an
    # outbound link was minted pointing at it — the token should still
    # resolve to wherever the identity actually lives now.
    repository.mark_lead_merged(loser.id, survivor.id)

    resolved = repository.get_active_lead_by_id(loser.id)
    check('get_active_lead_by_id follows merged_into_id to the survivor', resolved is not None and resolved.id == survivor.id)

    still_direct = repository.get_active_lead_by_id(survivor.id)
    check('get_active_lead_by_id returns an unmerged lead directly', still_direct is not None and still_direct.id == survivor.id)

    check('get_active_lead_by_id returns None for a nonexistent lead', repository.get_active_lead_by_id('not-a-real-lead-id') is None)


def test_recommend_form_variant_for_situation():
    cases = [
        ('renewal', 'renewal-pressure'),
        ('acquisition', 'acquisition'),
        ('refinance', 'lender-requirement'),
        ('construction', 'builders-risk'),
        ('completion', 'completion-leaseup'),
        ('benchmark', 'benchmark'),
        ('operating', 'benchmark'),  # no dedicated page for 'operating' -> falls back
        (None, 'benchmark'),
        ('not_a_real_situation', 'benchmark'),
    ]
    for situation, expected_slug in cases:
        variant = recommend_form_variant_for_situation(situation)
        check(f'situation={situation!r} recommends {expected_slug}', variant.slug == expected_slug)
        reason = recommendation_reason_for_slug(variant.slug)
        check(f'{expected_slug}: has a non-empty recommendation reason', bool(reason))


def main():
    try:
        test_mint_and_read_outbound_link()
        test_deterministic_merge_back_via_token()
        test_get_active_lead_by_id_follows_merge_chain()
        test_recommend_form_variant_for_situation()
    finally:
        for lid in _lead_ids:
            repository.delete_outbound_links_for_lead(lid)
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        print(f'\nCleaned up {len(_lead_ids)} tracked lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All outbound-link merge-back (Funnel Phase 3) tests passed.')


if __name__ == '__main__':
    main()
