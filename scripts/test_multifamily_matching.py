#!/usr/bin/env python
"""
Phase B tests for lead matching + merge.

Covers tier classification (auto vs review vs none), the merge engine's
union + re-score behavior, the on-intake auto-merge path, the
tombstone-on-confirmed-merge path, and confirms the demo pipeline +
dedupe are untouched. Inserts test rows tagged with a marker and cleans up.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily import repository, matching
from multifamily.pipeline import run_pipeline
from multifamily.scoring.multifamily_score_engine import score_lead
from multifamily.types import (
    MultifamilyLead, MultifamilyCompany, MultifamilyProperty, MultifamilySignal, MultifamilyContact, new_id,
)

_FAILURES = []
_M = '(MATCH TEST)'
_ids = []


def check(name, condition):
    print(('  PASS  ' if condition else '  FAIL  ') + name)
    if not condition:
        _FAILURES.append(name)


def mk(company, prop=None, email=None, phone=None, state='TX', city='Austin', signal='benchmark_form_submit',
       source='benchmark_form', detail=None, pain=None, source_url=None):
    c = MultifamilyCompany(id=new_id(), name=f'{company} {_M}')
    p = MultifamilyProperty(id=new_id(), name=(prop or f'{company} {_M} Property'), state=state, city=city,
                            asset_type='garden', unit_count=120)
    contacts = [MultifamilyContact(id=new_id(), full_name='A Person', email=email, phone=phone)] if (email or phone) else []
    s = MultifamilySignal(id=new_id(), signal_type=signal, source=source, source_url=source_url, detail=detail or {})
    lead = MultifamilyLead(id=new_id(), company=c, property=p, signals=[s], contacts=contacts, state=state, city=city,
                           primary_signal_type=signal, primary_source=source, source_url=source_url,
                           pain_flags=pain or [], is_demo=False)
    lead.score = score_lead(lead)
    return lead


def _persist(lead):
    repository.insert_lead(lead)
    repository.persist_lead_signals(lead)
    repository.record_lead_attribution_touch(lead, touch_type='first')
    _ids.append(lead.id)
    return lead


def test_classification_tiers():
    base = mk('Lone Star Multifamily', email='ops@lonestar.com')
    check('exact email -> auto',
          (lambda r: r['auto'] and 'exact_email' in r['auto'].reasons)(matching.classify(mk('Other Co', email='ops@lonestar.com'), [base])))
    check('same company+property -> auto',
          (lambda r: r['auto'] and 'exact_company_property' in r['auto'].reasons)(matching.classify(mk('Lone Star Multifamily', email='new@x.com'), [base])))
    check('fuzzy company same state -> review, not auto',
          (lambda r: r['auto'] is None and any('fuzzy_company_same_state' in c.reasons for c in r['review']))(
              matching.classify(mk('Lone Star Multifamily Holdings', prop='A Totally Different Project', email='z@gmail.com'), [base])))
    check('unrelated lead -> no match',
          (lambda r: r['auto'] is None and not r['review'])(matching.classify(mk('Cypress Builders', city='Houston', email='x@cypress.com'), [base])))


def test_merge_unions_and_rescores():
    # Survivor: a permit-only construction lead (no inbound). Incoming: a
    # benchmark form + renewal — should strengthen the survivor materially.
    survivor = mk('Riverbend Capital', signal='permit_filed', source='permit',
                  pain=['builders_risk_need'])
    before = survivor.score.category
    incoming = mk('Riverbend Capital', email='vp@riverbend.com', signal='benchmark_form_submit',
                  detail={'lead_situation': 'renewal'})
    incoming.signals.append(MultifamilySignal(id=new_id(), signal_type='renewal_date_known', source='form',
                                              detail={'days_until_renewal': 30}))
    matching.apply_merge(survivor, incoming)
    sig_types = {s.signal_type for s in survivor.signals}
    check('merge unions signals (permit + benchmark + renewal)',
          {'permit_filed', 'benchmark_form_submit', 'renewal_date_known'} <= sig_types)
    check('merge unions contacts', len(survivor.contacts) >= 1)
    check('survivor re-scored stronger after merge (was %s)' % before, survivor.score.category in ('call_today', 'hot'))


def test_merge_gap_fill_includes_page_variant_and_campaign_id():
    """Audit finding F5 — page_variant/campaign_id were missing from the
    merge gap-fill list, so a survivor with no page_variant/campaign_id
    yet never picked one up from a merged-in incoming lead, even though
    offer_type and every UTM field already did."""
    survivor = mk('Gapfill Holdings', email='ops@gapfill.com')
    check('survivor starts with no page_variant', survivor.page_variant is None)
    check('survivor starts with no campaign_id', survivor.campaign_id is None)

    incoming = mk('Gapfill Holdings', email='second@gapfill.com')
    incoming.page_variant = 'renewal-pressure'
    incoming.campaign_id = 'test-campaign-id-123'
    incoming.offer_type = 'renewal_pressure_test'

    matching.apply_merge(survivor, incoming)
    check('survivor picks up page_variant from the merged-in incoming lead',
          survivor.page_variant == 'renewal-pressure')
    check('survivor picks up campaign_id from the merged-in incoming lead',
          survivor.campaign_id == 'test-campaign-id-123')

    # And confirm gap-fill still respects "survivor's original identity
    # wins" when the survivor ALREADY has a value.
    survivor2 = mk('Gapfill Holdings Two', email='ops2@gapfill.com')
    survivor2.page_variant = 'builders-risk'
    survivor2.campaign_id = 'original-campaign-id'
    incoming2 = mk('Gapfill Holdings Two', email='second2@gapfill.com')
    incoming2.page_variant = 'renewal-pressure'
    incoming2.campaign_id = 'different-campaign-id'
    matching.apply_merge(survivor2, incoming2)
    check("survivor's existing page_variant is NOT overwritten by the incoming lead's",
          survivor2.page_variant == 'builders-risk')
    check("survivor's existing campaign_id is NOT overwritten by the incoming lead's",
          survivor2.campaign_id == 'original-campaign-id')


def test_different_contacts_same_company_property_add_contact():
    survivor = mk('Skyline Residential', email='first@skyline.com')
    incoming = mk('Skyline Residential', email='second@skyline.com')  # same company+property, different contact
    r = matching.classify(incoming, [survivor])
    check('different contact, same company+property -> auto merge', r['auto'] is not None)
    matching.apply_merge(survivor, incoming)
    emails = {c.email for c in survivor.contacts}
    check('both contacts retained (no new lead)', emails == {'first@skyline.com', 'second@skyline.com'})


def test_different_property_same_company_stays_separate():
    survivor = mk('Granite Holdings', prop='Granite Tower One', email='a@granite.com')
    incoming = mk('Granite Holdings', prop='Granite Tower Two', email='b@granite.com')
    r = matching.classify(incoming, [survivor])
    check('same company, different property, different contact -> NOT auto', r['auto'] is None)


def test_on_intake_auto_merge_persists_one_lead():
    survivor = _persist(mk('Auto Merge Co', email='ops@automerge.com'))
    pre_signal_count = repository.get_lead_row(survivor.id).get('signal_count')
    incoming = mk('Auto Merge Co', email='ops@automerge.com', signal='renewal_date_known', source='crm',
                  detail={'days_until_renewal': 40})
    # Simulate the create_lead auto path.
    result = matching.classify(incoming, repository.get_real_leads())
    check('intake classify finds the auto survivor', result['auto'] is not None)
    matching.merge_incoming_on_intake(result['auto'].lead, incoming)
    reloaded = repository.get_lead_by_id(survivor.id)
    check('survivor now carries both signals', len({s.signal_type for s in reloaded.signals}) >= 2)
    check('signal_count grew', repository.get_lead_row(survivor.id).get('signal_count') > (pre_signal_count or 0))
    # incoming never became its own row
    matches = [l for l in repository.get_real_leads() if l.company.name == incoming.company.name]
    check('no duplicate card created (one active lead for the company)', len(matches) == 1)
    check('an attribution touch was added', len(repository.get_attribution_for_lead(survivor.id)) >= 2)


def test_confirmed_merge_tombstones_loser():
    survivor = _persist(mk('Tombstone Co', prop='Tower A', email='a@tomb.com'))
    loser = _persist(mk('Tombstone Co', prop='Tower B', email='b@tomb.com'))  # separate lead
    out = matching.merge_existing(survivor.id, loser.id)
    check('merge_existing returns the survivor', out is not None and out.id == survivor.id)
    active_ids = {l.id for l in repository.get_real_leads()}
    check('loser is tombstoned (excluded from normal views)', loser.id not in active_ids)
    check('survivor still active', survivor.id in active_ids)
    check("loser's signals reassigned to survivor", len(repository.get_signals_for_lead(loser.id)) == 0)


def test_demo_and_dedupe_untouched():
    leads, runs = run_pipeline()
    check('demo pipeline still returns its leads', len(leads) == 13)
    check('demo leads all flagged is_demo', all(l.is_demo for l in leads))


def main():
    try:
        test_classification_tiers()
        test_merge_unions_and_rescores()
        test_merge_gap_fill_includes_page_variant_and_campaign_id()
        test_different_contacts_same_company_property_add_contact()
        test_different_property_same_company_stays_separate()
        test_on_intake_auto_merge_persists_one_lead()
        test_confirmed_merge_tombstones_loser()
        test_demo_and_dedupe_untouched()
    finally:
        for lid in _ids:
            repository.delete_signals_for_lead(lid)
            repository.delete_attribution_for_lead(lid)
            repository.delete_match_candidates_for_lead(lid)
            try:
                repository.delete_lead(lid)
            except Exception:
                pass
        # also nuke any rows tagged with the marker (merge may have created none extra)
        try:
            from db import get_db
            conn = get_db()
            conn.execute("DELETE FROM multifamily_leads WHERE company_name LIKE '%(MATCH TEST)%'")
            conn.commit(); conn.close()
        except Exception:
            pass
        print(f'\nCleaned up {len(_ids)} test lead(s).')

    print()
    if _FAILURES:
        print(f'{len(_FAILURES)} FAILED: {_FAILURES}')
        sys.exit(1)
    print('All matching/merge (Phase B) tests passed.')


if __name__ == '__main__':
    main()
