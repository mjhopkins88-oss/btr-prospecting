#!/usr/bin/env python
"""
Multifamily Command demo runner.

Runs the full mock pipeline (collectors -> dedupe -> scoring ->
explanations -> outreach -> daily brief) and prints a readable summary.
No external API keys or database required — all signal data is mock.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multifamily.pipeline import run_pipeline
from multifamily.daily_brief.multifamily_daily_brief_builder import build_daily_brief


def main():
    leads, source_runs = run_pipeline()

    print('=' * 100)
    print('MULTIFAMILY COMMAND — DEMO RUN')
    print('=' * 100)

    print(f'\nSource runs ({len(source_runs)}):')
    for run in source_runs:
        status = run.notes or 'ok'
        print(f'  - {run.source:18s} records={run.records_found:2d}  {status}')

    # `leads` is already ranked Call Today > Hot > Warm > Nurture > Watchlist
    # (then by score) by pipeline.run_pipeline(), so the dashboard always
    # surfaces real inbound intent ahead of generic trigger-based leads.
    print(f'\nLeads ({len(leads)}), ranked by priority:')
    for lead in leads:
        print(f'\n  {lead.company.name} — {lead.property.name}')
        print(f'    Location:   {lead.city or "?"}, {lead.state or "?"}')
        print(f'    Source:     {lead.primary_source} / {lead.primary_signal_type}')
        print(f'    Source URL: {lead.source_url or "(none)"}')
        print(f'    Confidence: {lead.confidence}')
        print(f'    Score:      {lead.score.total} ({lead.score.category})' if lead.score else '    Score: n/a')
        if lead.score:
            print(f'    Breakdown:  inbound={lead.score.inbound_intent} timing={lead.score.insurance_timing} '
                  f'fit={lead.score.account_fit} pain={lead.score.pain_potential} '
                  f'relationship={lead.score.relationship_warmth} penalties=-{lead.score.penalties}')
            print(f'    Reason codes:      {lead.score.reason_codes}')
            print(f'    Disqualifier codes:{lead.score.disqualifier_codes or "(none)"}')
        print(f'    Why warm:   {lead.why_warm}')
        print(f'    Likely pain:{lead.likely_pain}')
        print(f'    Next step:  {lead.next_best_action}')
        print(f'    Opener:     {lead.suggested_opener}')

    brief = build_daily_brief(leads)
    print('\n' + '=' * 100)
    print('DAILY BRIEF')
    print('=' * 100)
    for section in (
        'inbound_leads', 'website_intent_leads', 'renewal_opportunities', 'trigger_based_opportunities',
        'call_today_leads', 'hot_leads', 'warm_leads', 'nurture_watchlist_leads',
        'leads_needing_more_info',
    ):
        print(f'  {section}: {len(brief[section])}')
    print(f"  top_3_actions_today: {[a['company'] for a in brief['top_3_actions_today']]}")
    print(f"  best_first_call: {brief['best_first_call']['company'] if brief['best_first_call'] else None}")
    print(f"  best_email_draft: {brief['best_email_draft']['company'] if brief['best_email_draft'] else None}")
    print(f"  best_linkedin_touch: {brief['best_linkedin_touch']['company'] if brief['best_linkedin_touch'] else None}")


if __name__ == '__main__':
    main()
