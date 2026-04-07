"""
Daily Lead Brief Generator.
Produces a summary of new leads, top opportunities, and market activity.
"""
import json
from datetime import datetime, timedelta

try:
    import anthropic
except ImportError:
    anthropic = None

from shared.config import ANTHROPIC_API_KEY, AI_MODEL
from shared.database import fetch_all, fetch_one, get_db, new_id


def _get_brief_data():
    """Gather data for the daily brief."""
    yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()

    new_signals = fetch_all(
        "SELECT COUNT(*) as cnt, signal_type FROM li_signals "
        "WHERE created_at >= ? GROUP BY signal_type",
        [yesterday]
    )

    top_leads = fetch_all(
        "SELECT l.score, l.grade, l.status, l.next_action, "
        "p.name as project_name, p.city, p.state, p.unit_count, "
        "c.name as company_name "
        "FROM li_leads l "
        "LEFT JOIN li_projects p ON p.id = l.project_id "
        "LEFT JOIN li_companies c ON c.id = l.company_id "
        "ORDER BY l.score DESC LIMIT 10",
        []
    )

    new_leads = fetch_all(
        "SELECT COUNT(*) as cnt FROM li_leads WHERE created_at >= ?",
        [yesterday]
    )

    market_activity = fetch_all(
        "SELECT city, state, COUNT(*) as cnt "
        "FROM li_signals WHERE created_at >= ? "
        "GROUP BY city, state ORDER BY cnt DESC LIMIT 5",
        [yesterday]
    )

    return {
        'new_signals': new_signals,
        'top_leads': top_leads,
        'new_leads_count': new_leads[0]['cnt'] if new_leads else 0,
        'market_activity': market_activity,
    }


def generate_brief():
    """
    Generate the daily lead intelligence brief.
    Returns a structured brief dict.
    """
    data = _get_brief_data()

    brief = {
        'id': new_id(),
        'generated_at': datetime.utcnow().isoformat(),
        'summary': {
            'new_leads': data['new_leads_count'],
            'signals_by_type': {r['signal_type']: r['cnt'] for r in data['new_signals']},
            'total_new_signals': sum(r['cnt'] for r in data['new_signals']),
        },
        'top_leads': [],
        'market_activity': [],
    }

    for lead in data['top_leads']:
        brief['top_leads'].append({
            'project': lead.get('project_name', 'Unknown'),
            'company': lead.get('company_name', 'Unknown'),
            'city': lead.get('city'),
            'state': lead.get('state'),
            'score': lead.get('score', 0),
            'grade': lead.get('grade', 'F'),
            'units': lead.get('unit_count'),
            'action': lead.get('next_action'),
        })

    for ma in data['market_activity']:
        brief['market_activity'].append({
            'city': ma['city'],
            'state': ma['state'],
            'signal_count': ma['cnt'],
        })

    # Optionally generate AI narrative summary
    if ANTHROPIC_API_KEY and anthropic and data['top_leads']:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            prompt = f"""Write a concise 3-4 sentence daily intelligence brief for a BTR/SFR sales team.

Data:
- {data['new_leads_count']} new leads today
- {sum(r['cnt'] for r in data['new_signals'])} new signals detected
- Top markets: {json.dumps(data['market_activity'][:3], default=str)}
- Top lead: {data['top_leads'][0].get('project_name', 'N/A')} ({data['top_leads'][0].get('grade', '?')} grade)

Be direct and actionable. Focus on what matters for the sales team today."""

            resp = client.messages.create(
                model=AI_MODEL,
                max_tokens=300,
                messages=[{'role': 'user', 'content': prompt}]
            )
            brief['narrative'] = resp.content[0].text.strip()
        except Exception as e:
            brief['narrative'] = f"Brief generation note: {e}"

    # Store the brief
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT OR IGNORE INTO li_signals
            (id, source_type, headline, body, signal_type, strength, created_at)
            VALUES (?, 'system', 'Daily Lead Brief', ?, 'brief', 0.0, CURRENT_TIMESTAMP)
        ''', (brief['id'], json.dumps(brief, default=str)))
        conn.commit()
        conn.close()
    except Exception:
        pass

    print(f"[DailyBrief] Generated brief: {data['new_leads_count']} new leads, "
          f"{sum(r['cnt'] for r in data['new_signals'])} signals")
    return brief
