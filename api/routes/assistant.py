"""
API Routes: AI Assistant — Intelligent operator layer.

Intent-aware chat with structured response cards, CRM context,
action execution, slash commands, and chat persistence.
"""
from flask import Blueprint, request, jsonify
from shared.database import fetch_all, fetch_one, execute, new_id
from datetime import datetime, timedelta
import os
import anthropic
import json
import re

try:
    from services.proactive_suggestions import get_proactive_suggestions
except ImportError:
    def get_proactive_suggestions():
        return None

assistant_bp = Blueprint('assistant', __name__, url_prefix='/api/assistant')

# ---------------------------------------------------------------------------
# System prompt — instructs Claude to return structured card JSON
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are BTR Command — a concise, action-first AI operator embedded inside a commercial real estate prospecting application.

RESPONSE FORMAT:
Always return a JSON object inside <card>...</card> tags with this structure:
{
  "type": "DraftCard|NextActionCard|SignalCard|ContactSummaryCard|CompanySummaryCard|TouchpointLogCard|FollowUpCard|ExportCard|ConfirmationCard|ErrorCard|TextCard",
  "text": "Brief message to the user (1-3 sentences max)",
  "source": "Based on..." or null,
  "data": { ... card-specific data ... },
  "actions": [
    {"id": "action_id", "label": "Button Label", "action": "action_type", "params": {...}}
  ]
}

CARD TYPES AND DATA:

TextCard: Simple text response. data: {}
DraftCard: data: {"channel":"email|linkedin|call","target_name":"...","target_id":"...","subject":"...","body":"...","signal_ref":"..."}
NextActionCard: data: {"recommendations": [{"priority":"high|medium|low","action":"...","target":"...","reason":"..."}]}
SignalCard: data: {"signals": [{"title":"...","summary":"...","source_url":"...","importance":1-10}]}
ContactSummaryCard: data: {"name":"...","id":"...","title":"...","company":"...","stage":"...","last_touch":"...","touchpoint_count":N,"notes":"..."}
CompanySummaryCard: data: {"name":"...","id":"...","status":"...","warmth":N,"last_contact":"...","contacts":N,"opp_stage":"...","opp_value":"..."}
TouchpointLogCard: data: {"contact_name":"...","contact_id":"...","group_id":"...","channel":"email|call|meeting|linkedin|note","summary":"...","direction":"outbound|inbound"}
FollowUpCard: data: {"contact_name":"...","contact_id":"...","due_date":"YYYY-MM-DD","task_type":"follow_up|call|meeting","title":"..."}
ExportCard: data: {"export_type":"contacts|capital_partners|underwriting|prospects","url":"...","filename":"..."}
ConfirmationCard: data: {"what":"...","result":"...","entity_id":"..."}
ErrorCard: data: {"error":"...","suggestion":"..."}

CRITICAL RULES:
1. ALWAYS return exactly ONE <card>...</card> block. No extra text outside the card.
2. For drafts: write the COMPLETE message in data.body. Write AS the user, first person, professional.
3. For actions: only include actions the user can execute. Never pretend an action was completed.
4. Use real data from the CONTEXT below — never fabricate names, IDs, or stats.
5. If data is missing, say so clearly in the "text" field.
6. Keep "text" to 1-3 sentences. Be direct.
7. "source" field should say where your info came from, e.g. "Based on 3 recent touchpoints with Acme Corp" or null if general knowledge.
8. For /sprint: return a NextActionCard with today's prioritized work items.
9. For /brief: return a CompanySummaryCard or NextActionCard summarizing the day.
10. For /next: return the single highest-priority NextActionCard.

SLASH COMMANDS (pre-processed, you receive them as regular messages with context):
/draft [contact] — Draft outreach for this contact
/log [note] — Log a touchpoint
/next — Recommend top next action
/brief — Daily briefing
/export contacts — Trigger contacts export
/signal [company] — Show latest signals for company
/sprint — Start a focused work sprint with prioritized items"""


# ---------------------------------------------------------------------------
# Context builder — gathers CRM state for the assistant
# ---------------------------------------------------------------------------

def _build_context(extra_context=None):
    """Gather current app state for the assistant."""
    ctx_parts = []

    # Capital groups
    groups = fetch_all(
        """SELECT id, name, type, relationship_status, warmth_score,
                  last_contacted_at, opportunity_stage, opportunity_value, notes
           FROM capital_groups
           ORDER BY warmth_score DESC, last_contacted_at DESC NULLS LAST LIMIT 20""", []
    )
    if groups:
        ctx_parts.append("CAPITAL GROUPS (top 20):")
        for g in groups:
            line = f"- [{g['id'][:8]}] {g['name']} | status={g['relationship_status']} warmth={g['warmth_score']}"
            if g.get('last_contacted_at'):
                line += f" last_contact={str(g['last_contacted_at'])[:10]}"
            if g.get('opportunity_stage'):
                line += f" opp_stage={g['opportunity_stage']} opp_value={g.get('opportunity_value', '')}"
            ctx_parts.append(line)

    # Contacts with details
    contacts = fetch_all(
        """SELECT c.id, c.first_name, c.last_name, c.title, c.email, c.phone,
                  c.relationship_stage, c.last_touch_at, c.notes, c.group_id,
                  g.name as group_name
           FROM prospecting_contacts c
           LEFT JOIN capital_groups g ON c.group_id = g.id
           ORDER BY c.last_touch_at DESC NULLS LAST LIMIT 20""", []
    )
    if contacts:
        ctx_parts.append("\nCONTACTS (top 20 by recent touch):")
        for c in contacts:
            name = f"{c.get('first_name', '')} {c.get('last_name', '')}".strip()
            line = f"- [{c['id'][:8]}] {name}"
            if c.get('title'):
                line += f" ({c['title']})"
            if c.get('group_name'):
                line += f" at {c['group_name']}"
            line += f" stage={c.get('relationship_stage', 'cold')}"
            if c.get('last_touch_at'):
                line += f" last_touch={str(c['last_touch_at'])[:10]}"
            if c.get('email'):
                line += f" email={c['email']}"
            ctx_parts.append(line)

    # Recent signals
    signals = fetch_all(
        """SELECT id, title, summary, source_url, importance, signal_type, group_id,
                  contact_id, detected_at
           FROM prospecting_signals
           ORDER BY detected_at DESC NULLS LAST, created_at DESC
           LIMIT 10""", []
    )
    if signals:
        ctx_parts.append("\nRECENT SIGNALS:")
        for s in signals:
            line = f"- [{s['id'][:8]}] {s['title']}"
            if s.get('signal_type'):
                line += f" type={s['signal_type']}"
            if s.get('importance'):
                line += f" importance={s['importance']}"
            if s.get('source_url'):
                line += f" url={s['source_url'][:60]}"
            ctx_parts.append(line)

    # Recent touchpoints
    touchpoints = fetch_all(
        """SELECT t.id, t.channel, t.subject, t.summary, t.occurred_at,
                  c.first_name, c.last_name, g.name as group_name
           FROM prospecting_touchpoints t
           LEFT JOIN prospecting_contacts c ON t.contact_id = c.id
           LEFT JOIN capital_groups g ON t.group_id = g.id
           ORDER BY t.occurred_at DESC LIMIT 8""", []
    )
    if touchpoints:
        ctx_parts.append("\nRECENT TOUCHPOINTS:")
        for t in touchpoints:
            who = f"{t.get('first_name', '')} {t.get('last_name', '')}".strip()
            if not who and t.get('group_name'):
                who = t['group_name']
            line = f"- {t.get('channel', 'note')} with {who or 'unknown'}"
            if t.get('subject'):
                line += f": {t['subject'][:50]}"
            if t.get('occurred_at'):
                line += f" ({str(t['occurred_at'])[:10]})"
            ctx_parts.append(line)

    # Going cold
    cold = fetch_all(
        """SELECT id, name, last_contacted_at, relationship_status
           FROM capital_groups
           WHERE last_contacted_at IS NOT NULL
             AND last_contacted_at < ?
             AND relationship_status NOT IN ('dormant', 'cold')
           ORDER BY last_contacted_at ASC LIMIT 5""",
        [(datetime.utcnow() - timedelta(days=30)).isoformat()]
    )
    if cold:
        ctx_parts.append("\nGOING COLD (30+ days no contact):")
        for r in cold:
            try:
                days = (datetime.utcnow() - datetime.fromisoformat(
                    str(r['last_contacted_at']).replace('Z', '')
                )).days
            except Exception:
                days = '?'
            ctx_parts.append(f"- [{r['id'][:8]}] {r['name']} — {days}d silent")

    # Pending tasks / follow-ups
    tasks = fetch_all(
        """SELECT t.id, t.title, t.type, t.due_at, t.priority,
                  g.name as group_name
           FROM prospecting_tasks t
           LEFT JOIN capital_groups g ON t.capital_group_id = g.id
           WHERE t.status = 'pending'
           ORDER BY t.priority DESC, t.due_at ASC NULLS LAST LIMIT 10""", []
    )
    if tasks:
        ctx_parts.append("\nPENDING TASKS/FOLLOW-UPS:")
        for t in tasks:
            line = f"- [{t['id'][:8]}] {t['title']}"
            if t.get('group_name'):
                line += f" ({t['group_name']})"
            if t.get('due_at'):
                line += f" due={str(t['due_at'])[:10]}"
            ctx_parts.append(line)

    # Stats
    today = datetime.utcnow().strftime('%Y-%m-%d')
    tp_today = fetch_one(
        "SELECT COUNT(*) as cnt FROM prospecting_touchpoints WHERE DATE(occurred_at) = ?",
        [today]
    )
    total_contacts = fetch_one("SELECT COUNT(*) as cnt FROM prospecting_contacts")
    total_groups = fetch_one("SELECT COUNT(*) as cnt FROM capital_groups")

    ctx_parts.append(f"\nSTATS: {total_contacts['cnt'] if total_contacts else 0} contacts, "
                     f"{total_groups['cnt'] if total_groups else 0} capital groups, "
                     f"{tp_today['cnt'] if tp_today else 0} touchpoints today")
    ctx_parts.append(f"TODAY: {datetime.utcnow().strftime('%A, %B %d, %Y')}")

    if extra_context:
        ctx_parts.append(f"\nADDITIONAL CONTEXT:\n{extra_context}")

    return "\n".join(ctx_parts)


# ---------------------------------------------------------------------------
# Slash command pre-processor
# ---------------------------------------------------------------------------

def _preprocess_slash(text):
    """Convert slash commands into natural language with context hints."""
    text = text.strip()
    if not text.startswith('/'):
        return text, None

    parts = text.split(None, 1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ''

    extra_ctx = None

    if cmd == '/draft':
        if arg:
            contact = _find_contact(arg)
            if contact:
                signal = _latest_signal_for(contact.get('group_id'), contact.get('id'))
                extra_ctx = _format_contact_detail(contact, signal)
                return f"Draft outreach for {arg}. Use the contact details and latest signal below.", extra_ctx
        return f"Draft outreach for {arg or 'my warmest contact'}.", extra_ctx

    if cmd == '/log':
        return f"Log a touchpoint: {arg}" if arg else "Help me log a touchpoint.", extra_ctx

    if cmd == '/next':
        return "What is the single most important thing I should do right now?", extra_ctx

    if cmd == '/brief':
        return "Give me a daily briefing: key stats, overdue items, and top priorities for today.", extra_ctx

    if cmd == '/export':
        return f"Export {arg or 'contacts'} data.", extra_ctx

    if cmd == '/signal':
        if arg:
            signals = _find_signals_for(arg)
            if signals:
                extra_ctx = "MATCHING SIGNALS:\n" + "\n".join(
                    f"- {s['title']} (importance={s.get('importance', '?')}) url={s.get('source_url', 'N/A')}"
                    for s in signals[:5]
                )
        return f"Show me the latest signals for {arg or 'all companies'}.", extra_ctx

    if cmd == '/sprint':
        return "Start a focused work sprint. Give me my top 5 prioritized actions for today.", extra_ctx

    return text, extra_ctx


# ---------------------------------------------------------------------------
# Context helpers — find specific records
# ---------------------------------------------------------------------------

def _find_contact(name_query):
    """Find a contact by partial name match."""
    q = f"%{name_query.strip().lower()}%"
    return fetch_one(
        """SELECT c.*, g.name as group_name
           FROM prospecting_contacts c
           LEFT JOIN capital_groups g ON c.group_id = g.id
           WHERE LOWER(c.first_name || ' ' || c.last_name) LIKE ?
              OR LOWER(c.first_name) LIKE ?
              OR LOWER(c.last_name) LIKE ?
           ORDER BY c.last_touch_at DESC NULLS LAST LIMIT 1""",
        [q, q, q]
    )


def _find_group(name_query):
    """Find a capital group by partial name match."""
    q = f"%{name_query.strip().lower()}%"
    return fetch_one(
        "SELECT * FROM capital_groups WHERE LOWER(name) LIKE ? ORDER BY warmth_score DESC LIMIT 1",
        [q]
    )


def _latest_signal_for(group_id=None, contact_id=None):
    """Get latest signal for a group or contact."""
    if group_id:
        return fetch_one(
            "SELECT * FROM prospecting_signals WHERE group_id = ? ORDER BY detected_at DESC LIMIT 1",
            [group_id]
        )
    if contact_id:
        return fetch_one(
            "SELECT * FROM prospecting_signals WHERE contact_id = ? ORDER BY detected_at DESC LIMIT 1",
            [contact_id]
        )
    return None


def _find_signals_for(name_query):
    """Find signals matching a company or contact name."""
    group = _find_group(name_query)
    if group:
        return fetch_all(
            "SELECT * FROM prospecting_signals WHERE group_id = ? ORDER BY detected_at DESC LIMIT 5",
            [group['id']]
        )
    return fetch_all(
        "SELECT * FROM prospecting_signals ORDER BY detected_at DESC LIMIT 5", []
    )


def _format_contact_detail(contact, signal=None):
    """Format a contact's detail for extra context injection."""
    if not contact:
        return ""
    name = f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()
    lines = [f"TARGET CONTACT: {name}"]
    lines.append(f"  id={contact['id']}")
    if contact.get('title'):
        lines.append(f"  title={contact['title']}")
    if contact.get('group_name'):
        lines.append(f"  company={contact['group_name']}")
    if contact.get('email'):
        lines.append(f"  email={contact['email']}")
    lines.append(f"  stage={contact.get('relationship_stage', 'cold')}")
    if contact.get('last_touch_at'):
        lines.append(f"  last_touch={str(contact['last_touch_at'])[:10]}")
    if contact.get('notes'):
        lines.append(f"  notes={contact['notes'][:200]}")

    # Recent touchpoints for this contact
    tps = fetch_all(
        """SELECT channel, subject, summary, occurred_at
           FROM prospecting_touchpoints WHERE contact_id = ?
           ORDER BY occurred_at DESC LIMIT 3""",
        [contact['id']]
    )
    if tps:
        lines.append("  RECENT TOUCHPOINTS:")
        for t in tps:
            lines.append(f"    - {t.get('channel', 'note')}: {t.get('subject') or t.get('summary', '')[:60]} ({str(t.get('occurred_at', ''))[:10]})")

    if signal:
        lines.append(f"  LATEST SIGNAL: {signal.get('title', '')} — {signal.get('summary', '')[:100]}")
        if signal.get('source_url'):
            lines.append(f"    url={signal['source_url']}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@assistant_bp.route('/chat', methods=['POST'])
def chat():
    data = request.get_json(silent=True) or {}
    messages = data.get('messages', [])
    page_context = data.get('page_context', {})

    if not messages:
        return jsonify({'error': 'No messages provided'}), 400

    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        return jsonify({
            'role': 'assistant',
            'content': '',
            'card': {
                'type': 'ErrorCard',
                'text': 'AI assistant is not configured.',
                'data': {'error': 'ANTHROPIC_API_KEY not set', 'suggestion': 'Set it in your environment variables.'},
                'actions': []
            }
        })

    last_msg = messages[-1].get('content', '') if messages else ''
    processed_msg, extra_ctx = _preprocess_slash(last_msg)

    # Build page-aware context
    page_extra = ""
    if page_context.get('active_tab'):
        page_extra += f"\nUser is on the '{page_context['active_tab']}' page."
    if page_context.get('selected_contact_id'):
        contact = fetch_one(
            """SELECT c.*, g.name as group_name FROM prospecting_contacts c
               LEFT JOIN capital_groups g ON c.group_id = g.id
               WHERE c.id = ?""",
            [page_context['selected_contact_id']]
        )
        if contact:
            page_extra += "\n" + _format_contact_detail(contact, _latest_signal_for(contact.get('group_id'), contact['id']))
    if page_context.get('selected_group_id'):
        group = fetch_one("SELECT * FROM capital_groups WHERE id = ?",
                         [page_context['selected_group_id']])
        if group:
            page_extra += f"\nSelected company: {group['name']} (id={group['id'][:8]}, status={group.get('relationship_status')}, warmth={group.get('warmth_score')})"

    combined_extra = (extra_ctx or '') + page_extra
    context = _build_context(combined_extra if combined_extra.strip() else None)
    system = SYSTEM_PROMPT + "\n\n--- CURRENT DATA CONTEXT ---\n" + context

    api_messages = []
    for m in messages[:-1]:
        api_messages.append({
            'role': m.get('role', 'user'),
            'content': m.get('content', '')
        })
    api_messages.append({
        'role': 'user',
        'content': processed_msg
    })
    api_messages = api_messages[-20:]

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model='claude-sonnet-4-20250514',
            max_tokens=1500,
            system=system,
            messages=api_messages
        )
        reply = resp.content[0].text if resp.content else ''

        # Parse structured card
        card = None
        if '<card>' in reply and '</card>' in reply:
            try:
                card_str = reply.split('<card>')[1].split('</card>')[0].strip()
                card = json.loads(card_str)
            except (json.JSONDecodeError, IndexError):
                pass

        # Legacy: parse <action> blocks for backward compat
        action = None
        if not card and '<action>' in reply and '</action>' in reply:
            try:
                action_str = reply.split('<action>')[1].split('</action>')[0].strip()
                action = json.loads(action_str)
                card = _action_to_card(action, reply)
            except (json.JSONDecodeError, IndexError):
                pass

        # Fallback: wrap plain text as TextCard
        if not card:
            clean = re.sub(r'<card>[\s\S]*?</card>', '', reply).strip()
            clean = re.sub(r'<action>[\s\S]*?</action>', '', clean).strip()
            card = {
                'type': 'TextCard',
                'text': clean or reply,
                'source': None,
                'data': {},
                'actions': []
            }

        _persist_chat(messages[-1].get('content', ''), card)

        return jsonify({
            'role': 'assistant',
            'content': card.get('text', ''),
            'card': card,
            'action': action
        })
    except anthropic.APIError as e:
        return jsonify({
            'role': 'assistant',
            'content': str(e),
            'card': {
                'type': 'ErrorCard',
                'text': 'AI service error.',
                'data': {'error': str(e), 'suggestion': 'Try again in a moment.'},
                'actions': []
            }
        })
    except Exception as e:
        return jsonify({
            'role': 'assistant',
            'content': str(e),
            'card': {
                'type': 'ErrorCard',
                'text': 'Something went wrong.',
                'data': {'error': str(e), 'suggestion': 'Try rephrasing your request.'},
                'actions': []
            }
        })


def _action_to_card(action, full_reply):
    """Convert legacy <action> JSON to a card structure."""
    a_type = action.get('action', '')
    clean = re.sub(r'<action>[\s\S]*?</action>', '', full_reply).strip()

    if a_type in ('draft_message', 'draft_outreach'):
        return {
            'type': 'DraftCard',
            'text': clean or 'Here\'s a draft for you.',
            'source': action.get('context_note'),
            'data': {
                'channel': action.get('channel', 'email'),
                'target_name': action.get('target_name', ''),
                'target_id': action.get('target_id', ''),
                'subject': action.get('subject', ''),
                'body': action.get('body', ''),
                'signal_ref': action.get('signal_ref', '')
            },
            'actions': [
                {'id': 'copy_draft', 'label': 'Copy', 'action': 'copy_text', 'params': {}},
                {'id': 'log_tp', 'label': 'Log Touchpoint', 'action': 'log_touchpoint', 'params': {
                    'contact_id': action.get('target_id', ''),
                    'channel': action.get('channel', 'email'),
                    'summary': f"Outreach to {action.get('target_name', '')}"
                }}
            ]
        }

    if a_type == 'log_touchpoint':
        return {
            'type': 'TouchpointLogCard',
            'text': clean or 'Ready to log this touchpoint.',
            'source': None,
            'data': {
                'contact_name': action.get('contact_name', ''),
                'contact_id': action.get('contact_id', ''),
                'group_id': action.get('group_id', ''),
                'channel': action.get('type', 'note'),
                'summary': action.get('notes', ''),
                'direction': 'outbound'
            },
            'actions': [
                {'id': 'confirm_log', 'label': 'Log It', 'action': 'log_touchpoint', 'params': action}
            ]
        }

    if a_type == 'update_stage':
        return {
            'type': 'ConfirmationCard',
            'text': clean or f"Update stage to {action.get('new_stage', '?')}?",
            'source': None,
            'data': {'what': 'stage update', 'result': 'pending'},
            'actions': [
                {'id': 'confirm_stage', 'label': 'Confirm', 'action': 'update_stage', 'params': action}
            ]
        }

    return {
        'type': 'TextCard',
        'text': clean or 'Action parsed.',
        'source': None,
        'data': {},
        'actions': [
            {'id': 'exec', 'label': 'Execute', 'action': a_type, 'params': action}
        ]
    }


# ---------------------------------------------------------------------------
# Action execution
# ---------------------------------------------------------------------------

@assistant_bp.route('/execute-action', methods=['POST'])
def execute_action():
    """Execute a parsed action from the assistant."""
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    params = data.get('params', {})
    if not action:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'No action specified.',
            'data': {'error': 'Missing action'}, 'actions': []
        }}), 400

    try:
        if action == 'log_touchpoint':
            return _exec_log_touchpoint(params)
        if action == 'update_stage':
            return _exec_update_stage(params)
        if action in ('draft_message', 'draft_outreach', 'copy_text'):
            return jsonify({'success': True, 'card': {
                'type': 'ConfirmationCard',
                'text': 'Draft copied to clipboard.',
                'data': {'what': 'copy', 'result': 'success'}, 'actions': []
            }})
        if action == 'create_followup':
            return _exec_create_followup(params)
        if action == 'complete_task':
            return _exec_complete_task(params)
        if action == 'export':
            return _exec_export(params)

        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': f'Unknown action: {action}',
            'data': {'error': f'No handler for {action}'}, 'actions': []
        }}), 400
    except Exception as e:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Action failed.',
            'data': {'error': str(e), 'suggestion': 'Try again.'}, 'actions': []
        }}), 500


def _exec_log_touchpoint(params):
    contact_id = params.get('contact_id')
    group_id = params.get('group_id')
    if not contact_id and not group_id:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Need a contact or company to log against.',
            'data': {'error': 'contact_id or group_id required'}, 'actions': []
        }}), 400

    tp_id = new_id()
    execute(
        """INSERT INTO prospecting_touchpoints
           (id, contact_id, group_id, channel, direction, subject, summary, occurred_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
        [tp_id, contact_id, group_id,
         params.get('channel', 'note'),
         params.get('direction', 'outbound'),
         params.get('subject', ''),
         params.get('summary', params.get('notes', ''))]
    )
    if contact_id:
        execute("UPDATE prospecting_contacts SET last_touch_at = CURRENT_TIMESTAMP WHERE id = ?",
                [contact_id])
    if group_id:
        execute("UPDATE capital_groups SET last_contacted_at = CURRENT_TIMESTAMP WHERE id = ?",
                [group_id])
        tp2 = new_id()
        execute(
            """INSERT INTO capital_group_touchpoints (id, capital_group_id, type, notes, outcome, occurred_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            [tp2, group_id, params.get('channel', 'note'),
             params.get('summary', params.get('notes', '')), '']
        )

    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard',
        'text': 'Touchpoint logged successfully.',
        'data': {'what': 'touchpoint', 'result': 'logged', 'entity_id': tp_id},
        'actions': []
    }})


def _exec_update_stage(params):
    group_id = params.get('group_id')
    new_stage = params.get('new_stage')
    contact_id = params.get('contact_id')

    if contact_id and not group_id:
        execute(
            "UPDATE prospecting_contacts SET relationship_stage = ? WHERE id = ?",
            [new_stage, contact_id]
        )
        return jsonify({'success': True, 'card': {
            'type': 'ConfirmationCard', 'text': f'Contact stage updated to {new_stage}.',
            'data': {'what': 'stage', 'result': new_stage, 'entity_id': contact_id},
            'actions': []
        }})

    if not group_id or not new_stage:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'Missing group_id or new_stage.',
            'data': {'error': 'Incomplete params'}, 'actions': []
        }}), 400
    execute(
        "UPDATE capital_groups SET relationship_status = ? WHERE id = ?",
        [new_stage, group_id]
    )
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard', 'text': f'Stage updated to {new_stage}.',
        'data': {'what': 'stage', 'result': new_stage, 'entity_id': group_id},
        'actions': []
    }})


def _exec_create_followup(params):
    contact_id = params.get('contact_id')
    group_id = params.get('group_id')
    title = params.get('title', 'Follow up')
    due_date = params.get('due_date')

    if not due_date:
        due_date = (datetime.utcnow() + timedelta(days=3)).strftime('%Y-%m-%d')

    task_id = new_id()
    execute(
        """INSERT INTO prospecting_tasks
           (id, capital_group_id, type, title, status, priority, due_at, created_at)
           VALUES (?, ?, 'follow_up', ?, 'pending', 7, ?, CURRENT_TIMESTAMP)""",
        [task_id, group_id, title, due_date]
    )
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard',
        'text': f'Follow-up created: "{title}" due {due_date}.',
        'data': {'what': 'follow_up', 'result': 'created', 'entity_id': task_id},
        'actions': []
    }})


def _exec_complete_task(params):
    task_id = params.get('task_id')
    if not task_id:
        return jsonify({'success': False, 'card': {
            'type': 'ErrorCard', 'text': 'No task ID provided.',
            'data': {'error': 'task_id required'}, 'actions': []
        }}), 400
    execute(
        "UPDATE prospecting_tasks SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
        [task_id]
    )
    return jsonify({'success': True, 'card': {
        'type': 'ConfirmationCard', 'text': 'Task marked complete.',
        'data': {'what': 'task', 'result': 'completed', 'entity_id': task_id},
        'actions': []
    }})


def _exec_export(params):
    export_type = params.get('export_type', 'contacts')
    urls = {
        'contacts': '/api/prospecting/contacts/export',
        'capital_partners': '/api/prospecting/capital-groups-export',
        'underwriting': '/api/underwriting/export?mode=latest',
        'prospects': '/api/export',
    }
    url = urls.get(export_type, urls['contacts'])
    return jsonify({'success': True, 'card': {
        'type': 'ExportCard',
        'text': f'Your {export_type} export is ready to download.',
        'data': {'export_type': export_type, 'url': url,
                 'filename': f"{export_type}_{datetime.utcnow().strftime('%Y-%m-%d')}"},
        'actions': [
            {'id': 'download', 'label': 'Download', 'action': 'download', 'params': {'url': url}}
        ]
    }})


# ---------------------------------------------------------------------------
# Chat persistence (lightweight)
# ---------------------------------------------------------------------------

def _persist_chat(user_msg, card):
    """Log chat exchanges for continuity."""
    try:
        execute(
            """INSERT INTO assistant_chat_log (id, user_message, card_type, card_json, created_at)
               VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            [new_id(), user_msg[:500], card.get('type', 'TextCard'), json.dumps(card)[:2000]]
        )
    except Exception:
        pass


@assistant_bp.route('/history', methods=['GET'])
def chat_history():
    """Return recent chat history."""
    rows = fetch_all(
        """SELECT user_message, card_type, card_json, created_at
           FROM assistant_chat_log
           ORDER BY created_at DESC LIMIT 20""", []
    )
    rows.reverse()
    history = []
    for r in rows:
        history.append({'role': 'user', 'content': r['user_message']})
        try:
            card = json.loads(r['card_json'])
        except Exception:
            card = {'type': 'TextCard', 'text': '(history)', 'data': {}, 'actions': []}
        history.append({'role': 'assistant', 'content': card.get('text', ''), 'card': card})
    return jsonify({'history': history})
