"""
API Routes: AI Assistant
In-app chat assistant with access to prospecting data context.
"""
from flask import Blueprint, request, jsonify
from shared.database import fetch_all, fetch_one, execute, new_id
from datetime import datetime, timedelta
import os
import anthropic
import json

from services.proactive_suggestions import get_proactive_suggestions

assistant_bp = Blueprint('assistant', __name__, url_prefix='/api/assistant')

SYSTEM_PROMPT = """You are a concise, professional AI assistant embedded inside a commercial real estate prospecting application called BTR Prospecting.

You help users with:
- Understanding their pipeline, contacts, and relationships
- Drafting outreach messages (emails, LinkedIn messages, call scripts)
- Suggesting next best actions based on their data
- Logging touchpoints from natural language (you'll return structured JSON for this)
- Updating follow-up intervals or relationship stages

When the user asks to log a touchpoint or update a record, respond with a JSON action block:
{"action": "log_touchpoint", "group_id": "...", "type": "email", "notes": "..."}
{"action": "update_stage", "group_id": "...", "new_stage": "..."}

When the user asks you to draft an email, LinkedIn message, or call script, respond with a draft_message action block containing the ACTUAL full message text:
{"action": "draft_message", "channel": "email", "target_name": "John Smith", "subject": "Following up on our conversation", "body": "Hi John,\\n\\nI wanted to follow up...", "context_note": "Based on your warm relationship and last touch 5 days ago"}

CRITICAL DRAFT RULES:
- The "body" field MUST contain the complete, ready-to-send message text. Never put commentary or explanations in the body.
- Write the draft AS the user, in first person, professional tone.
- Use real names, companies, and context from the DATA CONTEXT below.
- For emails: include subject and full body. For LinkedIn: include body only. For call scripts: include talking points as the body.
- Do NOT explain what the draft does or why you wrote it a certain way. Just provide the draft in the action block.
- Any brief context (1 sentence max) goes in "context_note", not in the body.

Always embed the JSON block inside a <action>...</action> tag so the frontend can parse it.

Keep responses short and actionable. No fluff. Use the data context provided to give specific, personalized advice."""


def _build_context():
    """Gather current app state for the assistant."""
    ctx_parts = []

    groups = fetch_all(
        """SELECT id, name, type, relationship_status, warmth_score,
                  last_contacted_at, opportunity_stage, opportunity_value
           FROM capital_groups
           ORDER BY last_contacted_at DESC NULLS LAST LIMIT 20""", []
    )
    if groups:
        ctx_parts.append("CAPITAL GROUPS (top 20 by recent contact):")
        for g in groups:
            line = f"- {g['name']} | status={g['relationship_status']} warmth={g['warmth_score']}"
            if g['last_contacted_at']:
                line += f" last_contact={str(g['last_contacted_at'])[:10]}"
            if g['opportunity_stage']:
                line += f" opp={g['opportunity_stage']}"
            ctx_parts.append(line)

    contacts = fetch_all(
        """SELECT c.id, c.first_name, c.last_name, c.title, c.relationship_stage,
                  c.last_touch_at, g.name as group_name
           FROM prospecting_contacts c
           LEFT JOIN capital_groups g ON c.group_id = g.id
           ORDER BY c.last_touch_at DESC NULLS LAST LIMIT 15""", []
    )
    if contacts:
        ctx_parts.append("\nCONTACTS (top 15 by recent touch):")
        for c in contacts:
            name = f"{c.get('first_name', '')} {c.get('last_name', '')}".strip()
            line = f"- {name}"
            if c.get('title'):
                line += f" ({c['title']})"
            if c.get('group_name'):
                line += f" at {c['group_name']}"
            if c.get('relationship_stage'):
                line += f" stage={c['relationship_stage']}"
            if c.get('last_touch_at'):
                line += f" last_touch={str(c['last_touch_at'])[:10]}"
            ctx_parts.append(line)

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
        ctx_parts.append("\nGOING COLD (no contact in 30+ days):")
        for r in cold:
            days = (datetime.utcnow() - datetime.fromisoformat(str(r['last_contacted_at']).replace('Z', ''))).days
            ctx_parts.append(f"- {r['name']} — {days}d silent, status={r['relationship_status']}")

    overdue = fetch_all(
        """SELECT t.id, t.title, t.type, g.name as group_name
           FROM prospecting_tasks t
           LEFT JOIN capital_groups g ON t.capital_group_id = g.id
           WHERE t.status = 'pending'
           ORDER BY t.created_at ASC LIMIT 8""", []
    )
    if overdue:
        ctx_parts.append("\nPENDING TASKS:")
        for t in overdue:
            line = f"- {t['title']}"
            if t.get('group_name'):
                line += f" ({t['group_name']})"
            ctx_parts.append(line)

    return "\n".join(ctx_parts)


@assistant_bp.route('/chat', methods=['POST'])
def chat():
    data = request.get_json(silent=True) or {}
    messages = data.get('messages', [])
    if not messages:
        return jsonify({'error': 'No messages provided'}), 400

    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        return jsonify({
            'role': 'assistant',
            'content': 'AI assistant is not configured. Set ANTHROPIC_API_KEY in your environment.'
        })

    context = _build_context()
    system = SYSTEM_PROMPT + "\n\n--- CURRENT DATA CONTEXT ---\n" + context

    api_messages = []
    for m in messages[-20:]:
        api_messages.append({
            'role': m.get('role', 'user'),
            'content': m.get('content', '')
        })

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model='claude-sonnet-4-20250514',
            max_tokens=1024,
            system=system,
            messages=api_messages
        )
        reply = resp.content[0].text if resp.content else ''

        action = None
        if '<action>' in reply and '</action>' in reply:
            try:
                action_str = reply.split('<action>')[1].split('</action>')[0].strip()
                action = json.loads(action_str)
            except (json.JSONDecodeError, IndexError):
                pass

        try:
            suggestions = get_proactive_suggestions()
        except Exception:
            suggestions = None

        return jsonify({
            'role': 'assistant',
            'content': reply,
            'action': action,
            'suggestions': suggestions
        })
    except anthropic.APIError as e:
        return jsonify({
            'role': 'assistant',
            'content': f'AI service error: {str(e)}'
        })
    except Exception as e:
        return jsonify({
            'role': 'assistant',
            'content': f'Something went wrong: {str(e)}'
        })


@assistant_bp.route('/execute-action', methods=['POST'])
def execute_action():
    """Execute a parsed action from the assistant."""
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    if not action:
        return jsonify({'error': 'No action provided'}), 400

    action_type = action.get('action')

    if action_type == 'log_touchpoint':
        group_id = action.get('group_id')
        if not group_id:
            return jsonify({'error': 'group_id required'}), 400
        tp_id = new_id()
        execute(
            """INSERT INTO capital_group_touchpoints (id, capital_group_id, type, notes, outcome, occurred_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            [tp_id, group_id, action.get('type', 'note'), action.get('notes', ''), action.get('outcome', '')]
        )
        execute(
            "UPDATE capital_groups SET last_contacted_at = CURRENT_TIMESTAMP WHERE id = ?",
            [group_id]
        )
        return jsonify({'success': True, 'message': 'Touchpoint logged', 'id': tp_id})

    if action_type == 'update_stage':
        group_id = action.get('group_id')
        new_stage = action.get('new_stage')
        if not group_id or not new_stage:
            return jsonify({'error': 'group_id and new_stage required'}), 400
        execute(
            "UPDATE capital_groups SET relationship_status = ? WHERE id = ?",
            [new_stage, group_id]
        )
        return jsonify({'success': True, 'message': f'Stage updated to {new_stage}'})

    if action_type in ('draft_message', 'draft_outreach'):
        return jsonify({
            'success': True,
            'message': 'Draft ready',
            'draft': {
                'channel': action.get('channel', 'email'),
                'target_name': action.get('target_name', action.get('to', '')),
                'subject': action.get('subject', ''),
                'body': action.get('body', ''),
                'context_note': action.get('context_note', '')
            }
        })

    return jsonify({'error': f'Unknown action type: {action_type}'}), 400
