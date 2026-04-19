"""
Relationship-First Prospecting Rules Engine

Implements 6 task generation rules and next-best-action logic for
contact-centric prospecting. Separate from services.task_engine
(which handles group-level automation); this module operates on
individual contacts and signals.
"""
import json
from datetime import datetime, timedelta
from shared.database import fetch_all, fetch_one, execute, new_id


STAGE_COLD = 'cold'
STAGE_INITIAL = 'initial_outreach'
STAGE_LIGHT = 'light_conversation'
STAGE_ACTIVE = 'active'
STAGE_WARM = 'warm'
STAGE_STRATEGIC = 'strategic'
STAGE_DORMANT = 'dormant'

VALID_STAGES = {
    STAGE_COLD, STAGE_INITIAL, STAGE_LIGHT, STAGE_ACTIVE,
    STAGE_WARM, STAGE_STRATEGIC, STAGE_DORMANT
}

NBA_SIGNAL_COMPANY = 'signal_company'
NBA_SIGNAL_INDUSTRY = 'signal_industry'
NBA_OVERDUE_FOLLOWUP = 'overdue_followup'
NBA_STALE_CHECKIN = 'stale_checkin'
NBA_INITIAL_OUTREACH = 'initial_outreach'


def _now():
    return datetime.utcnow()


def _iso(dt):
    return dt.isoformat() if dt else None


def _add_business_days(start, days):
    d = start
    added = 0
    while added < days:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


def _has_open_task(contact_id, group_id, rule_tag):
    where = ["trigger_rule = ?", "status IN ('pending', 'in_progress')"]
    params = [rule_tag]
    if contact_id:
        where.append("contact_id = ?")
        params.append(contact_id)
    elif group_id:
        where.append("capital_group_id = ? AND contact_id IS NULL")
        params.append(group_id)
    else:
        return False
    row = fetch_one(f"SELECT id FROM prospecting_tasks WHERE {' AND '.join(where)}", params)
    return row is not None


def _create_task(contact_id=None, group_id=None, signal_id=None,
                 task_type='follow_up', title='Task', description='',
                 channel='email', due_at=None, priority=5,
                 generated_reason='', next_best_action_type=None,
                 rule_tag=''):
    if _has_open_task(contact_id, group_id, rule_tag):
        return None
    tid = new_id()
    execute(
        "INSERT INTO prospecting_tasks "
        "(id, capital_group_id, contact_id, signal_id, type, title, description, channel, "
        "status, priority, due_at, trigger_rule, generated_reason, next_best_action_type, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)",
        [tid, group_id, contact_id, signal_id, task_type, title, description, channel,
         priority, _iso(due_at), rule_tag, generated_reason, next_best_action_type,
         _iso(_now()), _iso(_now())]
    )
    return tid


# ── Rule 1: contact added with first_reached_out_at and no reply ─────
def rule_initial_followup(contact_id):
    c = fetch_one("SELECT * FROM prospecting_contacts WHERE id = ?", [contact_id])
    if not c or not c.get('first_reached_out_at'):
        return None
    if c.get('last_touch_at') and c['last_touch_at'] > c['first_reached_out_at']:
        return None
    try:
        start = datetime.fromisoformat(c['first_reached_out_at'])
    except (ValueError, TypeError):
        start = _now()
    due = _add_business_days(start, 7)
    name = f"{c.get('first_name') or ''} {c.get('last_name') or ''}".strip() or 'contact'
    return _create_task(
        contact_id=contact_id, group_id=c.get('group_id'),
        task_type='follow_up', title=f'Follow-up — {name}',
        description=f'7 business days since initial outreach. Send follow-up note.',
        channel='email', due_at=due, priority=7,
        generated_reason='initial outreach sent 7 business days ago, no reply logged',
        next_best_action_type=NBA_OVERDUE_FOLLOWUP,
        rule_tag='initial_followup'
    )


# ── Rule 2: light conversation / active no touch 30 days → check-in ──
def rule_stale_30d_relationship():
    threshold = (_now() - timedelta(days=30)).isoformat()
    contacts = fetch_all(
        "SELECT * FROM prospecting_contacts WHERE relationship_stage IN (?, ?) "
        "AND last_touch_at IS NOT NULL AND last_touch_at < ?",
        [STAGE_LIGHT, STAGE_ACTIVE, threshold]
    )
    created = 0
    for c in contacts:
        name = f"{c.get('first_name') or ''} {c.get('last_name') or ''}".strip() or 'contact'
        tid = _create_task(
            contact_id=c['id'], group_id=c.get('group_id'),
            task_type='check_in', title=f'Check-in — {name}',
            description='Relationship has been quiet for 30+ days. Send a light check-in.',
            channel='email', due_at=_now() + timedelta(days=1), priority=6,
            generated_reason='30-day relationship gap on active contact',
            next_best_action_type=NBA_STALE_CHECKIN,
            rule_tag='stale_30d'
        )
        if tid:
            created += 1
    return created


# ── Rule 3: strategic / warm no touch 45-60 days → high priority ─────
def rule_stale_45_60d_relationship():
    threshold = (_now() - timedelta(days=45)).isoformat()
    contacts = fetch_all(
        "SELECT * FROM prospecting_contacts WHERE relationship_stage IN (?, ?) "
        "AND last_touch_at IS NOT NULL AND last_touch_at < ?",
        [STAGE_WARM, STAGE_STRATEGIC, threshold]
    )
    created = 0
    for c in contacts:
        name = f"{c.get('first_name') or ''} {c.get('last_name') or ''}".strip() or 'contact'
        tid = _create_task(
            contact_id=c['id'], group_id=c.get('group_id'),
            task_type='re_engage', title=f'Re-engage — {name}',
            description=f'{c.get("relationship_stage", "warm")} relationship has 45+ days of silence.',
            channel='call', due_at=_now(), priority=9,
            generated_reason=f'{c.get("relationship_stage")} relationship stale 45+ days',
            next_best_action_type=NBA_STALE_CHECKIN,
            rule_tag='stale_45d_strategic'
        )
        if tid:
            created += 1
    return created


# ── Rule 4: company-specific signal → notice + task ──────────────────
def rule_company_signal(signal_id):
    sig = fetch_one("SELECT * FROM prospecting_signals WHERE id = ?", [signal_id])
    if not sig or sig.get('signal_scope') != 'company' or not sig.get('group_id'):
        return None

    nid = new_id()
    execute(
        "INSERT INTO prospecting_notices (id, group_id, contact_id, signal_id, title, summary, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'new', ?)",
        [nid, sig.get('group_id'), sig.get('contact_id'), signal_id,
         sig.get('title'), sig.get('summary'), _iso(_now())]
    )

    contact = None
    if sig.get('contact_id'):
        contact = fetch_one("SELECT * FROM prospecting_contacts WHERE id = ?", [sig['contact_id']])
    if not contact and sig.get('group_id'):
        contact = fetch_one(
            "SELECT * FROM prospecting_contacts WHERE group_id = ? ORDER BY last_touch_at DESC NULLS LAST LIMIT 1"
            if _is_pg() else
            "SELECT * FROM prospecting_contacts WHERE group_id = ? ORDER BY COALESCE(last_touch_at, '') DESC LIMIT 1",
            [sig['group_id']]
        )
    group = fetch_one("SELECT name FROM capital_groups WHERE id = ?", [sig['group_id']])
    target_name = f"{contact.get('first_name') or ''} {contact.get('last_name') or ''}".strip() if contact else (group['name'] if group else 'group')

    importance = sig.get('importance') or 5
    _create_task(
        contact_id=contact['id'] if contact else None,
        group_id=sig.get('group_id'), signal_id=signal_id,
        task_type='signal_outreach',
        title=f'Signal outreach — {target_name}',
        description=sig.get('summary') or sig.get('title', ''),
        channel='email', due_at=_now() + timedelta(days=1),
        priority=max(7, min(10, importance + 3)),
        generated_reason=f'company-specific signal: {sig.get("title")}',
        next_best_action_type=NBA_SIGNAL_COMPANY,
        rule_tag=f'signal_company_{signal_id}'
    )
    return nid


# ── Rule 5: industry signal → match to relevant contacts ─────────────
def rule_industry_signal(signal_id, match_types=None, match_stages=None):
    sig = fetch_one("SELECT * FROM prospecting_signals WHERE id = ?", [signal_id])
    if not sig or sig.get('signal_scope') != 'industry':
        return 0

    where = ["1=1"]
    params = []
    if match_types:
        placeholders = ','.join(['?'] * len(match_types))
        where.append(f"g.type IN ({placeholders})")
        params.extend(match_types)
    if match_stages:
        placeholders = ','.join(['?'] * len(match_stages))
        where.append(f"c.relationship_stage IN ({placeholders})")
        params.extend(match_stages)

    contacts = fetch_all(
        "SELECT c.*, g.name AS group_name FROM prospecting_contacts c "
        "LEFT JOIN capital_groups g ON g.id = c.group_id "
        f"WHERE {' AND '.join(where)}",
        params
    )

    created = 0
    for c in contacts:
        nid = new_id()
        execute(
            "INSERT INTO prospecting_notices (id, group_id, contact_id, signal_id, title, summary, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'new', ?)",
            [nid, c.get('group_id'), c['id'], signal_id,
             sig.get('title'), sig.get('summary'), _iso(_now())]
        )
        name = f"{c.get('first_name') or ''} {c.get('last_name') or ''}".strip() or 'contact'
        _create_task(
            contact_id=c['id'], group_id=c.get('group_id'), signal_id=signal_id,
            task_type='signal_outreach',
            title=f'Industry signal outreach — {name}',
            description=sig.get('summary') or sig.get('title', ''),
            channel='email', due_at=_now() + timedelta(days=2),
            priority=6,
            generated_reason=f'industry signal: {sig.get("title")}',
            next_best_action_type=NBA_SIGNAL_INDUSTRY,
            rule_tag=f'signal_industry_{signal_id}_{c["id"]}'
        )
        created += 1
    return created


# ── Rule 6: task complete + touchpoint → update last_touch + NBA ─────
def rule_task_complete(task_id, touchpoint_data=None):
    task = fetch_one("SELECT * FROM prospecting_tasks WHERE id = ?", [task_id])
    if not task:
        return None

    execute(
        "UPDATE prospecting_tasks SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?",
        [_iso(_now()), _iso(_now()), task_id]
    )

    tp_id = None
    if touchpoint_data:
        tp_id = new_id()
        execute(
            "INSERT INTO prospecting_touchpoints "
            "(id, contact_id, group_id, property_id, channel, direction, subject, summary, occurred_at, outcome, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [tp_id, task.get('contact_id'), task.get('capital_group_id'),
             touchpoint_data.get('property_id'),
             touchpoint_data.get('channel') or task.get('channel') or 'email',
             touchpoint_data.get('direction') or 'outbound',
             touchpoint_data.get('subject') or task.get('title'),
             touchpoint_data.get('summary') or '',
             _iso(_now()),
             touchpoint_data.get('outcome') or '',
             _iso(_now())]
        )

    now = _iso(_now())
    if task.get('contact_id'):
        execute(
            "UPDATE prospecting_contacts SET last_touch_at = ?, updated_at = ? WHERE id = ?",
            [now, now, task['contact_id']]
        )
    if task.get('capital_group_id'):
        execute(
            "UPDATE capital_groups SET last_touch_at = ?, last_contacted_at = ?, updated_at = ? WHERE id = ?",
            [now, now, now, task['capital_group_id']]
        )

    nba = compute_next_best_action(contact_id=task.get('contact_id'), group_id=task.get('capital_group_id'))
    return {'task_id': task_id, 'touchpoint_id': tp_id, 'next_best_action': nba}


# ── Next-best-action for a contact or group ──────────────────────────
def compute_next_best_action(contact_id=None, group_id=None):
    where = []
    params = []
    if contact_id:
        where.append("contact_id = ?")
        params.append(contact_id)
    elif group_id:
        where.append("capital_group_id = ?")
        params.append(group_id)
    else:
        return None
    where.append("status = 'pending'")

    order = (
        "CASE next_best_action_type "
        f"WHEN '{NBA_SIGNAL_COMPANY}' THEN 1 "
        f"WHEN '{NBA_SIGNAL_INDUSTRY}' THEN 2 "
        f"WHEN '{NBA_OVERDUE_FOLLOWUP}' THEN 3 "
        f"WHEN '{NBA_STALE_CHECKIN}' THEN 4 "
        f"WHEN '{NBA_INITIAL_OUTREACH}' THEN 5 "
        "ELSE 6 END"
    )
    row = fetch_one(
        f"SELECT id, type, title, description, channel, priority, due_at, next_best_action_type, generated_reason "
        f"FROM prospecting_tasks WHERE {' AND '.join(where)} "
        f"ORDER BY {order} ASC, priority DESC, due_at ASC LIMIT 1",
        params
    )
    if row:
        return row

    if contact_id:
        c = fetch_one("SELECT last_touch_at, first_reached_out_at, relationship_stage FROM prospecting_contacts WHERE id = ?", [contact_id])
        if c and not c.get('last_touch_at') and not c.get('first_reached_out_at'):
            return {
                'type': 'initial_outreach',
                'title': 'Initial outreach',
                'description': 'No contact yet. Send first outreach.',
                'channel': 'email',
                'next_best_action_type': NBA_INITIAL_OUTREACH,
                'generated_reason': 'no touches logged'
            }
    return None


def _is_pg():
    try:
        from db import is_postgres
        return is_postgres()
    except Exception:
        return False


# ── Daily runner for time-based rules (2 and 3) ──────────────────────
def run_daily_rules():
    r2 = rule_stale_30d_relationship()
    r3 = rule_stale_45_60d_relationship()
    return {'stale_30d_created': r2, 'stale_45d_created': r3}


# ── Ingest a signal from Daily Discovery and apply rules ─────────────
def ingest_signal(scope, title, summary='', source_url='', signal_type='', importance=5,
                  group_id=None, contact_id=None, property_id=None,
                  match_types=None, match_stages=None):
    """Store a prospecting signal, then fire rule 4 or rule 5 based on scope."""
    if scope not in ('company', 'industry', 'property'):
        return None
    sid = new_id()
    execute(
        "INSERT INTO prospecting_signals "
        "(id, group_id, contact_id, property_id, signal_scope, signal_type, title, summary, source_url, importance, detected_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [sid, group_id, contact_id, property_id, scope, signal_type, title, summary,
         source_url, importance, _iso(_now()), _iso(_now())]
    )
    if scope == 'company':
        rule_company_signal(sid)
    elif scope == 'industry':
        rule_industry_signal(sid, match_types=match_types, match_stages=match_stages)
    return sid


# ── SignalStack prefill payload ──────────────────────────────────────
def build_signalstack_payload(task_id, sender_identity=None):
    task = fetch_one("SELECT * FROM prospecting_tasks WHERE id = ?", [task_id])
    if not task:
        return None

    contact = None
    if task.get('contact_id'):
        contact = fetch_one("SELECT * FROM prospecting_contacts WHERE id = ?", [task['contact_id']])

    group = None
    if task.get('capital_group_id'):
        group = fetch_one(
            "SELECT id, name, type, markets, relationship_status, warmth_score, website, linkedin_url "
            "FROM capital_groups WHERE id = ?",
            [task['capital_group_id']]
        )
        if group and group.get('markets'):
            try:
                group['markets'] = json.loads(group['markets'])
            except (json.JSONDecodeError, TypeError):
                pass

    signal = None
    if task.get('signal_id'):
        signal = fetch_one("SELECT title, summary, source_url, signal_type, detected_at FROM prospecting_signals WHERE id = ?", [task['signal_id']])

    last_tp = None
    if task.get('contact_id'):
        last_tp = fetch_one(
            "SELECT channel, direction, subject, summary, occurred_at "
            "FROM prospecting_touchpoints WHERE contact_id = ? ORDER BY occurred_at DESC LIMIT 1",
            [task['contact_id']]
        )
    elif task.get('capital_group_id'):
        last_tp = fetch_one(
            "SELECT channel, direction, subject, summary, occurred_at "
            "FROM prospecting_touchpoints WHERE group_id = ? ORDER BY occurred_at DESC LIMIT 1",
            [task['capital_group_id']]
        )

    angle = _suggested_angle(task, signal, contact, group)

    return {
        'task_id': task_id,
        'sender': sender_identity or {'name': 'BTR Command', 'email': ''},
        'contact': contact,
        'group': group,
        'relationship_stage': (contact or {}).get('relationship_stage') or (group or {}).get('relationship_status'),
        'last_touch': last_tp,
        'trigger': signal or {'title': task.get('title'), 'summary': task.get('generated_reason')},
        'suggested_angle': angle,
        'channel': task.get('channel') or 'email',
        'task_type': task.get('type'),
        'title': task.get('title'),
        'description': task.get('description'),
    }


def _suggested_angle(task, signal, contact, group):
    nba = task.get('next_best_action_type')
    if nba == NBA_SIGNAL_COMPANY and signal:
        return f"Reference the company signal ('{signal.get('title')}') as a reason for reaching out."
    if nba == NBA_SIGNAL_INDUSTRY and signal:
        return f"Share the industry development ('{signal.get('title')}') and tie it to their portfolio."
    if nba == NBA_OVERDUE_FOLLOWUP:
        return "Polite follow-up on prior outreach. Keep short, offer one value-add."
    if nba == NBA_STALE_CHECKIN:
        stage = (contact or {}).get('relationship_stage') or (group or {}).get('relationship_status') or 'contact'
        return f"Relationship has gone quiet. Re-engage with a {stage}-appropriate touch (market update, intro, or check-in)."
    if nba == NBA_INITIAL_OUTREACH:
        return "First outreach. Lead with relevance, keep it human, ask for a brief intro call."
    return "Send a tailored outreach referencing the task context."
