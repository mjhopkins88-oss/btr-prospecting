"""
API Routes: Capital Groups

Capital groups are the long-term relationships behind the deals —
developers, capital partners, operators, and brokers who deploy
capital repeatedly across many projects. Unlike properties (which
are transactional), capital groups are tracked over time so the
operator can remember who they know, where they stand, who is
active in which markets, and when to re-engage.

This module exposes the CRUD + touchpoint endpoints that the
frontend uses to render the Capital Groups list, detail page, and
activity timeline. Linked properties are surfaced via the
``capital_group_id`` column on ``li_projects`` — a group can have
many projects, but a project can belong to at most one group.
"""
from flask import Blueprint, request, jsonify
import json

from shared.database import fetch_all, fetch_one, execute, new_id

capital_groups_bp = Blueprint(
    'capital_groups', __name__, url_prefix='/api/capital-groups'
)


# ---------------------------------------------------------------------------
# Enum-like value sets. Kept in code rather than a dedicated table so the
# frontend and backend can share the same lists without an extra round trip.
# ---------------------------------------------------------------------------

VALID_TYPES = ('developer', 'capital_partner', 'operator', 'broker')
VALID_STATUSES = (
    'prospect',        # identified but no contact yet
    'warm',            # initial conversations happening
    'engaged',         # in active dialogue / sharing deals
    'partner',         # doing deals together
    'dormant',         # previously engaged, now quiet
    'cold',            # lost the thread, re-engagement needed
)


def _parse_markets(raw):
    """Parse the markets field, which is stored as a JSON array string."""
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _serialize_markets(value):
    """Normalize an inbound markets value to a JSON array string."""
    if value is None:
        return None
    if isinstance(value, str):
        # Allow comma-separated input for convenience.
        parts = [p.strip() for p in value.split(',') if p.strip()]
        return json.dumps(parts)
    if isinstance(value, list):
        return json.dumps([str(p).strip() for p in value if str(p).strip()])
    return json.dumps([])


def _row_to_group(row):
    """Shape a DB row into the JSON response object for a capital group."""
    if not row:
        return None
    out = dict(row)
    out['markets'] = _parse_markets(out.get('markets'))
    return out


def _clamp_warmth(value):
    """Clamp warmth_score to the 1–10 range expected by the UI."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 1
    return max(1, min(10, v))


# ---------------------------------------------------------------------------
# LIST
# ---------------------------------------------------------------------------

@capital_groups_bp.route('', methods=['GET'])
def list_capital_groups():
    """List capital groups with optional filtering and search."""
    q = (request.args.get('q') or '').strip()
    group_type = request.args.get('type')
    status = request.args.get('status')
    market = (request.args.get('market') or '').strip()
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT id, name, type, markets, strategy, notes,
               relationship_status, warmth_score,
               last_contacted_at, created_at, updated_at,
               opportunity_stage, opportunity_value, opportunity_notes, opportunity_updated_at
        FROM capital_groups
        WHERE 1=1
    '''
    params = []

    if q:
        sql += ' AND (LOWER(name) LIKE ? OR LOWER(strategy) LIKE ?)'
        pattern = f'%{q.lower()}%'
        params.extend([pattern, pattern])
    if group_type and group_type in VALID_TYPES:
        sql += ' AND type = ?'
        params.append(group_type)
    if status and status in VALID_STATUSES:
        sql += ' AND relationship_status = ?'
        params.append(status)
    if market:
        # markets is a JSON array string; fall back to substring match.
        sql += ' AND LOWER(markets) LIKE ?'
        params.append(f'%{market.lower()}%')
    if request.args.get('has_opportunity'):
        sql += ' AND opportunity_stage IS NOT NULL'

    sql += ' ORDER BY warmth_score DESC, name ASC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    groups = [_row_to_group(r) for r in rows]
    return jsonify({'capital_groups': groups, 'count': len(groups)})


# ---------------------------------------------------------------------------
# CREATE
# ---------------------------------------------------------------------------

@capital_groups_bp.route('', methods=['POST'])
def create_capital_group():
    """Create a new capital group."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name required'}), 400

    group_type = data.get('type') or 'developer'
    if group_type not in VALID_TYPES:
        return jsonify({'error': f'invalid type, must be one of {VALID_TYPES}'}), 400

    status = data.get('relationship_status') or 'prospect'
    if status not in VALID_STATUSES:
        return jsonify({'error': f'invalid relationship_status, must be one of {VALID_STATUSES}'}), 400

    gid = new_id()
    try:
        execute(
            '''
            INSERT INTO capital_groups
                (id, name, type, markets, strategy, notes,
                 relationship_status, warmth_score, last_contacted_at,
                 website, linkedin_url,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''',
            [
                gid,
                name,
                group_type,
                _serialize_markets(data.get('markets')),
                data.get('strategy'),
                data.get('notes'),
                status,
                _clamp_warmth(data.get('warmth_score') or 1),
                data.get('last_contacted_at'),
                data.get('website'),
                data.get('linkedin_url'),
            ],
        )
    except Exception as e:
        return jsonify({'error': f'insert failed: {e}'}), 400

    created = fetch_one('SELECT * FROM capital_groups WHERE id = ?', [gid])

    try:
        from services.task_engine import rule_new_group
        rule_new_group(gid, name)
    except Exception:
        pass

    return jsonify(_row_to_group(created)), 201


# ---------------------------------------------------------------------------
# DETAIL
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>', methods=['GET'])
def get_capital_group(group_id):
    """Get a single capital group with linked projects and touchpoint timeline."""
    group = fetch_one('SELECT * FROM capital_groups WHERE id = ?', [group_id])
    if not group:
        return jsonify({'error': 'not found'}), 404

    out = _row_to_group(group)

    # Linked projects (the "properties" the group is driving).
    out['properties'] = fetch_all(
        '''
        SELECT id, name, city, state, project_type, status,
               unit_count, estimated_value, updated_at
        FROM li_projects
        WHERE capital_group_id = ?
        ORDER BY updated_at DESC
        ''',
        [group_id],
    )

    # Touchpoint timeline — most recent first, with contact name.
    out['touchpoints'] = fetch_all(
        '''
        SELECT t.id, t.type, t.outcome, t.notes, t.occurred_at, t.created_at,
               t.contact_id, c.first_name AS contact_first, c.last_name AS contact_last
        FROM capital_group_touchpoints t
        LEFT JOIN prospecting_contacts c ON t.contact_id = c.id
        WHERE t.capital_group_id = ?
        ORDER BY t.occurred_at DESC
        LIMIT 200
        ''',
        [group_id],
    )

    # Contacts linked to this group.
    out['contacts'] = fetch_all(
        '''
        SELECT id, first_name, last_name, title, email, phone, notes,
               last_touch_at, relationship_stage, created_at
        FROM prospecting_contacts
        WHERE group_id = ?
        ORDER BY first_name, last_name
        ''',
        [group_id],
    )

    return jsonify(out)


# ---------------------------------------------------------------------------
# UPDATE (partial)
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>', methods=['PATCH'])
def update_capital_group(group_id):
    """Partially update a capital group."""
    data = request.get_json(silent=True) or {}
    existing = fetch_one('SELECT id FROM capital_groups WHERE id = ?', [group_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

    # Only the fields that were actually passed get updated; everything else
    # stays as-is. This keeps the UI's partial-edit flows (warmth slider,
    # status dropdown, notes field) from accidentally clobbering siblings.
    sets = []
    params = []

    if 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'name cannot be empty'}), 400
        sets.append('name = ?')
        params.append(name)
    if 'type' in data:
        if data['type'] not in VALID_TYPES:
            return jsonify({'error': f'invalid type, must be one of {VALID_TYPES}'}), 400
        sets.append('type = ?')
        params.append(data['type'])
    if 'markets' in data:
        sets.append('markets = ?')
        params.append(_serialize_markets(data['markets']))
    if 'strategy' in data:
        sets.append('strategy = ?')
        params.append(data['strategy'])
    if 'notes' in data:
        sets.append('notes = ?')
        params.append(data['notes'])
    if 'relationship_status' in data:
        if data['relationship_status'] not in VALID_STATUSES:
            return jsonify({'error': f'invalid relationship_status, must be one of {VALID_STATUSES}'}), 400
        sets.append('relationship_status = ?')
        params.append(data['relationship_status'])
    if 'warmth_score' in data:
        sets.append('warmth_score = ?')
        params.append(_clamp_warmth(data['warmth_score']))
    if 'last_contacted_at' in data:
        sets.append('last_contacted_at = ?')
        params.append(data['last_contacted_at'])
    if 'website' in data:
        sets.append('website = ?')
        params.append(data['website'])
    if 'linkedin_url' in data:
        sets.append('linkedin_url = ?')
        params.append(data['linkedin_url'])
    if 'opportunity_stage' in data:
        sets.append('opportunity_stage = ?')
        params.append(data['opportunity_stage'] or None)
        sets.append('opportunity_updated_at = CURRENT_TIMESTAMP')
    if 'opportunity_value' in data:
        sets.append('opportunity_value = ?')
        params.append(data['opportunity_value'])
    if 'opportunity_notes' in data:
        sets.append('opportunity_notes = ?')
        params.append(data['opportunity_notes'])

    if not sets:
        return jsonify({'error': 'no updatable fields provided'}), 400

    sets.append('updated_at = CURRENT_TIMESTAMP')
    params.append(group_id)

    execute(
        f'UPDATE capital_groups SET {", ".join(sets)} WHERE id = ?',
        params,
    )

    updated = fetch_one('SELECT * FROM capital_groups WHERE id = ?', [group_id])
    return jsonify(_row_to_group(updated))


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>', methods=['DELETE'])
def delete_capital_group(group_id):
    """Delete a capital group and its touchpoints. Linked projects are
    unlinked (capital_group_id set to NULL), not deleted — the project
    graph is a separate concern and shouldn't vanish when a relationship
    record is tidied up."""
    existing = fetch_one('SELECT id FROM capital_groups WHERE id = ?', [group_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

    execute('UPDATE li_projects SET capital_group_id = NULL WHERE capital_group_id = ?', [group_id])
    execute('DELETE FROM capital_group_touchpoints WHERE capital_group_id = ?', [group_id])
    execute('DELETE FROM capital_groups WHERE id = ?', [group_id])
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# TOUCHPOINTS — log a contact event against the relationship timeline
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>/touchpoints', methods=['POST'])
def create_touchpoint(group_id):
    """Log a new touchpoint and bump last_contacted_at on the parent group."""
    existing = fetch_one('SELECT id FROM capital_groups WHERE id = ?', [group_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

    data = request.get_json(silent=True) or {}
    ttype = (data.get('type') or '').strip()
    if not ttype:
        return jsonify({'error': 'type required (e.g. call, email, meeting, note)'}), 400

    tid = new_id()
    occurred_at = data.get('occurred_at')
    contact_id = data.get('contact_id') or None

    if occurred_at:
        execute(
            '''
            INSERT INTO capital_group_touchpoints
                (id, capital_group_id, contact_id, type, outcome, notes, occurred_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''',
            [tid, group_id, contact_id, ttype, data.get('outcome'), data.get('notes'), occurred_at],
        )
    else:
        execute(
            '''
            INSERT INTO capital_group_touchpoints
                (id, capital_group_id, contact_id, type, outcome, notes, occurred_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''',
            [tid, group_id, contact_id, ttype, data.get('outcome'), data.get('notes')],
        )

    if contact_id:
        execute(
            'UPDATE prospecting_contacts SET last_touch_at = CURRENT_TIMESTAMP WHERE id = ?',
            [contact_id],
        )

    # Always roll the parent's "last contacted" forward so the list view's
    # re-engagement signal stays accurate without the UI needing two calls.
    execute(
        '''
        UPDATE capital_groups
        SET last_contacted_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''',
        [group_id],
    )

    touchpoint = fetch_one(
        'SELECT * FROM capital_group_touchpoints WHERE id = ?', [tid]
    )

    try:
        from services.task_engine import rule_meeting_followup, rule_proposal_followup, _log_feed
        group = fetch_one('SELECT name FROM capital_groups WHERE id = ?', [group_id])
        gname = group['name'] if group else ''
        notes = data.get('notes') or ''
        if ttype == 'meeting':
            rule_meeting_followup(group_id, gname, notes)
        elif ttype in ('proposal', 'coverage'):
            rule_proposal_followup(group_id, gname, notes)
        else:
            _log_feed(group_id, 'touchpoint', f'{ttype.capitalize()} logged', notes or f'{ttype} with {gname}')
    except Exception:
        pass

    return jsonify(touchpoint), 201


@capital_groups_bp.route('/<group_id>/touchpoints', methods=['GET'])
def list_touchpoints(group_id):
    """List touchpoints for a capital group, newest first."""
    rows = fetch_all(
        '''
        SELECT id, type, outcome, notes, occurred_at, created_at
        FROM capital_group_touchpoints
        WHERE capital_group_id = ?
        ORDER BY occurred_at DESC
        LIMIT 500
        ''',
        [group_id],
    )
    return jsonify({'touchpoints': rows, 'count': len(rows)})


@capital_groups_bp.route('/<group_id>/schedule-followup', methods=['POST'])
def schedule_group_followup(group_id):
    """Schedule a follow-up task for the group using interval-based selection."""
    group = fetch_one('SELECT id, name FROM capital_groups WHERE id = ?', [group_id])
    if not group:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json(silent=True) or {}
    intervals = {'1w': 7, '2w': 14, '3w': 21, '1m': 30, '6wk': 42, '2m': 60}
    interval = data.get('interval', '2w')
    days = intervals.get(interval, 14)
    from datetime import datetime, timedelta
    due_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    task_id = new_id()
    execute(
        "INSERT INTO prospecting_tasks (id, capital_group_id, type, title, description, "
        "status, priority, due_at, trigger_rule, created_at) "
        "VALUES (?, ?, 'follow_up', ?, ?, 'pending', 6, ?, 'manual_followup', ?)",
        [task_id, group_id, f"Follow up with {group['name']}",
         f'Scheduled {interval} follow-up', due_at, datetime.utcnow().isoformat()]
    )
    return jsonify({'task_id': task_id, 'due_at': due_at, 'days': days}), 201


# ---------------------------------------------------------------------------
# STATUS — convenience endpoint for the quick-action dropdown on the list
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>/status', methods=['PATCH'])
def update_status(group_id):
    """Quick-update the relationship status. The UI's status dropdown on the
    list view calls this so it can avoid building a full PATCH body."""
    data = request.get_json(silent=True) or {}
    status = data.get('relationship_status') or data.get('status')
    if status not in VALID_STATUSES:
        return jsonify({'error': f'invalid status, must be one of {VALID_STATUSES}'}), 400

    rc = execute(
        'UPDATE capital_groups SET relationship_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, group_id],
    )
    if rc == 0:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'ok': True, 'relationship_status': status})


# ---------------------------------------------------------------------------
# PROPERTY LINKING — attach/detach an li_project to/from a capital group
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>/properties/<project_id>', methods=['PUT'])
def link_property(group_id, project_id):
    """Attach an existing project to this capital group."""
    existing = fetch_one('SELECT id FROM capital_groups WHERE id = ?', [group_id])
    if not existing:
        return jsonify({'error': 'capital group not found'}), 404

    project = fetch_one('SELECT id FROM li_projects WHERE id = ?', [project_id])
    if not project:
        return jsonify({'error': 'project not found'}), 404

    execute(
        'UPDATE li_projects SET capital_group_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [group_id, project_id],
    )
    return jsonify({'ok': True, 'capital_group_id': group_id, 'project_id': project_id})


@capital_groups_bp.route('/<group_id>/properties/<project_id>', methods=['DELETE'])
def unlink_property(group_id, project_id):
    """Detach a project from this capital group (does not delete the project)."""
    execute(
        'UPDATE li_projects SET capital_group_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND capital_group_id = ?',
        [project_id, group_id],
    )
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# META — small endpoint the UI uses to populate dropdowns without hardcoding
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/meta', methods=['GET'])
def meta():
    """Return the enum value sets so the frontend dropdowns stay in sync."""
    return jsonify({
        'types': list(VALID_TYPES),
        'relationship_statuses': list(VALID_STATUSES),
    })


# ---------------------------------------------------------------------------
# GROUP CONTACTS — CRUD for contacts scoped to a capital group
# ---------------------------------------------------------------------------

@capital_groups_bp.route('/<group_id>/contacts', methods=['GET'])
def list_group_contacts(group_id):
    """List contacts that belong to a capital group."""
    rows = fetch_all(
        '''
        SELECT id, first_name, last_name, title, email, phone, notes,
               last_touch_at, relationship_stage, created_at
        FROM prospecting_contacts
        WHERE group_id = ?
        ORDER BY first_name, last_name
        ''',
        [group_id],
    )
    return jsonify({'contacts': rows, 'count': len(rows)})


@capital_groups_bp.route('/<group_id>/contacts', methods=['POST'])
def create_group_contact(group_id):
    """Create a contact linked to this capital group."""
    existing = fetch_one('SELECT id FROM capital_groups WHERE id = ?', [group_id])
    if not existing:
        return jsonify({'error': 'group not found'}), 404

    data = request.get_json(silent=True) or {}
    first = (data.get('first_name') or '').strip()
    last = (data.get('last_name') or '').strip()
    if not first and not last:
        return jsonify({'error': 'first_name or last_name required'}), 400

    cid = new_id()
    from datetime import datetime
    now = datetime.utcnow().isoformat()
    execute(
        '''
        INSERT INTO prospecting_contacts
            (id, group_id, first_name, last_name, title, email, phone, notes,
             relationship_stage, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'cold', ?, ?)
        ''',
        [cid, group_id, first, last, data.get('title'), data.get('email'),
         data.get('phone'), data.get('notes'), now, now],
    )
    contact = fetch_one('SELECT * FROM prospecting_contacts WHERE id = ?', [cid])
    return jsonify(contact), 201


@capital_groups_bp.route('/<group_id>/contacts/<contact_id>', methods=['PATCH'])
def update_group_contact(group_id, contact_id):
    """Update a contact's fields (especially notes)."""
    existing = fetch_one(
        'SELECT id FROM prospecting_contacts WHERE id = ? AND group_id = ?',
        [contact_id, group_id],
    )
    if not existing:
        return jsonify({'error': 'contact not found'}), 404

    data = request.get_json(silent=True) or {}
    sets = []
    params = []
    for field in ('first_name', 'last_name', 'title', 'email', 'phone', 'notes'):
        if field in data:
            sets.append(f'{field} = ?')
            params.append(data[field])

    if not sets:
        return jsonify({'error': 'no updatable fields provided'}), 400

    sets.append('updated_at = CURRENT_TIMESTAMP')
    params.append(contact_id)
    execute(f'UPDATE prospecting_contacts SET {", ".join(sets)} WHERE id = ?', params)

    updated = fetch_one('SELECT * FROM prospecting_contacts WHERE id = ?', [contact_id])
    return jsonify(updated)
