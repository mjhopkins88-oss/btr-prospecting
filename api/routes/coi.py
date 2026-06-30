"""
API Routes: Centers of Influence

Centers of Influence (COI) are the professional connectors behind deals —
brokers, consultants, lenders, attorneys, referral partners, and market
connectors who repeatedly introduce opportunities. Like Capital Groups,
they are relationship entities tracked over time with touchpoints,
contacts, warmth scoring, and follow-up workflows.
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import json

from shared.database import fetch_all, fetch_one, execute, new_id

coi_bp = Blueprint('coi', __name__, url_prefix='/api/coi')


VALID_TYPES = ('broker', 'consultant', 'lender', 'attorney', 'referral_partner', 'market_connector')
VALID_STATUSES = (
    'prospect',
    'warm',
    'engaged',
    'partner',
    'dormant',
    'cold',
)


def _parse_markets(raw):
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
    if value is None:
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(',') if p.strip()]
        return json.dumps(parts)
    if isinstance(value, list):
        return json.dumps([str(p).strip() for p in value if str(p).strip()])
    return json.dumps([])


def _row_to_coi(row):
    if not row:
        return None
    out = dict(row)
    out['markets'] = _parse_markets(out.get('markets'))
    return out


def _clamp_warmth(value):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 1
    return max(1, min(10, v))


# ---------------------------------------------------------------------------
# LIST
# ---------------------------------------------------------------------------

@coi_bp.route('', methods=['GET'])
def list_coi():
    q = (request.args.get('q') or '').strip()
    coi_type = request.args.get('type')
    status = request.args.get('status')
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))

    sql = '''
        SELECT id, name, type, markets, specialty, notes,
               relationship_status, warmth_score,
               last_contacted_at, created_at, updated_at
        FROM centers_of_influence
        WHERE 1=1
    '''
    params = []

    if q:
        sql += ' AND (LOWER(name) LIKE ? OR LOWER(specialty) LIKE ?)'
        pattern = f'%{q.lower()}%'
        params.extend([pattern, pattern])
    if coi_type and coi_type in VALID_TYPES:
        sql += ' AND type = ?'
        params.append(coi_type)
    if status and status in VALID_STATUSES:
        sql += ' AND relationship_status = ?'
        params.append(status)

    sql += ' ORDER BY warmth_score DESC, name ASC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = fetch_all(sql, params)
    items = [_row_to_coi(r) for r in rows]
    return jsonify({'centers_of_influence': items, 'count': len(items)})


# ---------------------------------------------------------------------------
# CREATE
# ---------------------------------------------------------------------------

@coi_bp.route('', methods=['POST'])
def create_coi():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name required'}), 400

    coi_type = data.get('type') or 'broker'
    if coi_type not in VALID_TYPES:
        return jsonify({'error': f'invalid type, must be one of {VALID_TYPES}'}), 400

    status = data.get('relationship_status') or 'prospect'
    if status not in VALID_STATUSES:
        return jsonify({'error': f'invalid relationship_status'}), 400

    cid = new_id()
    try:
        execute(
            '''
            INSERT INTO centers_of_influence
                (id, name, type, markets, specialty, notes,
                 relationship_status, warmth_score, last_contacted_at,
                 website, linkedin_url,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''',
            [
                cid, name, coi_type,
                _serialize_markets(data.get('markets')),
                data.get('specialty'),
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

    created = fetch_one('SELECT * FROM centers_of_influence WHERE id = ?', [cid])
    return jsonify(_row_to_coi(created)), 201


# ---------------------------------------------------------------------------
# DETAIL
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>', methods=['GET'])
def get_coi(coi_id):
    row = fetch_one('SELECT * FROM centers_of_influence WHERE id = ?', [coi_id])
    if not row:
        return jsonify({'error': 'not found'}), 404

    out = _row_to_coi(row)

    out['touchpoints'] = fetch_all(
        '''
        SELECT t.id, t.type, t.outcome, t.notes, t.occurred_at, t.created_at,
               t.contact_id, c.first_name AS contact_first, c.last_name AS contact_last
        FROM coi_touchpoints t
        LEFT JOIN prospecting_contacts c ON t.contact_id = c.id
        WHERE t.coi_id = ?
        ORDER BY t.occurred_at DESC
        LIMIT 200
        ''',
        [coi_id],
    )

    out['contacts'] = fetch_all(
        '''
        SELECT id, first_name, last_name, title, email, phone, notes,
               last_touch_at, relationship_stage, created_at
        FROM prospecting_contacts
        WHERE coi_id = ?
        ORDER BY first_name, last_name
        ''',
        [coi_id],
    )

    return jsonify(out)


# ---------------------------------------------------------------------------
# UPDATE
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>', methods=['PATCH'])
def update_coi(coi_id):
    data = request.get_json(silent=True) or {}
    existing = fetch_one('SELECT id FROM centers_of_influence WHERE id = ?', [coi_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

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
            return jsonify({'error': f'invalid type'}), 400
        sets.append('type = ?')
        params.append(data['type'])
    if 'markets' in data:
        sets.append('markets = ?')
        params.append(_serialize_markets(data['markets']))
    if 'specialty' in data:
        sets.append('specialty = ?')
        params.append(data['specialty'])
    if 'notes' in data:
        sets.append('notes = ?')
        params.append(data['notes'])
    if 'relationship_status' in data:
        if data['relationship_status'] not in VALID_STATUSES:
            return jsonify({'error': 'invalid relationship_status'}), 400
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

    if not sets:
        return jsonify({'error': 'no updatable fields provided'}), 400

    sets.append('updated_at = CURRENT_TIMESTAMP')
    params.append(coi_id)

    execute(f'UPDATE centers_of_influence SET {", ".join(sets)} WHERE id = ?', params)
    updated = fetch_one('SELECT * FROM centers_of_influence WHERE id = ?', [coi_id])
    return jsonify(_row_to_coi(updated))


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>', methods=['DELETE'])
def delete_coi(coi_id):
    existing = fetch_one('SELECT id FROM centers_of_influence WHERE id = ?', [coi_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

    execute('DELETE FROM coi_touchpoints WHERE coi_id = ?', [coi_id])
    execute('UPDATE prospecting_contacts SET coi_id = NULL WHERE coi_id = ?', [coi_id])
    execute('DELETE FROM centers_of_influence WHERE id = ?', [coi_id])
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# TOUCHPOINTS
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>/touchpoints', methods=['POST'])
def create_touchpoint(coi_id):
    existing = fetch_one('SELECT id FROM centers_of_influence WHERE id = ?', [coi_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

    data = request.get_json(silent=True) or {}
    ttype = (data.get('type') or '').strip()
    if not ttype:
        return jsonify({'error': 'type required'}), 400

    tid = new_id()
    occurred_at = data.get('occurred_at')
    contact_id = data.get('contact_id') or None

    if occurred_at:
        execute(
            '''INSERT INTO coi_touchpoints
                (id, coi_id, contact_id, type, outcome, notes, occurred_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            [tid, coi_id, contact_id, ttype, data.get('outcome'), data.get('notes'), occurred_at],
        )
    else:
        execute(
            '''INSERT INTO coi_touchpoints
                (id, coi_id, contact_id, type, outcome, notes, occurred_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
            [tid, coi_id, contact_id, ttype, data.get('outcome'), data.get('notes')],
        )

    if contact_id:
        execute('UPDATE prospecting_contacts SET last_touch_at = CURRENT_TIMESTAMP WHERE id = ?', [contact_id])

    execute(
        'UPDATE centers_of_influence SET last_contacted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [coi_id],
    )

    touchpoint = fetch_one('SELECT * FROM coi_touchpoints WHERE id = ?', [tid])
    return jsonify(touchpoint), 201


@coi_bp.route('/<coi_id>/touchpoints', methods=['GET'])
def list_touchpoints(coi_id):
    rows = fetch_all(
        'SELECT * FROM coi_touchpoints WHERE coi_id = ? ORDER BY occurred_at DESC LIMIT 500',
        [coi_id],
    )
    return jsonify({'touchpoints': rows, 'count': len(rows)})


# ---------------------------------------------------------------------------
# FOLLOW-UP
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>/schedule-followup', methods=['POST'])
def schedule_followup(coi_id):
    row = fetch_one('SELECT id, name FROM centers_of_influence WHERE id = ?', [coi_id])
    if not row:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json(silent=True) or {}
    intervals = {'1w': 7, '2w': 14, '3w': 21, '1m': 30, '6wk': 42, '2m': 60}
    interval = data.get('interval', '2w')
    days = intervals.get(interval, 14)
    due_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    task_id = new_id()
    execute(
        "INSERT INTO prospecting_tasks (id, capital_group_id, type, title, description, "
        "status, priority, due_at, trigger_rule, created_at) "
        "VALUES (?, ?, 'follow_up', ?, ?, 'pending', 6, ?, 'manual_followup', ?)",
        [task_id, coi_id, f"Follow up with {row['name']}",
         f'Scheduled {interval} follow-up', due_at, datetime.utcnow().isoformat()]
    )
    return jsonify({'task_id': task_id, 'due_at': due_at, 'days': days}), 201


# ---------------------------------------------------------------------------
# STATUS
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>/status', methods=['PATCH'])
def update_status(coi_id):
    data = request.get_json(silent=True) or {}
    status = data.get('relationship_status') or data.get('status')
    if status not in VALID_STATUSES:
        return jsonify({'error': f'invalid status'}), 400
    rc = execute(
        'UPDATE centers_of_influence SET relationship_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, coi_id],
    )
    if rc == 0:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'ok': True, 'relationship_status': status})


# ---------------------------------------------------------------------------
# CONTACTS
# ---------------------------------------------------------------------------

@coi_bp.route('/<coi_id>/contacts', methods=['GET'])
def list_contacts(coi_id):
    rows = fetch_all(
        '''SELECT id, first_name, last_name, title, email, phone, notes,
               last_touch_at, relationship_stage, created_at
        FROM prospecting_contacts WHERE coi_id = ?
        ORDER BY first_name, last_name''',
        [coi_id],
    )
    return jsonify({'contacts': rows, 'count': len(rows)})


@coi_bp.route('/<coi_id>/contacts', methods=['POST'])
def create_contact(coi_id):
    existing = fetch_one('SELECT id FROM centers_of_influence WHERE id = ?', [coi_id])
    if not existing:
        return jsonify({'error': 'not found'}), 404

    data = request.get_json(silent=True) or {}
    first = (data.get('first_name') or '').strip()
    last = (data.get('last_name') or '').strip()
    if not first and not last:
        return jsonify({'error': 'first_name or last_name required'}), 400

    cid = new_id()
    now = datetime.utcnow().isoformat()
    execute(
        '''INSERT INTO prospecting_contacts
            (id, coi_id, first_name, last_name, title, email, phone, notes,
             relationship_stage, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'cold', ?, ?)''',
        [cid, coi_id, first, last, data.get('title'), data.get('email'),
         data.get('phone'), data.get('notes'), now, now],
    )
    contact = fetch_one('SELECT * FROM prospecting_contacts WHERE id = ?', [cid])
    return jsonify(contact), 201


# ---------------------------------------------------------------------------
# META
# ---------------------------------------------------------------------------

@coi_bp.route('/meta', methods=['GET'])
def meta():
    return jsonify({
        'types': list(VALID_TYPES),
        'relationship_statuses': list(VALID_STATUSES),
    })
