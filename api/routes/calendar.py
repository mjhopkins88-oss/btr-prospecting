"""
CRM-integrated Calendar system for meetings.
Supports creating, listing, updating, and post-meeting flows tied to contacts/companies.
"""
import uuid
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from shared.database import fetch_all, fetch_one, execute, new_id

calendar_bp = Blueprint('calendar', __name__, url_prefix='/api/calendar')


def _now():
    return datetime.utcnow().isoformat()


@calendar_bp.route('/meetings', methods=['GET'])
def list_meetings():
    start = request.args.get('start')
    end = request.args.get('end')
    contact_id = request.args.get('contact_id')
    status = request.args.get('status')

    sql = "SELECT m.*, c.first_name, c.last_name, c.title as contact_title, g.name as company_name " \
          "FROM calendar_meetings m " \
          "LEFT JOIN prospecting_contacts c ON c.id = m.contact_id " \
          "LEFT JOIN capital_groups g ON g.id = m.group_id " \
          "WHERE 1=1"
    params = []

    if start:
        sql += " AND m.meeting_date >= ?"
        params.append(start)
    if end:
        sql += " AND m.meeting_date <= ?"
        params.append(end)
    if contact_id:
        sql += " AND m.contact_id = ?"
        params.append(contact_id)
    if status:
        sql += " AND m.status = ?"
        params.append(status)

    sql += " ORDER BY m.meeting_date ASC, m.meeting_time ASC"

    meetings = fetch_all(sql, params)
    for m in meetings:
        m['contact_name'] = ' '.join(filter(None, [m.get('first_name', ''), m.get('last_name', '')]))
    return jsonify({'success': True, 'meetings': meetings})


@calendar_bp.route('/meetings', methods=['POST'])
def create_meeting():
    data = request.get_json(force=True)
    contact_id = data.get('contact_id')
    if not contact_id:
        return jsonify({'success': False, 'error': 'contact_id is required'}), 400

    contact = fetch_one("SELECT c.*, g.name as company_name FROM prospecting_contacts c "
                        "LEFT JOIN capital_groups g ON g.id = c.group_id WHERE c.id = ?", [contact_id])
    if not contact:
        return jsonify({'success': False, 'error': 'Contact not found'}), 404

    meeting_date = data.get('meeting_date')
    meeting_time = data.get('meeting_time', '09:00')
    meeting_type = data.get('meeting_type', 'general')
    if not meeting_date:
        return jsonify({'success': False, 'error': 'meeting_date is required'}), 400

    existing = fetch_one(
        "SELECT id FROM calendar_meetings WHERE contact_id = ? AND meeting_date = ? AND meeting_time = ? AND status != 'cancelled'",
        [contact_id, meeting_date, meeting_time]
    )
    if existing:
        return jsonify({'success': False, 'error': 'A meeting already exists at this time for this contact'}), 409

    mid = new_id()
    now = _now()
    execute(
        "INSERT INTO calendar_meetings (id, contact_id, group_id, meeting_date, meeting_time, "
        "duration_min, meeting_type, title, notes, status, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?)",
        [mid, contact_id, contact.get('group_id'), meeting_date, meeting_time,
         data.get('duration_min', 30), meeting_type,
         data.get('title', f"Meeting with {contact.get('first_name', '')} {contact.get('last_name', '')}".strip()),
         data.get('notes', ''), now, now]
    )

    meeting = fetch_one("SELECT m.*, c.first_name, c.last_name, c.title as contact_title, g.name as company_name "
                        "FROM calendar_meetings m "
                        "LEFT JOIN prospecting_contacts c ON c.id = m.contact_id "
                        "LEFT JOIN capital_groups g ON g.id = m.group_id "
                        "WHERE m.id = ?", [mid])
    if meeting:
        meeting['contact_name'] = ' '.join(filter(None, [meeting.get('first_name', ''), meeting.get('last_name', '')]))
    return jsonify({'success': True, 'meeting': meeting}), 201


@calendar_bp.route('/meetings/<meeting_id>', methods=['GET'])
def get_meeting(meeting_id):
    meeting = fetch_one(
        "SELECT m.*, c.first_name, c.last_name, c.title as contact_title, c.email, c.phone, "
        "c.linkedin_url, c.relationship_stage, c.notes as contact_notes, g.name as company_name "
        "FROM calendar_meetings m "
        "LEFT JOIN prospecting_contacts c ON c.id = m.contact_id "
        "LEFT JOIN capital_groups g ON g.id = m.group_id "
        "WHERE m.id = ?", [meeting_id])
    if not meeting:
        return jsonify({'success': False, 'error': 'Meeting not found'}), 404

    meeting['contact_name'] = ' '.join(filter(None, [meeting.get('first_name', ''), meeting.get('last_name', '')]))

    touchpoints = fetch_all(
        "SELECT * FROM prospecting_touchpoints WHERE contact_id = ? ORDER BY occurred_at DESC LIMIT 5",
        [meeting.get('contact_id')]
    )

    signals = fetch_all(
        "SELECT * FROM prospecting_signals WHERE contact_id = ? OR group_id = ? ORDER BY detected_at DESC LIMIT 5",
        [meeting.get('contact_id'), meeting.get('group_id')]
    )

    return jsonify({'success': True, 'meeting': meeting, 'touchpoints': touchpoints, 'signals': signals})


@calendar_bp.route('/meetings/<meeting_id>', methods=['PATCH'])
def update_meeting(meeting_id):
    existing = fetch_one("SELECT id FROM calendar_meetings WHERE id = ?", [meeting_id])
    if not existing:
        return jsonify({'success': False, 'error': 'Meeting not found'}), 404

    data = request.get_json(force=True)
    allowed = ['meeting_date', 'meeting_time', 'duration_min', 'meeting_type', 'title', 'notes', 'status',
               'outcome', 'outcome_notes', 'next_steps']
    sets = []
    params = []
    for k in allowed:
        if k in data:
            sets.append(f"{k} = ?")
            params.append(data[k])

    if not sets:
        return jsonify({'success': False, 'error': 'No fields to update'}), 400

    sets.append("updated_at = ?")
    params.append(_now())
    params.append(meeting_id)
    execute(f"UPDATE calendar_meetings SET {', '.join(sets)} WHERE id = ?", params)

    updated = fetch_one("SELECT m.*, c.first_name, c.last_name, g.name as company_name "
                        "FROM calendar_meetings m "
                        "LEFT JOIN prospecting_contacts c ON c.id = m.contact_id "
                        "LEFT JOIN capital_groups g ON g.id = m.group_id "
                        "WHERE m.id = ?", [meeting_id])
    if updated:
        updated['contact_name'] = ' '.join(filter(None, [updated.get('first_name', ''), updated.get('last_name', '')]))
    return jsonify({'success': True, 'meeting': updated})


@calendar_bp.route('/meetings/<meeting_id>', methods=['DELETE'])
def delete_meeting(meeting_id):
    existing = fetch_one("SELECT id FROM calendar_meetings WHERE id = ?", [meeting_id])
    if not existing:
        return jsonify({'success': False, 'error': 'Meeting not found'}), 404
    execute("UPDATE calendar_meetings SET status = 'cancelled', updated_at = ? WHERE id = ?", [_now(), meeting_id])
    return jsonify({'success': True})


@calendar_bp.route('/meetings/<meeting_id>/complete', methods=['POST'])
def complete_meeting(meeting_id):
    """Post-meeting flow: log outcome, notes, create touchpoint, optionally create follow-up."""
    meeting = fetch_one("SELECT * FROM calendar_meetings WHERE id = ?", [meeting_id])
    if not meeting:
        return jsonify({'success': False, 'error': 'Meeting not found'}), 404

    data = request.get_json(force=True)
    outcome = data.get('outcome', 'completed')
    outcome_notes = data.get('outcome_notes', '')
    next_steps = data.get('next_steps', '')
    new_stage = data.get('new_stage')
    follow_up_date = data.get('follow_up_date')

    now = _now()
    execute(
        "UPDATE calendar_meetings SET status = 'completed', outcome = ?, outcome_notes = ?, "
        "next_steps = ?, updated_at = ? WHERE id = ?",
        [outcome, outcome_notes, next_steps, now, meeting_id]
    )

    tp_id = new_id()
    execute(
        "INSERT INTO prospecting_touchpoints (id, contact_id, group_id, channel, direction, subject, "
        "summary, occurred_at, outcome, created_at) VALUES (?, ?, ?, 'meeting', 'outbound', ?, ?, ?, ?, ?)",
        [tp_id, meeting.get('contact_id'), meeting.get('group_id'),
         meeting.get('title', 'Meeting'), outcome_notes or outcome, meeting.get('meeting_date'), outcome, now]
    )

    execute("UPDATE prospecting_contacts SET last_touch_at = ?, updated_at = ? WHERE id = ?",
            [now, now, meeting.get('contact_id')])

    if new_stage and meeting.get('contact_id'):
        execute("UPDATE prospecting_contacts SET relationship_stage = ?, updated_at = ? WHERE id = ?",
                [new_stage, now, meeting.get('contact_id')])

    follow_up_id = None
    if follow_up_date:
        follow_up_id = new_id()
        contact_name = ''
        contact = fetch_one("SELECT first_name, last_name FROM prospecting_contacts WHERE id = ?",
                            [meeting.get('contact_id')])
        if contact:
            contact_name = f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip()
        execute(
            "INSERT INTO calendar_meetings (id, contact_id, group_id, meeting_date, meeting_time, "
            "duration_min, meeting_type, title, notes, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 30, 'follow_up', ?, ?, 'scheduled', ?, ?)",
            [follow_up_id, meeting.get('contact_id'), meeting.get('group_id'),
             follow_up_date, meeting.get('meeting_time', '09:00'),
             f"Follow-up with {contact_name}", next_steps or '', now, now]
        )

    return jsonify({
        'success': True,
        'touchpoint_id': tp_id,
        'follow_up_meeting_id': follow_up_id,
        'message': 'Meeting completed and logged.'
    })


@calendar_bp.route('/meetings/pending-review', methods=['GET'])
def pending_review():
    """Get meetings whose time has passed but haven't been completed — triggers 'How did it go?'"""
    now_dt = datetime.utcnow()
    cutoff = now_dt.strftime('%Y-%m-%d')
    cutoff_time = now_dt.strftime('%H:%M')

    meetings = fetch_all(
        "SELECT m.*, c.first_name, c.last_name, g.name as company_name "
        "FROM calendar_meetings m "
        "LEFT JOIN prospecting_contacts c ON c.id = m.contact_id "
        "LEFT JOIN capital_groups g ON g.id = m.group_id "
        "WHERE m.status = 'scheduled' AND (m.meeting_date < ? OR (m.meeting_date = ? AND m.meeting_time <= ?)) "
        "ORDER BY m.meeting_date DESC, m.meeting_time DESC",
        [cutoff, cutoff, cutoff_time]
    )
    for m in meetings:
        m['contact_name'] = ' '.join(filter(None, [m.get('first_name', ''), m.get('last_name', '')]))
    return jsonify({'success': True, 'meetings': meetings})


@calendar_bp.route('/contacts/search', methods=['GET'])
def search_contacts():
    """Quick contact search for meeting creation form."""
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({'success': True, 'contacts': []})
    like = f"%{q}%"
    contacts = fetch_all(
        "SELECT c.id, c.first_name, c.last_name, c.title, c.email, c.group_id, g.name as company_name "
        "FROM prospecting_contacts c LEFT JOIN capital_groups g ON g.id = c.group_id "
        "WHERE c.first_name LIKE ? OR c.last_name LIKE ? OR g.name LIKE ? "
        "ORDER BY c.last_name ASC LIMIT 20",
        [like, like, like]
    )
    for c in contacts:
        c['full_name'] = f"{c.get('first_name', '')} {c.get('last_name', '')}".strip()
    return jsonify({'success': True, 'contacts': contacts})
