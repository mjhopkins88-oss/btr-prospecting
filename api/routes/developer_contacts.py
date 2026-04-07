"""
API Routes: Developer Contacts
Flask Blueprint for developer contact discovery and outreach endpoints.
"""
from flask import Blueprint, request, jsonify

from shared.database import fetch_all, fetch_one, execute
from workers.sales.outreach_generator import generate_drafts_for_lead
from workers.sales.email_sender import send_lead_email

developer_contacts_bp = Blueprint('developer_contacts', __name__, url_prefix='/api')


@developer_contacts_bp.route('/developer-contacts', methods=['GET'])
def get_developer_contacts():
    """Return developer contacts, optionally filtered by developer name."""
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    developer = request.args.get('developer')

    sql = """SELECT id, developer_name, contact_name, title, email, linkedin_url,
                    company_domain, confidence_score, created_at
             FROM developer_contacts WHERE 1=1"""
    params = []

    if developer:
        sql += " AND developer_name = ?"
        params.append(developer)

    sql += " ORDER BY confidence_score DESC, created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = fetch_all(sql, params)

    return jsonify({
        "contacts": [
            {
                "id": r.get("id"),
                "developer": r.get("developer_name"),
                "contact_name": r.get("contact_name"),
                "title": r.get("title"),
                "email": r.get("email"),
                "linkedin": r.get("linkedin_url"),
                "company_domain": r.get("company_domain"),
                "confidence_score": r.get("confidence_score"),
                "created_at": r.get("created_at"),
            }
            for r in rows
        ],
        "count": len(rows)
    })


@developer_contacts_bp.route('/developer-contacts/by-lead/<lead_id>', methods=['GET'])
def get_contacts_for_lead(lead_id):
    """Return contacts and outreach drafts associated with a specific sales lead."""
    lead = fetch_one("SELECT * FROM sales_leads WHERE id = ?", [lead_id])
    if not lead:
        return jsonify({"error": "Lead not found"}), 404

    developer = lead.get("developer")
    contacts = fetch_all(
        """SELECT dc.id, dc.contact_name, dc.title, dc.email, dc.linkedin_url,
                  dc.company_domain, dc.confidence_score
           FROM developer_contacts dc
           WHERE dc.developer_name = ?
           ORDER BY dc.confidence_score DESC""",
        [developer]
    )

    # Attach outreach drafts for each contact
    results = []
    for c in contacts:
        draft = fetch_one(
            "SELECT id, subject, email_body FROM outreach_drafts WHERE lead_id = ? AND contact_id = ?",
            [lead_id, c.get("id")]
        )
        results.append({
            "id": c.get("id"),
            "contact_name": c.get("contact_name"),
            "title": c.get("title"),
            "email": c.get("email"),
            "linkedin": c.get("linkedin_url"),
            "company_domain": c.get("company_domain"),
            "confidence_score": c.get("confidence_score"),
            "outreach_draft": {
                "id": draft.get("id"),
                "subject": draft.get("subject"),
                "email_body": draft.get("email_body"),
            } if draft else None,
        })

    return jsonify({
        "lead_id": lead_id,
        "developer": developer,
        "contacts": results,
        "count": len(results)
    })


@developer_contacts_bp.route('/developer-contacts/generate-drafts/<lead_id>', methods=['POST'])
def generate_drafts(lead_id):
    """Generate outreach drafts for all contacts on a given lead."""
    count = generate_drafts_for_lead(lead_id)
    return jsonify({"drafts_generated": count})


@developer_contacts_bp.route('/developer-contacts/send-outreach/<draft_id>', methods=['POST'])
def send_outreach(draft_id):
    """Send an outreach email using a stored draft via the Resend API."""
    draft = fetch_one("SELECT * FROM outreach_drafts WHERE id = ?", [draft_id])
    if not draft:
        return jsonify({"error": "Draft not found"}), 404

    contact = fetch_one(
        "SELECT * FROM developer_contacts WHERE id = ?",
        [draft.get("contact_id")]
    )

    subject = draft.get("subject", "")
    body_text = draft.get("email_body", "")
    html_body = f"<pre style='font-family: sans-serif; line-height: 1.6;'>{body_text}</pre>"

    response = send_lead_email(subject, html_body)

    if response and response.status_code == 200:
        return jsonify({"status": "sent", "draft_id": draft_id})
    else:
        return jsonify({"status": "failed", "draft_id": draft_id}), 500
