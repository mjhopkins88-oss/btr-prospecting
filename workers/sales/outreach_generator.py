"""
Outreach Generator Module

Generates personalized outreach email drafts for developer contacts.
Attaches drafts to sales leads via the outreach_drafts table.
"""
import uuid

from shared.database import fetch_all, fetch_one, execute


# ---------------------------------------------------------------------------
# Outreach template
# ---------------------------------------------------------------------------

def generate_outreach_draft(contact_name, developer_name, city, state):
    """
    Generate a personalized outreach email draft.

    Returns (subject, email_body) tuple.
    """
    first_name = contact_name.split()[0] if contact_name else "there"

    subject = f"Quick question on development activity in {city}"

    email_body = (
        f"Hi {first_name},\n\n"
        f"We've been tracking development activity in {city} and noticed "
        f"{developer_name} expanding into that corridor.\n\n"
        f"Curious if you're evaluating any new build-to-rent projects "
        f"in the {city}, {state} market.\n\n"
        f"Happy to compare notes if helpful.\n\n"
        f"Best,\nMax"
    )

    return subject, email_body


# ---------------------------------------------------------------------------
# Store outreach draft
# ---------------------------------------------------------------------------

def store_outreach_draft(lead_id, contact_id, subject, email_body):
    """Insert an outreach draft into the outreach_drafts table."""
    draft_id = str(uuid.uuid4())
    execute(
        """INSERT INTO outreach_drafts (id, lead_id, contact_id, subject, email_body)
           VALUES (?, ?, ?, ?, ?)""",
        [draft_id, lead_id, contact_id, subject, email_body]
    )
    return draft_id


# ---------------------------------------------------------------------------
# Generate drafts for leads
# ---------------------------------------------------------------------------

def generate_drafts_for_lead(lead_id):
    """
    Generate outreach drafts for all contacts matching a sales lead.

    Looks up the lead's developer, finds matching contacts, and creates
    personalized drafts for each.
    """
    lead = fetch_one("SELECT * FROM sales_leads WHERE id = ?", [lead_id])
    if not lead:
        print(f"[OutreachGenerator] Lead {lead_id} not found.")
        return 0

    developer = lead.get("developer")
    city = lead.get("city", "")
    state = lead.get("state", "")

    contacts = fetch_all(
        "SELECT * FROM developer_contacts WHERE developer_name = ? ORDER BY confidence_score DESC",
        [developer]
    )

    drafts_created = 0
    for contact in contacts:
        contact_id = contact.get("id")

        # Skip if draft already exists for this lead + contact
        existing = fetch_one(
            "SELECT id FROM outreach_drafts WHERE lead_id = ? AND contact_id = ?",
            [lead_id, contact_id]
        )
        if existing:
            continue

        contact_name = contact.get("contact_name", "")
        subject, email_body = generate_outreach_draft(contact_name, developer, city, state)
        store_outreach_draft(lead_id, contact_id, subject, email_body)
        drafts_created += 1
        print(f"[OutreachGenerator] Draft created for {contact_name} on lead {lead_id}")

    return drafts_created


def generate_all_pending_drafts():
    """Generate outreach drafts for all sales leads that have matching contacts but no drafts."""
    leads = fetch_all(
        """SELECT sl.id FROM sales_leads sl
           WHERE EXISTS (
               SELECT 1 FROM developer_contacts dc
               WHERE dc.developer_name = sl.developer
           )
           AND NOT EXISTS (
               SELECT 1 FROM outreach_drafts od
               WHERE od.lead_id = sl.id
           )
           ORDER BY sl.created_at DESC
           LIMIT 100"""
    )

    total = 0
    for lead in leads:
        total += generate_drafts_for_lead(lead["id"])

    print(f"[OutreachGenerator] Generated {total} new outreach drafts.")
    return total
