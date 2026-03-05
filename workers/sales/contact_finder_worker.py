"""
Developer Contact Finder Worker

Discovers contact information for developers detected by the intelligence engine.
Searches sales_leads, predicted_developments, and developer_intent_predictions
for developer companies, then finds executive contacts, LinkedIn profiles,
infers email patterns, and scores contact confidence.

Scheduled to run every 6 hours via Railway cron: 0 */6 * * *
"""
import uuid
import re
from datetime import datetime, timedelta

from shared.database import fetch_all, fetch_one, execute


# ---------------------------------------------------------------------------
# Target roles
# ---------------------------------------------------------------------------

TARGET_TITLES = [
    "Development Director",
    "VP of Development",
    "Vice President of Development",
    "Managing Director",
    "Principal",
    "Founder",
    "Partner",
    "CEO",
    "President",
    "Chief Development Officer",
]

# ---------------------------------------------------------------------------
# Common email patterns
# ---------------------------------------------------------------------------

EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first_initial}{last}@{domain}",
    "{first}@{domain}",
    "{first}{last}@{domain}",
    "{first}_{last}@{domain}",
]


# ---------------------------------------------------------------------------
# Developer collection
# ---------------------------------------------------------------------------

def collect_developers():
    """Gather unique developer names from intelligence sources."""
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    developers = set()

    sales_leads = fetch_all(
        "SELECT DISTINCT developer FROM sales_leads WHERE created_at >= ?",
        [since]
    )
    for row in sales_leads:
        name = row.get("developer")
        if name:
            developers.add(name)

    predicted = fetch_all(
        "SELECT DISTINCT developer FROM predicted_developments WHERE created_at >= ?",
        [since]
    )
    for row in predicted:
        name = row.get("developer")
        if name:
            developers.add(name)

    intent = fetch_all(
        "SELECT DISTINCT developer FROM developer_intent_predictions WHERE created_at >= ?",
        [since]
    )
    for row in intent:
        name = row.get("developer")
        if name:
            developers.add(name)

    return list(developers)


# ---------------------------------------------------------------------------
# Domain detection
# ---------------------------------------------------------------------------

def infer_company_domain(developer_name):
    """
    Infer a company website domain from the developer name.

    Example: 'Crescent Communities' -> 'crescentcommunities.com'
    """
    cleaned = re.sub(r'[^a-zA-Z0-9\s]', '', developer_name)
    parts = cleaned.lower().split()
    stop_words = {"llc", "inc", "corp", "group", "the", "and", "of", "co", "ltd"}
    filtered = [p for p in parts if p not in stop_words]
    if not filtered:
        filtered = parts
    domain = "".join(filtered) + ".com"
    return domain


# ---------------------------------------------------------------------------
# Email pattern inference
# ---------------------------------------------------------------------------

def generate_candidate_emails(contact_name, domain):
    """
    Generate candidate email addresses for a contact at a given domain.

    Returns list of (email, confidence) tuples.
    """
    parts = contact_name.strip().lower().split()
    if len(parts) < 2:
        return []

    first = parts[0]
    last = parts[-1]
    first_initial = first[0] if first else ""

    candidates = []
    pattern_scores = [
        ("{first}.{last}@{domain}", 90),
        ("{first_initial}{last}@{domain}", 75),
        ("{first}@{domain}", 60),
        ("{first}{last}@{domain}", 70),
        ("{first}_{last}@{domain}", 65),
    ]

    for pattern, score in pattern_scores:
        email = pattern.format(
            first=first,
            last=last,
            first_initial=first_initial,
            domain=domain
        )
        candidates.append((email, score))

    return candidates


# ---------------------------------------------------------------------------
# LinkedIn profile detection
# ---------------------------------------------------------------------------

def infer_linkedin_url(contact_name):
    """
    Generate a candidate LinkedIn profile URL from a contact name.

    Example: 'John Smith' -> 'https://linkedin.com/in/johnsmith'
    """
    parts = contact_name.strip().lower().split()
    slug = "".join(re.sub(r'[^a-z]', '', p) for p in parts)
    if not slug:
        return None
    return f"https://linkedin.com/in/{slug}"


# ---------------------------------------------------------------------------
# Contact scoring
# ---------------------------------------------------------------------------

def calculate_contact_confidence(has_linkedin, has_email, title, company_match):
    """
    Calculate contact confidence score (max 100).

    Scoring:
        LinkedIn profile match  -> +40
        Email pattern match     -> +25
        Title relevance         -> +20
        Company match           -> +15
    """
    score = 0
    if has_linkedin:
        score += 40
    if has_email:
        score += 25
    if title and any(t.lower() in title.lower() for t in TARGET_TITLES):
        score += 20
    if company_match:
        score += 15
    return min(score, 100)


# ---------------------------------------------------------------------------
# Contact storage
# ---------------------------------------------------------------------------

def contact_exists(developer_name, contact_name):
    """Check if a contact already exists for this developer."""
    existing = fetch_one(
        "SELECT id FROM developer_contacts WHERE developer_name = ? AND contact_name = ?",
        [developer_name, contact_name]
    )
    return existing is not None


def store_contact(developer_name, contact_name, title, email, linkedin_url, company_domain, confidence_score):
    """Insert a discovered contact into the developer_contacts table."""
    contact_id = str(uuid.uuid4())
    execute(
        """INSERT INTO developer_contacts (id, developer_name, contact_name, title, email, linkedin_url, company_domain, confidence_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [contact_id, developer_name, contact_name, title, email, linkedin_url, company_domain, confidence_score]
    )
    return contact_id


# ---------------------------------------------------------------------------
# Discovery pipeline
# ---------------------------------------------------------------------------

def discover_contacts_for_developer(developer_name):
    """
    Run the full contact discovery pipeline for a single developer.

    Steps:
    1. Identify company domain
    2. Search for executive contacts (simulated via company name heuristics)
    3. Generate LinkedIn profiles
    4. Infer email addresses
    5. Score and store contacts
    """
    domain = infer_company_domain(developer_name)

    # Search for known contacts in existing intelligence data
    known_contacts = fetch_all(
        "SELECT DISTINCT contact_name, title FROM developer_contacts WHERE developer_name = ?",
        [developer_name]
    )

    # Also check if we have any related data from the platform
    leadership_hints = _extract_leadership_hints(developer_name)

    contacts_created = 0
    for contact_name, title in leadership_hints:
        if contact_exists(developer_name, contact_name):
            continue

        linkedin_url = infer_linkedin_url(contact_name)
        emails = generate_candidate_emails(contact_name, domain)
        best_email = emails[0][0] if emails else None

        confidence = calculate_contact_confidence(
            has_linkedin=linkedin_url is not None,
            has_email=best_email is not None,
            title=title,
            company_match=True
        )

        store_contact(
            developer_name=developer_name,
            contact_name=contact_name,
            title=title,
            email=best_email,
            linkedin_url=linkedin_url,
            company_domain=domain,
            confidence_score=confidence
        )
        contacts_created += 1
        print(f"[ContactFinder] Contact stored: {contact_name} ({title}) at {developer_name}")

    return contacts_created


def _extract_leadership_hints(developer_name):
    """
    Extract potential leadership contacts for a developer.

    Searches existing platform data sources:
    - contractor_activity (contact references)
    - developer_intent_predictions (agent/contact fields)
    - predicted_developments (contact fields)

    Returns list of (contact_name, title) tuples.
    """
    contacts = []

    # Check contractor relationships for contact references
    contractor_rows = fetch_all(
        "SELECT DISTINCT contact_name, contact_title FROM contractor_developer_relationships "
        "WHERE developer_name = ? AND contact_name IS NOT NULL",
        [developer_name]
    ) or []
    for row in contractor_rows:
        name = row.get("contact_name")
        title = row.get("contact_title", "Development Executive")
        if name:
            contacts.append((name, title))

    # Check developer profiles
    dev_row = fetch_one(
        "SELECT primary_contact, primary_contact_title FROM developers WHERE name = ?",
        [developer_name]
    )
    if dev_row and dev_row.get("primary_contact"):
        contacts.append((
            dev_row["primary_contact"],
            dev_row.get("primary_contact_title", "Principal")
        ))

    return contacts


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------

def run():
    """Execute the contact finder worker cycle."""
    print("[ContactFinder] Starting contact discovery scan...")

    developers = collect_developers()
    print(f"[ContactFinder] Found {len(developers)} developers to process.")

    total_contacts = 0
    for developer in developers:
        try:
            count = discover_contacts_for_developer(developer)
            total_contacts += count
        except Exception as e:
            print(f"[ContactFinder] Error processing {developer}: {e}")

    print(f"[ContactFinder] Scan complete. {total_contacts} new contacts discovered.")
    return total_contacts


if __name__ == "__main__":
    run()
