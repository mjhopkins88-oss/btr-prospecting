"""
Inside Sales Automation Bot

Monitors intelligence signals across the BTR Command platform and automatically
generates qualified development leads. When high-value opportunities are detected,
the bot scores them, generates a summary, stores the lead, and sends an email
notification via Resend.

Signals monitored:
- predicted_developments
- developer_intent_predictions
- capital_predictions
- opportunity_clusters
- contractor_activity
- parcel_development_probability

Scheduled to run every 30 minutes via Railway cron: */30 * * * *
"""
import uuid
from datetime import datetime, timedelta

from shared.database import fetch_all, fetch_one, execute
from workers.sales.email_sender import send_lead_email


# ---------------------------------------------------------------------------
# Signal collection
# ---------------------------------------------------------------------------

def collect_signals():
    """Gather recent intelligence signals from all monitored sources."""
    since = (datetime.utcnow() - timedelta(minutes=30)).isoformat()

    predicted_developments = fetch_all(
        "SELECT * FROM predicted_developments WHERE created_at >= ? ORDER BY confidence DESC",
        [since]
    )

    developer_intent = fetch_all(
        "SELECT * FROM developer_intent_predictions WHERE created_at >= ? ORDER BY confidence DESC",
        [since]
    )

    capital_predictions = fetch_all(
        "SELECT * FROM capital_predictions WHERE created_at >= ? ORDER BY confidence DESC",
        [since]
    )

    contractor_activity = fetch_all(
        "SELECT * FROM contractor_activity WHERE created_at >= ? ORDER BY created_at DESC",
        [since]
    )

    parcel_probability = fetch_all(
        "SELECT * FROM parcel_development_probability WHERE probability_score >= 80 "
        "AND created_at >= ? ORDER BY probability_score DESC",
        [since]
    )

    opportunity_clusters = fetch_all(
        "SELECT * FROM opportunity_clusters WHERE created_at >= ? ORDER BY created_at DESC",
        [since]
    )

    return {
        "predicted_developments": predicted_developments,
        "developer_intent": developer_intent,
        "capital_predictions": capital_predictions,
        "contractor_activity": contractor_activity,
        "parcel_probability": parcel_probability,
        "opportunity_clusters": opportunity_clusters,
    }


# ---------------------------------------------------------------------------
# Lead scoring  (max 100)
# ---------------------------------------------------------------------------

def calculate_lead_score(signals_for_opportunity):
    """
    Score a potential lead based on detected signals.

    Scoring breakdown:
        parcel_probability > 80    -> +20
        developer_intent detected  -> +25
        contractor_activity        -> +20
        capital_deployment         -> +30
        developer_dna_match        -> +15
    """
    score = 0

    if signals_for_opportunity.get("parcel_probability"):
        parcel = signals_for_opportunity["parcel_probability"]
        prob = parcel.get("probability_score", 0) if isinstance(parcel, dict) else 0
        if prob > 80:
            score += 20

    if signals_for_opportunity.get("developer_intent"):
        score += 25

    if signals_for_opportunity.get("contractor_activity"):
        score += 20

    if signals_for_opportunity.get("capital_deployment"):
        score += 30

    if signals_for_opportunity.get("developer_dna_match"):
        score += 15

    return min(score, 100)


# ---------------------------------------------------------------------------
# Lead summary generation
# ---------------------------------------------------------------------------

def generate_lead_summary(developer, city, state, confidence, detected_signals):
    """Build a human-readable lead summary string."""
    signal_bullets = []
    if detected_signals.get("developer_intent"):
        signal_bullets.append("Developer Intent")
    if detected_signals.get("contractor_activity"):
        signal_bullets.append("Contractor Activity")
    if detected_signals.get("parcel_probability"):
        signal_bullets.append("High Parcel Probability")
    if detected_signals.get("capital_deployment"):
        signal_bullets.append("Capital Deployment Signal")
    if detected_signals.get("developer_dna_match"):
        signal_bullets.append("Developer DNA Match")

    signals_text = "\n".join(f"  * {s}" for s in signal_bullets) if signal_bullets else "  * General Intelligence Signal"

    summary = (
        f"NEW DEVELOPMENT OPPORTUNITY\n"
        f"Developer: {developer}\n"
        f"Market: {city}, {state}\n"
        f"Signals Detected:\n{signals_text}\n"
        f"Estimated Project Type: Build-to-Rent\n"
        f"Confidence: {confidence}%\n"
        f"Suggested Action: Contact development director."
    )
    return summary


# ---------------------------------------------------------------------------
# Duplicate prevention
# ---------------------------------------------------------------------------

def is_duplicate_lead(developer, city):
    """Check if the same developer + city already exists within last 48 hours."""
    cutoff = (datetime.utcnow() - timedelta(hours=48)).isoformat()
    existing = fetch_one(
        "SELECT id FROM sales_leads WHERE developer = ? AND city = ? AND created_at >= ?",
        [developer, city, cutoff]
    )
    return existing is not None


# ---------------------------------------------------------------------------
# Email notification
# ---------------------------------------------------------------------------

def send_opportunity_email(developer, city, state, confidence, detected_signals):
    """Send email notification for a qualified lead."""
    signal_items = []
    if detected_signals.get("developer_intent"):
        signal_items.append("<li>Developer Intent</li>")
    if detected_signals.get("contractor_activity"):
        signal_items.append("<li>Contractor Activity</li>")
    if detected_signals.get("parcel_probability"):
        signal_items.append("<li>Parcel Probability Spike</li>")
    if detected_signals.get("capital_deployment"):
        signal_items.append("<li>Capital Deployment Signal</li>")
    if detected_signals.get("developer_dna_match"):
        signal_items.append("<li>Developer DNA Match</li>")

    signals_html = "\n".join(signal_items) if signal_items else "<li>General Intelligence Signal</li>"

    subject = "\U0001f6a8 New Development Opportunity Detected"
    email_body = f"""
<h2>New Development Opportunity</h2>
<b>Developer:</b> {developer}<br>
<b>Market:</b> {city}, {state}<br>
<b>Confidence:</b> {confidence}%<br>
<h3>Signals Detected</h3>
<ul>
{signals_html}
</ul>
"""
    send_lead_email(subject, email_body)


# ---------------------------------------------------------------------------
# Store lead
# ---------------------------------------------------------------------------

def store_lead(developer, city, state, lead_score, lead_summary, source_signal, confidence):
    """Insert a qualified lead into the sales_leads table."""
    lead_id = str(uuid.uuid4())
    execute(
        """INSERT INTO sales_leads (id, developer, city, state, lead_score, lead_summary, source_signal, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [lead_id, developer, city, state, lead_score, lead_summary, source_signal, confidence]
    )
    return lead_id


# ---------------------------------------------------------------------------
# Main bot loop
# ---------------------------------------------------------------------------

def _group_by_developer(signals):
    """Group collected signals into per-developer opportunity bundles."""
    opportunities = {}

    for dev in signals.get("developer_intent", []):
        key = (dev.get("developer", "Unknown"), dev.get("city", "Unknown"), dev.get("state", ""))
        opp = opportunities.setdefault(key, {})
        opp["developer_intent"] = dev
        opp["confidence"] = max(opp.get("confidence", 0), dev.get("confidence", 0))

    for cap in signals.get("capital_predictions", []):
        key = (cap.get("developer", "Unknown"), cap.get("city", "Unknown"), cap.get("state", ""))
        opp = opportunities.setdefault(key, {})
        opp["capital_deployment"] = cap
        opp["confidence"] = max(opp.get("confidence", 0), cap.get("confidence", 0))

    for ca in signals.get("contractor_activity", []):
        key = (ca.get("developer", "Unknown"), ca.get("city", "Unknown"), ca.get("state", ""))
        opp = opportunities.setdefault(key, {})
        opp["contractor_activity"] = ca
        opp["confidence"] = max(opp.get("confidence", 0), ca.get("confidence", 0))

    for pp in signals.get("parcel_probability", []):
        key = (pp.get("developer", "Unknown"), pp.get("city", "Unknown"), pp.get("state", ""))
        opp = opportunities.setdefault(key, {})
        opp["parcel_probability"] = pp
        opp["confidence"] = max(opp.get("confidence", 0), pp.get("probability_score", 0))

    for pd in signals.get("predicted_developments", []):
        key = (pd.get("developer", "Unknown"), pd.get("city", "Unknown"), pd.get("state", ""))
        opp = opportunities.setdefault(key, {})
        opp["predicted_development"] = pd
        opp["confidence"] = max(opp.get("confidence", 0), pd.get("confidence", 0))

    for oc in signals.get("opportunity_clusters", []):
        key = (oc.get("developer", "Unknown"), oc.get("city", "Unknown"), oc.get("state", ""))
        opp = opportunities.setdefault(key, {})
        opp["opportunity_cluster"] = oc
        opp["confidence"] = max(opp.get("confidence", 0), oc.get("confidence", 0))

    return opportunities


def run():
    """Execute the inside sales bot cycle."""
    print("[InsideSalesBot] Starting signal scan...")

    signals = collect_signals()
    opportunities = _group_by_developer(signals)

    leads_created = 0

    for (developer, city, state), opp_signals in opportunities.items():
        score = calculate_lead_score(opp_signals)

        if score < 70:
            continue

        if is_duplicate_lead(developer, city):
            print(f"[InsideSalesBot] Duplicate skipped: {developer} / {city}")
            continue

        confidence = opp_signals.get("confidence", 0)
        source_signal = ", ".join(
            k for k in opp_signals if k != "confidence"
        )

        summary = generate_lead_summary(developer, city, state, confidence, opp_signals)
        store_lead(developer, city, state, score, summary, source_signal, confidence)
        send_opportunity_email(developer, city, state, confidence, opp_signals)

        leads_created += 1
        print(f"[InsideSalesBot] Lead created: {developer} / {city}, {state} (score={score})")

    print(f"[InsideSalesBot] Scan complete. {leads_created} new leads created.")
    return leads_created


if __name__ == "__main__":
    run()
