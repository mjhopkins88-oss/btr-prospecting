"""
Daily Sales Digest

Sends a daily email summary of new inside sales leads at 8 AM.
Scheduled via Railway cron: 0 8 * * *
"""
from datetime import datetime, timedelta

from shared.database import fetch_all, fetch_one
from workers.sales.email_sender import send_lead_email


def run():
    """Generate and send the daily sales digest email."""
    print("[DailySalesDigest] Generating daily digest...")

    yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()

    new_leads = fetch_all(
        "SELECT developer, city, state, lead_score, confidence "
        "FROM sales_leads WHERE created_at >= ? ORDER BY lead_score DESC",
        [yesterday]
    )

    total_new = len(new_leads)

    if total_new == 0:
        print("[DailySalesDigest] No new leads today. Skipping digest.")
        return

    # Top markets by lead count
    market_counts = {}
    for lead in new_leads:
        market = f"{lead.get('city', 'Unknown')}, {lead.get('state', '')}"
        market_counts[market] = market_counts.get(market, 0) + 1
    top_markets = sorted(market_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Highest confidence opportunity
    top_lead = new_leads[0] if new_leads else None

    # Build email
    markets_html = "".join(f"<li>{m} ({c} leads)</li>" for m, c in top_markets)

    top_opp_html = ""
    if top_lead:
        top_opp_html = (
            f"<p><b>{top_lead.get('developer', 'Unknown')}</b> &mdash; "
            f"{top_lead.get('city', '')}, {top_lead.get('state', '')} "
            f"(Score: {top_lead.get('lead_score', 0)}, "
            f"Confidence: {top_lead.get('confidence', 0)}%)</p>"
        )

    leads_table_rows = ""
    for lead in new_leads[:10]:
        leads_table_rows += (
            f"<tr>"
            f"<td>{lead.get('developer', 'Unknown')}</td>"
            f"<td>{lead.get('city', '')}, {lead.get('state', '')}</td>"
            f"<td>{lead.get('lead_score', 0)}</td>"
            f"<td>{lead.get('confidence', 0)}%</td>"
            f"</tr>"
        )

    html = f"""
<h2>Daily Development Intelligence Brief</h2>
<p><b>New Leads Today:</b> {total_new}</p>

<h3>Top Markets</h3>
<ul>
{markets_html}
</ul>

<h3>Highest Confidence Opportunity</h3>
{top_opp_html}

<h3>Recent Leads</h3>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
<tr><th>Developer</th><th>Market</th><th>Score</th><th>Confidence</th></tr>
{leads_table_rows}
</table>
"""

    send_lead_email("Daily Development Intelligence Brief", html)
    print(f"[DailySalesDigest] Digest sent. {total_new} leads summarized.")
    return total_new


if __name__ == "__main__":
    run()
