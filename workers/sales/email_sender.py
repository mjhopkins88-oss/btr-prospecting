"""
Email sender module using the Resend API.
Sends lead notification emails when high-value opportunities are detected.
"""
import requests
import os

RESEND_API_KEY = os.getenv("RESEND_API_KEY")


def send_lead_email(subject, html_content):
    """Send an email notification via the Resend API."""
    url = "https://api.resend.com/emails"
    payload = {
        "from": "BTR Intelligence <alerts@btrcommand.com>",
        "to": ["max@btrcommand.com"],
        "subject": subject,
        "html": html_content
    }
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }
    requests.post(url, json=payload, headers=headers)
