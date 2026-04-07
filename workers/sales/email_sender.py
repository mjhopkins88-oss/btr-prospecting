"""
Email sender module using the Resend API.
Sends lead notification emails when high-value opportunities are detected.
"""
import requests
import os

RESEND_API_KEY = os.getenv("RESEND_API_KEY")


def send_lead_email(subject, html_content):
    """Send an email notification via the Resend API."""
    if not RESEND_API_KEY:
        print("[EmailSender] ERROR: RESEND_API_KEY is not set. Email not sent.")
        return None

    url = "https://api.resend.com/emails"
    payload = {
        "from": "BTR Intelligence <alerts@btrcommand.com>",
        "to": ["mlyle@alkemeins.com"],
        "subject": subject,
        "html": html_content
    }
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print(f"[EmailSender] ERROR: Resend API returned {response.status_code}: {response.text}")
    else:
        print(f"[EmailSender] Email sent successfully: {subject}")
    return response
