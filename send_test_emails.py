"""
Guardly Phase 4 Local Test Runner.
Sends 4 sample test emails over SMTP to Guardly (127.0.0.1:2525)
to demonstrate all policy enforcement outcomes (ALLOW, REVIEW, QUARANTINE, REJECT).
"""

import time
import smtplib
from email.message import EmailMessage

def send_smtp_email(subject: str, sender: str, recipient: str, body: str, reply_to: str = None, attachment: tuple = None, headers: dict = None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    if reply_to:
        msg["Reply-To"] = reply_to

    if headers:
        for k, v in headers.items():
            msg[k] = v

    msg.set_content(body)

    if attachment:
        content, mime_main, mime_sub, filename = attachment
        msg.add_attachment(content, maintype=mime_main, subtype=mime_sub, filename=filename)

    with smtplib.SMTP("127.0.0.1", 2525) as server:
        server.send_message(msg)

print("==================================================================")
print("  GUARDLY LOCAL TESTING -- SENDING 4 SAMPLE SMTP EMAILS")
print("==================================================================")

# 1. Clean Email -> Expected Decision: ALLOW -> Delivered via Relay (Port 2526)
print("\n[1/4] Sending CLEAN email...")
send_smtp_email(
    subject="Weekly Project Status Update",
    sender="alice@company.com",
    recipient="bob@company.com",
    body="Hi Bob,\nAttached is the status update for this week. All deliverables are on schedule.\n\nThanks,\nAlice"
)
print("  └─ Sent! Expected: ALLOW (Score 0-29) -> Delivered to Relay")

time.sleep(1.5)

# 2. Uncertain Email -> Expected Decision: REVIEW -> Held in Review Queue
print("\n[2/4] Sending UNCERTAIN email...")
send_smtp_email(
    subject="Action Required: Review Pending Document",
    sender="notifications@docu-verify-service.net",
    recipient="employee@company.com",
    reply_to="support@external-docu-verify.com",
    body="Hello,\nPlease verify the document at your earliest convenience."
)
print("  └─ Sent! Expected: REVIEW (Score 30-64) -> Held in Review Queue")

time.sleep(1.5)

# 3. Phishing Email -> Expected Decision: QUARANTINE -> Vaulted in quarantine/
print("\n[3/4] Sending PHISHING email...")
send_smtp_email(
    subject="URGENT: Your PayPal Account Has Been Suspended",
    sender="PayPal Security <login@paypal-security-alert.top>",
    recipient="user@target.local",
    reply_to="attacker@evil-domain.com",
    body="Dear Customer,\nYour account password has expired. Click http://192.168.1.1/login immediately to prevent account closure."
)
print("  └─ Sent! Expected: QUARANTINE (Score 65-95) -> Vaulted in quarantine/")

time.sleep(1.5)

# 4. Critical Phishing Email with Malicious Executable -> Expected Decision: REJECT
print("\n[4/4] Sending CRITICAL PHISHING email with executable attachment...")
send_smtp_email(
    subject="CRITICAL SECURITY ALERT: Immediate Action Required",
    sender="PayPal Support <login@paypal-security-alert.top>",
    recipient="victim@company.com",
    reply_to="attacker@evil-domain.com",
    body="Enter your password at http://192.168.1.1/verify and open attached invoice statement.",
    headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    attachment=(b"%PDF-1.4 Fake PDF Data", "application", "octet-stream", "invoice_statement.pdf.exe")
)
print("  └─ Sent! Expected: REJECT (Score 96-100) -> Rejected")

print("\n==================================================================")
print("✅ ALL 4 TEST EMAILS DELIVERED TO GUARDLY SMTP GATEWAY!")
print("==================================================================")
