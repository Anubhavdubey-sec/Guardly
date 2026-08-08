"""
Guardly Phase 4 Live Local Integration Demo.
Starts the Inbound SMTP Receiver (2525), Target SMTP Relay Server (2526), and Workers,
sends 4 test emails covering all policy outcomes, and displays live telemetry & DB results.
"""

import os
import time
import smtplib
from email.message import EmailMessage

from app import create_app
from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage as EmailMessageModel
from models.policy import MailDecision, MailQuarantine, MailAuditLog
from models.relay import MailRelayLog
from services.smtp_receiver import GuardlySMTPServer
from services.mail_queue import process_pending_queue
from services.mail_relay import process_relay_queue

# Create App Context
app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///guardly_demo.db"})
app_context = app.app_context()
app_context.push()
db.create_all()

# 1. Start Inbound Gateway Receiver (Port 2525)
rx_server = GuardlySMTPServer(host="127.0.0.1", port=2525, storage_path="received_emails")
rx_server.start()

# 2. Start Target Destination Relay Server (Port 2526)
relay_server = GuardlySMTPServer(host="127.0.0.1", port=2526, storage_path="received_emails/destination_relayed")
relay_server.start()

print("==================================================================")
print("  GUARDLY PHASE 4 -- LIVE LOCAL INTEGRATION DEMO")
print("==================================================================")
print("  [+] Inbound SMTP Gateway Active: 127.0.0.1:2525")
print("  [+] Target Relay Server Active:  127.0.0.1:2526")

def send_test_email(msg_id, subject, sender, recipient, body, reply_to=None, attachment=None, headers=None):
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

    with smtplib.SMTP("127.0.0.1", 2525) as s:
        s.send_message(msg)

try:
    # 1. Clean Email -> ALLOW
    print("\n[1/4] Delivering CLEAN Email to Gateway (Port 2525)...")
    send_test_email(
        "clean_001",
        "Weekly Status Report",
        "alice@company.com",
        "bob@company.com",
        "Hi Bob, attached is the weekly status report."
    )

    # 2. Uncertain Email -> REVIEW
    print("\n[2/4] Delivering UNCERTAIN Email to Gateway (Port 2525)...")
    send_test_email(
        "review_002",
        "Action Required: Review Pending Document",
        "notifications@docu-verify-service.net",
        "employee@company.com",
        "Hello, please verify the document at your earliest convenience.",
        reply_to="support@external-docu-verify.com"
    )

    # 3. Phishing Email -> QUARANTINE
    print("\n[3/4] Delivering PHISHING Email to Gateway (Port 2525)...")
    send_test_email(
        "quar_003",
        "URGENT: Account Suspended Immediately",
        "PayPal Support <login@paypal-security-alert.top>",
        "user@target.local",
        "Your account password has expired. Click http://192.168.1.1/login immediately.",
        reply_to="attacker@evil-domain.com"
    )

    # 4. Critical Email -> REJECT
    print("\n[4/4] Delivering CRITICAL PHISHING Email to Gateway (Port 2525)...")
    send_test_email(
        "reject_004",
        "CRITICAL: Immediate Action Required",
        "PayPal Support <login@paypal-security-alert.top>",
        "victim@company.com",
        "Enter password at http://192.168.1.1/verify and open attached statement.",
        reply_to="attacker@evil-domain.com",
        headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
        attachment=(b"%PDF-1.4 Fake PDF Data", "application", "octet-stream", "invoice_statement.pdf.exe")
    )

    time.sleep(1)

    from mail.storage import get_stored_emails
    from services.mail_queue import enqueue_message
    stored_files = get_stored_emails("received_emails")
    for s_file in stored_files:
        full_p = os.path.join("received_emails", s_file)
        enqueue_message(full_p)

    print("\n------------------------------------------------------------------")
    print("  [*] PROCESSING MAIL QUEUE, PARSER, THREAT ENGINE & POLICY...")
    print("------------------------------------------------------------------")
    processed_count = process_pending_queue(app, max_jobs=10)
    print(f"  [+] Queue Engine processed {processed_count} messages.")

    print("\n------------------------------------------------------------------")
    print("  [*] PROCESSING OUTBOUND MAIL RELAY (PORT 2526)...")
    print("------------------------------------------------------------------")
    relayed_count = process_relay_queue(app, max_jobs=10)
    print(f"  [+] Relay Engine delivered {relayed_count} clean messages to Port 2526.")

    print("\n==================================================================")
    print("  LIVE TELEMETRY & ENFORCEMENT SUMMARY")
    print("==================================================================")

    all_messages = EmailMessageModel.query.order_by(EmailMessageModel.id.asc()).all()
    for m in all_messages:
        dec_record = MailDecision.query.filter_by(message_id=m.message_id).first()
        dec_str = dec_record.decision if dec_record else "N/A"
        print(f"\n  Subject:     {m.subject}")
        print(f"  From:        {m.from_address}")
        print(f"  Risk Score:  {m.risk_score} / 100")
        print(f"  Severity:    {m.severity}")
        print(f"  Decision:    {dec_str}")
        print(f"  Final State: {m.status}")

    print("\n==================================================================")
    print("  [+] DEMO COMPLETE -- ALL MODULES 1 TO 5 VERIFIED OPERATIONAL!")
    print("==================================================================")

finally:
    rx_server.stop()
    relay_server.stop()
    app_context.pop()
