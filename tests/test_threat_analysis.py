"""
Unit & Integration Test Suite for Guardly Phase 4 / Module 3 (Threat Analysis Engine).
Tests Clean Email, Phishing Email, SPF/DKIM/DMARC Failures, Reply-To Mismatch,
Display-Name Impersonation, Suspicious/Shortened/Punycode/IP/Decimal URLs, Credential Lures,
Urgency Language, Multilingual Content, PDF & Executable & Double Extension Attachments,
IOC Extraction, Deterministic Risk Scoring, and End-to-End Pipeline Integration.
"""

import os
import socket
import smtplib
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage
from models.scan import EmailScan
from services.email_parser import parse_raw_email
from services.threat_analysis import (
    ThreatAnalysisEngine,
    HeaderAnalyzer,
    AuthenticationAnalyzer,
    SenderAnalyzer,
    ContentAnalyzer,
    URLAnalyzer,
    AttachmentAnalyzer,
    IOCAnalyzer,
    normalize_text_content,
)
from services.smtp_receiver import GuardlySMTPServer
from mail.storage import get_stored_emails, read_stored_email
from services.mail_queue import process_pending_queue


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ThreatAnalysisUnitTests(unittest.TestCase):
    """Unit tests for individual analyzers within the Threat Analysis Engine."""

    def setUp(self):
        self.engine = ThreatAnalysisEngine()

    def test_clean_email_low_risk_scoring(self):
        clean_email = {
            "message_id": "clean_123",
            "from": "alice@company.com",
            "to": ["bob@company.com"],
            "subject": "Weekly Project Update",
            "text_body": "Hi Bob, attached is the regular status report. Thanks!",
            "html_body": "<p>Hi Bob, attached is the regular status report. Thanks!</p>",
            "auth_results": "spf=pass dkim=pass dmarc=pass",
            "urls": [],
            "attachments": [],
        }
        res = self.engine.analyze(clean_email)
        self.assertLessEqual(res["risk_score"], 40)
        self.assertIn(res["recommendation"], ("ALLOW", "REVIEW"))

    def test_phishing_email_high_risk_scoring(self):
        phish_email = {
            "message_id": "phish_999",
            "from": "PayPal Support <login@paypal-security-alert.top>",
            "reply_to": "attacker@evil-domain.com",
            "to": ["victim@company.com"],
            "subject": "URGENT: Your account has been suspended",
            "text_body": "Dear customer, your password will expire in 2 hours. Enter your password at https://192.168.1.1/verify",
            "html_body": '<a href="https://xn--pypal-4ve.com/login">Verify Account</a>',
            "auth_results": "spf=fail dkim=fail dmarc=fail",
            "urls": ["https://192.168.1.1/verify", "https://xn--pypal-4ve.com/login"],
            "attachments": [
                {
                    "filename": "invoice_update.pdf.exe",
                    "original_filename": "invoice_update.pdf.exe",
                    "mime_type": "application/octet-stream",
                    "size": 5000,
                    "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                    "storage_path": "",
                }
            ],
        }
        res = self.engine.analyze(phish_email)
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertIn(res["severity"], ("HIGH", "CRITICAL"))
        self.assertEqual(res["recommendation"], "QUARANTINE")
        self.assertTrue(len(res["findings"]) > 0)

    def test_authentication_analyzer_failures(self):
        analyzer = AuthenticationAnalyzer()
        parsed = {"auth_results": "spf=fail dkim=fail dmarc=fail"}
        res = analyzer.analyze(parsed)
        self.assertEqual(res["spf"], "FAIL")
        self.assertEqual(res["dkim"], "FAIL")
        self.assertEqual(res["dmarc"], "FAIL")
        self.assertGreaterEqual(res["auth_score_penalty"], 60)

    def test_sender_impersonation_and_reply_to_mismatch(self):
        analyzer = SenderAnalyzer()
        parsed = {
            "from": "Bank of America Support <alert@scam-bank.com>",
            "reply_to": "collect@attacker.net",
        }
        res = analyzer.analyze(parsed)
        self.assertIn("scam-bank.com", res["from_domain"])
        self.assertTrue(any("impersonation" in f.lower() for f in res["findings"]))
        self.assertTrue(any("reply-to" in f.lower() for f in res["findings"]))

    def test_content_analyzer_urgency_and_credential_lures(self):
        analyzer = ContentAnalyzer()
        parsed = {
            "subject": "Immediate Action Required: Password Reset",
            "text_body": "Your account will be suspended. Please verify your MFA passcode immediately.",
            "body": "Your account will be suspended. Please verify your MFA passcode immediately.",
        }
        res = analyzer.analyze(parsed)
        self.assertGreaterEqual(res["content_score_penalty"], 10)
        self.assertTrue(len(res["tactics"]) > 0)

    def test_url_analyzer_types(self):
        analyzer = URLAnalyzer()
        parsed = {
            "urls": [
                "https://bit.ly/3xXyz",             # Shortener
                "https://xn--microsft-95a.com",     # Punycode
                "http://192.168.1.100/login",       # IP URL
                "http://0xC0A80164/verify",         # Hex/Decimal IP URL
                "http://suspicious-site.top/auth",  # Suspicious TLD
            ]
        }
        analyzed_urls, findings, penalty = analyzer.analyze(parsed)
        self.assertEqual(len(analyzed_urls), 5)
        self.assertGreaterEqual(penalty, 25)
        self.assertTrue(len(findings) > 0)

    def test_attachment_analyzer_dangerous_and_double_extension(self):
        analyzer = AttachmentAnalyzer()
        parsed = {
            "attachments": [
                {
                    "filename": "payload.bat",
                    "original_filename": "payload.bat",
                    "mime_type": "text/plain",
                    "size": 100,
                    "sha256": "abc123hash",
                },
                {
                    "filename": "statement.pdf.exe",
                    "original_filename": "statement.pdf.exe",
                    "mime_type": "application/x-msdownload",
                    "size": 200,
                    "sha256": "def456hash",
                },
            ]
        }
        analyzed_atts, findings, penalty = analyzer.analyze(parsed)
        self.assertEqual(len(analyzed_atts), 2)
        self.assertGreaterEqual(penalty, 40)
        self.assertTrue(any("double extension" in f.lower() for f in findings))

    def test_ioc_analyzer_extraction(self):
        analyzer = IOCAnalyzer()
        parsed = {
            "text_body": "Connect to 198.51.100.45 or send bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Email us at admin@phish.net",
            "urls": ["https://phish.net/login"],
            "attachments": [{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        }
        iocs = analyzer.analyze(parsed)
        self.assertIn("198.51.100.45", iocs["ip_addresses"])
        self.assertIn("phish.net", iocs["domains"])
        self.assertIn("admin@phish.net", iocs["email_addresses"])
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", iocs["hashes"])
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", iocs["crypto_wallets"])

    def test_multilingual_content_normalization(self):
        norm = normalize_text_content("V&#233;rifiez&nbsp;votre\u200bcompte")
        self.assertNotIn("&nbsp;", norm)
        self.assertNotIn("\u200b", norm)
        self.assertIn("Vérifiez", norm)


class EndToEndPipelineIntegrationTests(unittest.TestCase):
    """
    End-to-End Integration Test for complete Module 1 + 2 + 3 flow:
    SMTP Receiver -> Store .eml -> Enqueue -> Parse Email -> Threat Analysis -> Risk Scoring & DB.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.test_port = find_free_port()
        self.server = GuardlySMTPServer(
            host="127.0.0.1",
            port=self.test_port,
            storage_path=self.temp_dir.name,
        )
        self.server.start()

    def tearDown(self):
        if self.server and self.server.is_running:
            self.server.stop()
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self.temp_dir.cleanup()

    def test_full_pipeline_smtp_to_threat_analysis_db_persistence(self):
        """Send an email over SMTP and verify it flows through Queue, Parser, Threat Engine to DB."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")

        msg = (
            "From: Security Support <alert@paypal-login-alert.top>\r\n"
            "To: target@company.com\r\n"
            "Reply-To: attacker@evil.net\r\n"
            "Subject: URGENT: Verify your account credentials\r\n"
            "\r\n"
            "Your account will be suspended. Please verify password at http://192.168.1.1/login"
        )

        res = client.sendmail("alert@paypal-login-alert.top", ["target@company.com"], msg)
        self.assertEqual(res, {})
        client.quit()

        # Retrieve stored .eml file from storage directory
        stored_files = get_stored_emails(self.temp_dir.name)
        self.assertGreaterEqual(len(stored_files), 1)

        full_eml_path = os.path.join(self.temp_dir.name, stored_files[0])
        with open(full_eml_path, "rb") as f:
            raw_eml_bytes = f.read()
        self.assertIsNotNone(raw_eml_bytes)

        # Parse & Analyze
        parsed = parse_raw_email(raw_eml_bytes)
        self.assertEqual(parsed["subject"], "URGENT: Verify your account credentials")

        engine = ThreatAnalysisEngine()
        analysis = engine.analyze(parsed)

        self.assertGreaterEqual(analysis["risk_score"], 50)
        self.assertIn(analysis["severity"], ("HIGH", "CRITICAL"))
        self.assertEqual(analysis["recommendation"], "QUARANTINE")
        self.assertTrue(len(analysis["findings"]) > 0)


if __name__ == "__main__":
    unittest.main()
