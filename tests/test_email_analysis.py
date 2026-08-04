import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.phishing_detector import analyze_email
from scanner.email_parser import parse_email


class EmailAnalysisTests(unittest.TestCase):
    def test_clean_email_analysis(self):
        email_data = {
            "from": "alice@example.com",
            "from_address": "alice@example.com",
            "to": "bob@example.com",
            "subject": "Meeting reminder",
            "date": "Mon, 1 Jan 2026 10:00:00 +0000",
            "reply_to": "",
            "body": "Hi Bob, see you at 10am.",
            "urls": [],
            "attachments": [],
            "headers": {"from_address": "alice@example.com"},
            "has_html": False,
            "has_plain_text": True,
            "iocs": {"domains": ["example.com"], "ip_addresses": [], "urls": []},
        }
        result = analyze_email(email_data)
        self.assertEqual(result["verdict"], "Low Risk")
        self.assertLess(result["score"], 20)

    def test_phishing_email_with_suspicious_url_and_attachment(self):
        email_data = {
            "from": "security@bank-verify.com",
            "from_address": "security@bank-verify.com",
            "to": "target@example.com",
            "subject": "URGENT: Verify your account now",
            "date": "Mon, 1 Jan 2026 10:00:00 +0000",
            "reply_to": "attacker@evil.com",
            "body": "Click here to log in: http://192.168.1.1/login and see attachment.",
            "urls": ["http://192.168.1.1/login"],
            "attachments": [{"filename": "invoice.exe", "content_type": "application/x-msdownload", "size": 1024}],
            "headers": {"from_address": "security@bank-verify.com"},
            "has_html": True,
            "has_plain_text": True,
            "iocs": {"domains": ["bank-verify.com", "evil.com"], "ip_addresses": ["192.168.1.1"], "urls": ["http://192.168.1.1/login"]},
        }
        result = analyze_email(email_data)
        self.assertEqual(result["verdict"], "High Risk")
        self.assertGreaterEqual(result["score"], 50)

    def test_email_parser_with_raw_eml(self):
        eml_content = (
            "From: Sender <sender@example.com>\n"
            "To: Receiver <receiver@example.com>\n"
            "Subject: Test Subject\n"
            "Date: Mon, 1 Jan 2026 10:00:00 +0000\n"
            "\n"
            "This is a test email body."
        )
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".eml") as tmp:
            tmp.write(eml_content)
            tmp_path = tmp.name
        try:
            parsed = parse_email(tmp_path)
            self.assertEqual(parsed["from"], "Sender <sender@example.com>")
            self.assertEqual(parsed["subject"], "Test Subject")
            self.assertIn("This is a test email body.", parsed["body"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_url_extraction(self):
        email_data = {
            "from": "test@example.com",
            "from_address": "test@example.com",
            "to": "user@example.com",
            "subject": "Link test",
            "date": "Mon, 1 Jan 2026 10:00:00 +0000",
            "reply_to": "",
            "body": "Check this: https://example.com/test",
            "urls": ["https://example.com/test"],
            "attachments": [],
            "headers": {},
            "has_html": False,
            "has_plain_text": True,
            "iocs": {"domains": ["example.com"], "ip_addresses": [], "urls": ["https://example.com/test"]},
        }
        result = analyze_email(email_data)
        self.assertEqual(len(result["url_assessments"]), 1)
        self.assertEqual(result["url_assessments"][0]["url"], "https://example.com/test")


if __name__ == "__main__":
    unittest.main()
