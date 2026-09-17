import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.phishing_detector import (
    KEYWORD_CATEGORIES,
    SUSPICIOUS_KEYWORDS,
    analyze_email,
    normalize_for_matching,
)
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
        self.assertIn("Urgency / pressure tactics", result["categories"])
        self.assertIn("Credential harvesting / account security", result["categories"])

    def test_extra_spaces_evasion_caught(self):
        email_data = {
            "from": "security@service.com",
            "from_address": "security@service.com",
            "to": "target@example.com",
            "subject": "Account Alert",
            "body": "Please v e r i f y  your account immediately.",
            "urls": [],
            "attachments": [],
            "headers": {},
        }
        result = analyze_email(email_data)
        self.assertIn("Credential harvesting / account security", result["categories"])
        self.assertGreaterEqual(result["score"], 20)

    def test_leetspeak_evasion_caught(self):
        email_data = {
            "from": "alert@service.com",
            "from_address": "alert@service.com",
            "to": "target@example.com",
            "subject": "Secur1ty Notice",
            "body": "Please ver1fy y0ur acc0unt to continue.",
            "urls": [],
            "attachments": [],
            "headers": {},
        }
        result = analyze_email(email_data)
        self.assertIn("Credential harvesting / account security", result["categories"])
        self.assertGreaterEqual(result["score"], 20)

    def test_body_only_keyword_match(self):
        email_data = {
            "from": "support@service.com",
            "from_address": "support@service.com",
            "to": "user@example.com",
            "subject": "Regular Notification",
            "body": "Please click here to verify your account immediately.",
            "urls": [],
            "attachments": [],
            "headers": {},
        }
        result = analyze_email(email_data)
        self.assertIn("Credential harvesting / account security", result["categories"])
        self.assertGreaterEqual(result["score"], 20)
        finding_texts = " ".join(result["findings"])
        self.assertIn("verify your account", finding_texts)

    def test_multiple_keyword_categories_matching(self):
        email_data = {
            "from": "alert@bank.com",
            "from_address": "alert@bank.com",
            "to": "user@example.com",
            "subject": "Urgent final notice",  # Urgency (12)
            "body": "Payment failed for your account. Update your password now.",  # Financial (18) + Credential (20) -> sum 50, capped at 40
            "urls": [],
            "attachments": [],
            "headers": {},
        }
        result = analyze_email(email_data)
        self.assertIn("Urgency / pressure tactics", result["categories"])
        self.assertIn("Financial / billing lures", result["categories"])
        self.assertIn("Credential harvesting / account security", result["categories"])
        self.assertEqual(result["score"], 40)

    def test_keyword_score_40_cap_respected(self):
        email_data = {
            "from": "scammer@scam.com",
            "from_address": "scammer@scam.com",
            "to": "victim@example.com",
            "subject": "Urgent: Final notice! You have won a free gift card",
            "body": (
                "Verify your account now. Payment failed. Virus detected on your computer. "
                "Delivery failed package on hold. I have access to your webcam recording. "
                "Direct deposit change requested. IRS notice unpaid taxes. Your insurance claim update."
            ),
            "urls": [],
            "attachments": [],
            "headers": {},
        }
        result = analyze_email(email_data)
        self.assertEqual(result["score"], 40)
        self.assertGreaterEqual(len(result["categories"]), 5)

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

    def test_assess_url_heuristics(self):
        from scanner.url_heuristics import assess_url
        clean_reasons = assess_url("https://www.google.com")
        self.assertEqual(clean_reasons, [])

        suspicious_reasons = assess_url("http://paypal-security-update.com/verify")
        self.assertTrue(any("impersonate Paypal" in r for r in suspicious_reasons))
        self.assertTrue(any("suspicious keywords" in r for r in suspicious_reasons))

    def test_domain_based_suspicious_url_flagged_in_email(self):
        email_data = {
            "from": "newsletter@domain.com",
            "from_address": "newsletter@domain.com",
            "to": "user@example.com",
            "subject": "Monthly Newsletter",
            "body": "Click here to unsubscribe: https://example.xyz/track/user123",
            "urls": ["https://example.xyz/track/user123"],
            "attachments": [],
            "headers": {},
        }
        result = analyze_email(email_data)
        self.assertEqual(result["url_assessments"][0]["status"], "Suspicious")
        self.assertIn("Suspicious URL", result["categories"])
        self.assertGreaterEqual(result["score"], 25)
    def test_is_ip_literal_strict_validation(self):
        from scanner.url_heuristics import is_ip_literal
        self.assertTrue(is_ip_literal("192.168.1.1"))
        self.assertTrue(is_ip_literal("8.8.8.8"))
        self.assertTrue(is_ip_literal("::1"))
        self.assertTrue(is_ip_literal("[2607:f8b0:4005:805::200e]:443"))

    def test_check_brand_impersonation_tokenization(self):
        from scanner.url_heuristics import check_brand_impersonation
        # False positives prevented (substring in larger domain label)
        self.assertIsNone(check_brand_impersonation("googleapis.com"))
        self.assertIsNone(check_brand_impersonation("amazonaws.com"))
        self.assertIsNone(check_brand_impersonation("purchase.com"))
        self.assertIsNone(check_brand_impersonation("snapple.com"))

        # True positives preserved
        self.assertEqual(check_brand_impersonation("paypal-secure-login.com"), "Paypal")
        self.assertEqual(check_brand_impersonation("apple-support-verify.org"), "Apple")

    def test_benign_email_with_analytics_and_s3_images(self):
        eml_content = """From: support@company.com
To: user@company.com
Subject: Your Order Shipping Confirmation
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>Thank you for your order! Your items have shipped.</p>
<p><img src="https://my-bucket.s3.amazonaws.com/images/banner.png" alt="Banner"></p>
<p>Track your shipment or view order details on your <a href="https://www.company.com/track?id=12345">Account Dashboard</a>.</p>
<script src="https://googleapis.com/analytics.js"></script>
</body>
</html>
"""
        with tempfile.NamedTemporaryFile("wb", suffix=".eml", delete=False) as tf:
            tf.write(eml_content.encode("utf-8"))
            tf_path = tf.name

        try:
            parsed = parse_email(tf_path)
            result = analyze_email(parsed)
            self.assertEqual(result["verdict"], "Low Risk")
            self.assertEqual(result["score"], 0)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()
