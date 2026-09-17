"""
Unit & Integration Test Suite for Guardly Phase 5 (Gmail Workspace Post-Delivery Scanner).
Tests Gmail API Mock Authentication, Message Listing, Raw Email Retrieval, Threat Engine Evaluation,
Automated Post-Delivery Remediation (Trashing/Quarantining), Audit Logging, and Batch Inbox Scans.
"""

import unittest
from app import create_app
from models.user import db
from models.policy import MailAuditLog
from models.gmail_scan import GmailPostDeliveryScan
from services.gmail_scanner import (
    GmailScannerConfig,
    GmailPostDeliveryScanner,
    process_gmail_inbox_scans,
)


class GmailScannerUnitTests(unittest.TestCase):
    """Unit tests for Gmail Post-Delivery Threat Scanner."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_scanner_config_defaults(self):
        config = GmailScannerConfig(mock_mode=True, risk_threshold=65)
        self.assertTrue(config.mock_mode)
        self.assertEqual(config.risk_threshold, 65)
        self.assertEqual(config.remediation_action, "TRASH")

    def test_list_and_get_message_raw_mock_mode(self):
        scanner = GmailPostDeliveryScanner(config=GmailScannerConfig(mock_mode=True))
        messages = scanner.list_user_messages("user@company.com", max_results=5)
        self.assertGreater(len(messages), 0)

        raw_bytes = scanner.get_message_raw_bytes("user@company.com", messages[0]["id"])
        self.assertIsNotNone(raw_bytes)
        self.assertIn(b"Subject:", raw_bytes)

    def test_scan_clean_message_allowed(self):
        scanner = GmailPostDeliveryScanner(config=GmailScannerConfig(mock_mode=True))
        res = scanner.scan_user_message("user@company.com", "mock_clean_001")

        self.assertEqual(res["action_taken"], "ALLOWED")
        self.assertLess(res["risk_score"], 65)

        # Check DB record
        scan_record = GmailPostDeliveryScan.query.filter_by(gmail_message_id="mock_clean_001").first()
        self.assertIsNotNone(scan_record)
        self.assertEqual(scan_record.action_taken, "ALLOWED")

    def test_scan_phishing_message_trashed_and_audited(self):
        scanner = GmailPostDeliveryScanner(config=GmailScannerConfig(mock_mode=True, risk_threshold=65))
        res = scanner.scan_user_message("user@company.com", "mock_phish_003")

        self.assertEqual(res["action_taken"], "TRASHED")
        self.assertGreaterEqual(res["risk_score"], 65)

        # Check Telemetry DB Record
        scan_record = GmailPostDeliveryScan.query.filter_by(gmail_message_id="mock_phish_003").first()
        self.assertIsNotNone(scan_record)
        self.assertEqual(scan_record.action_taken, "TRASHED")

        # Check Audit Telemetry Log
        audit_log = MailAuditLog.query.filter_by(message_id="mock_phish_003", action="POST_DELIVERY_QUARANTINED").first()
        self.assertIsNotNone(audit_log)

    def test_process_gmail_inbox_scans_batch(self):
        res = process_gmail_inbox_scans(self.app, ["user1@company.com", "user2@company.com"], max_results=3)

        self.assertGreaterEqual(res["total_scanned"], 4)
        self.assertGreaterEqual(res["total_remediated"], 2)
        self.assertEqual(len(res["results"]), res["total_scanned"])


if __name__ == "__main__":
    unittest.main()
