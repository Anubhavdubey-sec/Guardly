"""
Unit & Integration Test Suite for Guardly Phase 4 / Module 5 (Secure Mail Relay & Outbound Delivery Engine).
Tests Outbound SMTP Delivery, Lab Mock Relay Mode, Relay Failure Handling, Batch Relay Processing,
Audit Telemetry Logs, and Full End-to-End Pipeline (Port 2525 Receiver -> Modules 1-4 -> Target Port 2526 SMTP Relay -> DELIVERED).
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
from models.policy import MailDecision, MailAuditLog
from models.relay import MailRelayLog
from services.mail_relay import MailRelayEngine, RelayConfig, process_relay_queue
from services.smtp_receiver import GuardlySMTPServer
from mail.storage import get_stored_emails
from services.mail_queue import process_pending_queue
from tests.test_threat_analysis import find_free_port


class MailRelayUnitTests(unittest.TestCase):
    """Unit tests for MailRelayEngine, Mock Mode, Failure Handling, and Audit Telemetry."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self.temp_dir.cleanup()

    def _create_mock_ready_email(self, msg_id: str = "msg_relay_001") -> EmailMessage:
        raw_path = os.path.join(self.temp_dir.name, f"{msg_id}.eml")
        with open(raw_path, "wb") as f:
            f.write(b"From: sender@domain.com\r\nTo: dest@domain.com\r\nSubject: Test Relay\r\n\r\nBody")

        email_msg = EmailMessage(
            message_id=msg_id,
            from_address="sender@domain.com",
            to_addresses='["dest@domain.com"]',
            subject="Test Relay",
            text_body="Body",
            raw_message_path=raw_path,
            risk_score=10,
            status="READY_FOR_RELAY"
        )
        db.session.add(email_msg)

        q_item = MailQueue(message_id=msg_id, raw_message_path=raw_path, status=MailQueue.STATUS_READY_FOR_RELAY)
        db.session.add(q_item)

        db.session.commit()
        return email_msg

    def test_mock_mode_relay_delivery(self):
        email_msg = self._create_mock_ready_email("msg_mock_relay_100")
        config = RelayConfig(enabled=True, mock_mode=True)
        engine = MailRelayEngine(config=config)

        success, msg = engine.relay_message(email_msg, tenant_id="default")
        self.assertTrue(success)
        self.assertIn("Simulated", msg)

        # Check DB State -> DELIVERED
        self.assertEqual(email_msg.status, "DELIVERED")

        q_item = MailQueue.query.filter_by(message_id="msg_mock_relay_100").first()
        self.assertEqual(q_item.status, MailQueue.STATUS_DELIVERED)

        # Check Relay Log
        relay_log = MailRelayLog.query.filter_by(message_id="msg_mock_relay_100").first()
        self.assertIsNotNone(relay_log)
        self.assertEqual(relay_log.status, "DELIVERED")
        self.assertEqual(relay_log.smtp_code, 250)

        # Check Audit Log
        audit = MailAuditLog.query.filter_by(message_id="msg_mock_relay_100", action="DELIVERED").first()
        self.assertIsNotNone(audit)

    def test_relay_failure_handling(self):
        email_msg = self._create_mock_ready_email("msg_fail_relay_200")
        config = RelayConfig(enabled=True, host="127.0.0.1", port=59999, mock_mode=False, timeout=1)
        engine = MailRelayEngine(config=config)

        success, msg = engine.relay_message(email_msg, tenant_id="default")
        self.assertFalse(success)
        self.assertIn("connection error", msg.lower())

        # Check DB State -> FAILED
        self.assertEqual(email_msg.status, "FAILED")

        q_item = MailQueue.query.filter_by(message_id="msg_fail_relay_200").first()
        self.assertEqual(q_item.status, MailQueue.STATUS_FAILED)

        relay_log = MailRelayLog.query.filter_by(message_id="msg_fail_relay_200").first()
        self.assertIsNotNone(relay_log)
        self.assertEqual(relay_log.status, "FAILED")

    def test_process_relay_queue_batch(self):
        for i in range(3):
            self._create_mock_ready_email(f"msg_batch_relay_{i}")

        config = RelayConfig(enabled=True, mock_mode=True)
        with patch("services.mail_relay.RelayConfig", return_value=config):
            relayed_count = process_relay_queue(self.app, max_jobs=5)
            self.assertEqual(relayed_count, 3)

            for i in range(3):
                msg = EmailMessage.query.filter_by(message_id=f"msg_batch_relay_{i}").first()
                self.assertEqual(msg.status, "DELIVERED")


class FullEndToEndMailRelayPipelineTests(unittest.TestCase):
    """
    End-to-End Pipeline Integration Test (Modules 1 -> 2 -> 3 -> 4 -> 5):
    SMTP Gateway (Port A) -> Queue -> Parser -> Threat Engine -> Policy Engine (ALLOW) -> Enforcement -> Mail Relay -> Target SMTP (Port B) -> DELIVERED.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Inbound Gateway Receiver Port
        self.rx_port = find_free_port()
        self.rx_server = GuardlySMTPServer(
            host="127.0.0.1",
            port=self.rx_port,
            storage_path=self.temp_dir.name,
        )
        self.rx_server.start()

        # Outbound Target Destination SMTP Server Port
        self.target_port = find_free_port()
        self.target_server = GuardlySMTPServer(
            host="127.0.0.1",
            port=self.target_port,
            storage_path=os.path.join(self.temp_dir.name, "target_rx"),
        )
        self.target_server.start()

    def tearDown(self):
        if self.rx_server and self.rx_server.is_running:
            self.rx_server.stop()
        if self.target_server and self.target_server.is_running:
            self.target_server.stop()

        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self.temp_dir.cleanup()

    def test_full_end_to_end_delivery_pipeline(self):
        """Send clean email over SMTP and verify full pipeline to Target SMTP server."""
        client = smtplib.SMTP("127.0.0.1", self.rx_port, timeout=5)
        client.ehlo("localhost")

        msg = (
            "From: alice@company.com\r\n"
            "To: bob@company.com\r\n"
            "Subject: Module 5 End-to-End Relay Test\r\n"
            "\r\n"
            "Hi Bob, this is a clean test email for outbound relay verification."
        )

        client.sendmail("alice@company.com", ["bob@company.com"], msg)
        client.quit()

        # 1. Retrieve stored raw email & enqueue
        stored_files = get_stored_emails(self.temp_dir.name)
        self.assertGreaterEqual(len(stored_files), 1)

        from services.mail_queue import enqueue_message
        full_path = os.path.join(self.temp_dir.name, stored_files[0])
        enqueue_message(full_path, message_id="e2e_relay_msg_001")

        # 2. Process Queue (Parse + Threat Engine + Policy Engine -> READY_FOR_RELAY)
        processed_count = process_pending_queue(self.app, max_jobs=5)
        self.assertEqual(processed_count, 1)

        email_msg = EmailMessage.query.filter_by(message_id="e2e_relay_msg_001").first()
        self.assertIsNotNone(email_msg)
        self.assertEqual(email_msg.status, "READY_FOR_RELAY")

        # 3. Process Outbound Mail Relay to Target SMTP Server (Port B)
        relay_config = RelayConfig(enabled=True, host="127.0.0.1", port=self.target_port, mock_mode=False)
        relay_engine = MailRelayEngine(config=relay_config)

        success, response_str = relay_engine.relay_message(email_msg, tenant_id="default")
        self.assertTrue(success)
        self.assertIn("250", response_str)

        # 4. Verify Final State Machine -> DELIVERED
        self.assertEqual(email_msg.status, "DELIVERED")

        q_item = MailQueue.query.filter_by(message_id="e2e_relay_msg_001").first()
        self.assertEqual(q_item.status, MailQueue.STATUS_DELIVERED)

        # 5. Verify Target SMTP Server received the relayed file
        target_rx_dir = os.path.join(self.temp_dir.name, "target_rx")
        target_files = get_stored_emails(target_rx_dir)
        self.assertGreaterEqual(len(target_files), 1)


if __name__ == "__main__":
    unittest.main()
