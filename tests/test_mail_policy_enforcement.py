"""
Unit & Integration Test Suite for Guardly Phase 4 / Module 4 (Mail Policy & Enforcement Engine).
Tests Policy Engine Boundary Rules (0-29 ALLOW, 30-64 REVIEW, 65-95 QUARANTINE, 96-100 REJECT),
Config Threshold Validation, Mail Enforcement State Transitions, Isolated Quarantine Vault,
Multi-Tenant RBAC Isolation, Authorized/Unauthorized Quarantine Release, Failure Safety,
Idempotency, and End-to-End LAB Pipeline Integration.
"""

import os
import smtplib
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage
from models.policy import MailDecision, MailQuarantine, MailAuditLog
from services.mail_policy import PolicyEngine, PolicyConfig
from services.mail_enforcement import (
    enforce_mail_decision,
    quarantine_message,
    release_message,
    reject_message,
    get_quarantined_message,
    list_quarantined_messages,
    get_review_messages,
    release_review_message,
)
from services.smtp_receiver import GuardlySMTPServer
from mail.storage import save_raw_email
from services.email_parser import parse_raw_email
from services.threat_analysis import ThreatAnalysisEngine
from tests.test_threat_analysis import find_free_port


class PolicyEngineBoundaryTests(unittest.TestCase):
    """Explicit test coverage for policy decision boundaries and threshold configurations."""

    def setUp(self):
        self.engine = PolicyEngine()

    def test_default_policy_boundary_values(self):
        # ALLOW: 0 - 29 (Inclusive)
        for score in [0, 5, 25, 29]:
            dec, _ = self.engine.evaluate_decision(score)
            self.assertEqual(dec, "ALLOW", f"Score {score} failed expected ALLOW")

        # REVIEW: 30 - 64 (Inclusive)
        for score in [30, 40, 64]:
            dec, _ = self.engine.evaluate_decision(score)
            self.assertEqual(dec, "REVIEW", f"Score {score} failed expected REVIEW")

        # QUARANTINE: 65 - 95 (Inclusive)
        for score in [65, 70, 90, 95]:
            dec, _ = self.engine.evaluate_decision(score)
            self.assertEqual(dec, "QUARANTINE", f"Score {score} failed expected QUARANTINE")

        # REJECT: 96 - 100 (Inclusive)
        for score in [96, 99, 100]:
            dec, _ = self.engine.evaluate_decision(score)
            self.assertEqual(dec, "REJECT", f"Score {score} failed expected REJECT")

    def test_invalid_policy_configuration(self):
        # Overlapping / Gap sequence
        with self.assertRaises(ValueError):
            PolicyConfig(allow_max=35, review_min=30, review_max=64)

        # Out of bounds range
        with self.assertRaises(ValueError):
            PolicyConfig(allow_max=150)


class MailEnforcementUnitTests(unittest.TestCase):
    """Unit tests for Mail Enforcement actions, state machine, vault storage, and multi-tenant RBAC."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["MAIL_QUARANTINE_PATH"] = self.temp_dir.name

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self.temp_dir.cleanup()
        if "MAIL_QUARANTINE_PATH" in os.environ:
            del os.environ["MAIL_QUARANTINE_PATH"]

    def _create_mock_email(self, msg_id: str, score: int = 10, subject: str = "Test Subject") -> EmailMessage:
        raw_path = os.path.join(self.temp_dir.name, f"{msg_id}.eml")
        with open(raw_path, "wb") as f:
            f.write(f"Subject: {subject}\r\nFrom: sender@domain.com\r\nTo: dest@domain.com\r\n\r\nTest Body".encode("utf-8"))

        email_msg = EmailMessage(
            message_id=msg_id,
            from_address="sender@domain.com",
            to_addresses='["dest@domain.com"]',
            subject=subject,
            text_body="Test Body",
            raw_message_path=raw_path,
            risk_score=score,
            status="ANALYZED"
        )
        db.session.add(email_msg)

        q_item = MailQueue(message_id=msg_id, raw_message_path=raw_path, status=MailQueue.STATUS_PROCESSING)
        db.session.add(q_item)

        db.session.commit()
        return email_msg

    def test_enforce_allow_decision(self):
        email_msg = self._create_mock_email("msg_allow_123", score=10)
        dec, status = enforce_mail_decision(email_msg, {"risk_score": 10, "severity": "LOW"})

        self.assertEqual(dec, "ALLOW")
        self.assertEqual(status, "READY_FOR_RELAY")
        self.assertEqual(email_msg.status, "READY_FOR_RELAY")

        # Verify audit log
        audit = MailAuditLog.query.filter_by(message_id="msg_allow_123", action="ALLOW").first()
        self.assertIsNotNone(audit)

    def test_enforce_review_decision(self):
        email_msg = self._create_mock_email("msg_review_456", score=40)
        dec, status = enforce_mail_decision(email_msg, {"risk_score": 40, "severity": "MEDIUM"})

        self.assertEqual(dec, "REVIEW")
        self.assertEqual(status, "REVIEW")
        self.assertEqual(email_msg.status, "REVIEW")

        reviews = get_review_messages()
        self.assertEqual(len(reviews), 1)

    def test_enforce_quarantine_decision_and_vault_file(self):
        email_msg = self._create_mock_email("msg_quar_789", score=85)
        dec, status = enforce_mail_decision(email_msg, {"risk_score": 85, "severity": "HIGH"})

        self.assertEqual(dec, "QUARANTINE")
        self.assertEqual(status, "QUARANTINED")

        quars = list_quarantined_messages()
        self.assertEqual(len(quars), 1)
        quar_record = quars[0]
        self.assertTrue(os.path.exists(quar_record.quarantine_file_path))
        self.assertTrue(quar_record.quarantine_id.startswith("QUAR-"))

    def test_enforce_reject_decision(self):
        email_msg = self._create_mock_email("msg_reject_999", score=98)
        dec, status = enforce_mail_decision(email_msg, {"risk_score": 98, "severity": "CRITICAL"})

        self.assertEqual(dec, "REJECT")
        self.assertEqual(status, "REJECTED")
        self.assertEqual(email_msg.status, "REJECTED")

    def test_failure_safety_defaults_to_review(self):
        email_msg = self._create_mock_email("msg_fail_000", score=0)
        with patch.object(PolicyEngine, "evaluate_decision", side_effect=Exception("Simulated Policy Error")):
            dec, status = enforce_mail_decision(email_msg, {"risk_score": 0})
            self.assertEqual(dec, "REVIEW")
            self.assertEqual(status, "REVIEW")

    def test_authorized_and_unauthorized_quarantine_release(self):
        email_msg = self._create_mock_email("msg_release_test", score=75)
        enforce_mail_decision(email_msg, {"risk_score": 75, "severity": "HIGH"}, tenant_id="Tenant_A")

        quar_record = MailQuarantine.query.filter_by(message_id="msg_release_test").first()
        self.assertIsNotNone(quar_record)

        # Unauthorized Release (Tenant_B admin trying to release Tenant_A message)
        ok, msg = release_message(quar_record.quarantine_id, released_by_user_id="admin_b", user_tenant_id="Tenant_B")
        self.assertFalse(ok)
        self.assertIn("Unauthorized", msg)

        # Authorized Release (Tenant_A admin releasing Tenant_A message)
        ok_auth, msg_auth = release_message(quar_record.quarantine_id, released_by_user_id="admin_a", user_tenant_id="Tenant_A")
        self.assertTrue(ok_auth)
        self.assertIn("released successfully", msg_auth)

        # Verify state -> READY_FOR_RELAY
        updated_msg = EmailMessage.query.filter_by(message_id="msg_release_test").first()
        self.assertEqual(updated_msg.status, "READY_FOR_RELAY")

        # Double Release Prevention
        ok_repeat, _ = release_message(quar_record.quarantine_id, released_by_user_id="admin_a", user_tenant_id="Tenant_A")
        self.assertFalse(ok_repeat)

    def test_quarantine_idempotency(self):
        email_msg = self._create_mock_email("msg_dup_quar", score=80)
        q1 = quarantine_message(email_msg, "Phishing", 80, "HIGH", tenant_id="default")
        q2 = quarantine_message(email_msg, "Phishing", 80, "HIGH", tenant_id="default")
        self.assertEqual(q1.id, q2.id)


class EndToEndLabPipelineEnforcementTests(unittest.TestCase):
    """
    End-to-End LAB Mode Pipeline Integration Test:
    SMTP -> Queue -> Parser -> Threat Analysis -> Policy Engine -> Mail Enforcement.
    """

    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["MAIL_QUARANTINE_PATH"] = os.path.join(self.temp_dir.name, "quarantine")

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self.temp_dir.cleanup()
        if "MAIL_QUARANTINE_PATH" in os.environ:
            del os.environ["MAIL_QUARANTINE_PATH"]

    def _run_lab_pipeline(self, msg_id: str, subject: str, body: str, headers: str = "") -> Tuple[str, str, int]:
        eml_bytes = f"Subject: {subject}\r\nFrom: sender@domain.com\r\nTo: dest@domain.com\r\n{headers}\r\n\r\n{body}".encode("utf-8")
        eml_path = os.path.join(self.temp_dir.name, f"{msg_id}.eml")
        with open(eml_path, "wb") as f:
            f.write(eml_bytes)

        parsed = parse_raw_email(eml_bytes, fallback_message_id=msg_id)
        engine = ThreatAnalysisEngine()
        analysis_res = engine.analyze(parsed)

        email_msg = EmailMessage(
            message_id=msg_id,
            from_address=parsed.get("from"),
            to_addresses='["dest@domain.com"]',
            subject=parsed.get("subject"),
            text_body=parsed.get("text_body"),
            raw_message_path=eml_path,
            risk_score=analysis_res["risk_score"],
            severity=analysis_res["severity"],
            status="ANALYZED"
        )
        db.session.add(email_msg)
        db.session.commit()

        dec, status = enforce_mail_decision(email_msg, analysis_res, tenant_id="default")
        return dec, status, analysis_res["risk_score"]

    def test_pipeline_test_a_clean_email_allow(self):
        dec, status, score = self._run_lab_pipeline("test_a_clean", "Team Meeting Notes", "Hi team, here are the meeting notes.")
        self.assertLessEqual(score, 29)
        self.assertEqual(dec, "ALLOW")
        self.assertEqual(status, "READY_FOR_RELAY")

    def test_pipeline_test_b_uncertain_email_review(self):
        dec, status, score = self._run_lab_pipeline(
            "test_b_review",
            "Action Required: Password Change",
            "Please verify your credentials within 24 hours.",
            headers="Reply-To: external-support@scam.net\r\n"
        )
        self.assertTrue(30 <= score <= 64)
        self.assertEqual(dec, "REVIEW")
        self.assertEqual(status, "REVIEW")

    def test_pipeline_test_c_phishing_email_quarantine(self):
        dec, status, score = self._run_lab_pipeline(
            "test_c_quarantine",
            "URGENT: Account Suspended Immediately",
            "Click http://192.168.1.1/login to prevent permanent deletion.",
            headers="From: PayPal Support <login@paypal-security-alert.top>\r\nReply-To: attacker@evil.com\r\n"
        )
        self.assertTrue(65 <= score <= 95)
        self.assertEqual(dec, "QUARANTINE")
        self.assertEqual(status, "QUARANTINED")

    def test_pipeline_test_d_critical_email_reject(self):
        dec, status, score = self._run_lab_pipeline(
            "test_d_reject",
            "CRITICAL: Password Expired",
            "Enter password at http://192.168.1.1/verify and open attached invoice_update.pdf.exe",
            headers="From: PayPal Support <login@paypal-security-alert.top>\r\nReply-To: attacker@evil.com\r\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\r\n"
        )
        self.assertGreaterEqual(score, 96)
        self.assertEqual(dec, "REJECT")
        self.assertEqual(status, "REJECTED")


if __name__ == "__main__":
    unittest.main()
