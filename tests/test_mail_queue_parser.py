"""
Unit & Integration Test Suite for Guardly Phase 4 / Module 2 (Mail Queue & Email Parser).
Tests plain text, HTML, multiple recipients, CC, Reply-To, plain & HTML URLs,
attachments (PDF, multiple, empty, path traversal filenames), malformed MIME,
large emails, queue duplicate handling, retries, and parser failure handling.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage, EmailAttachment
from services.email_parser import parse_raw_email, sanitize_filename, extract_urls_from_text_and_html
from services.mail_queue import enqueue_message, process_queue_job, process_pending_queue


class EmailParserUnitTests(unittest.TestCase):
    """Unit tests for Email Parser, URL extraction, and filename sanitization."""

    def test_sanitize_filename_security(self):
        # Path traversal attempts
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\windows\\system32\\cmd.exe"), "cmd.exe")
        self.assertEqual(sanitize_filename("../malicious.sh"), "malicious.sh")
        self.assertFalse(".." in sanitize_filename(".._.._file.txt"))

        # Injection characters
        cleaned = sanitize_filename('test\x00file<script>:|*.pdf')
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("<", cleaned)
        self.assertNotIn(":", cleaned)

    def test_extract_urls_from_text_and_html(self):
        text_body = "Check https://example.com/login and http://test.org/verify."
        html_body = '<a href="https://phish.net/reset">Reset</a> <img src="http://tracker.io/pixel.png"/>'

        urls = extract_urls_from_text_and_html(text_body, html_body)
        self.assertIn("https://example.com/login", urls)
        self.assertIn("http://test.org/verify", urls)
        self.assertIn("https://phish.net/reset", urls)
        self.assertIn("http://tracker.io/pixel.png", urls)

    def test_plain_text_email_parsing(self):
        raw_eml = (
            b"From: sender@domain.com\r\n"
            b"To: recipient1@target.com, recipient2@target.com\r\n"
            b"Cc: cc@target.com\r\n"
            b"Reply-To: reply@domain.com\r\n"
            b"Subject: Simple Plain Text\r\n"
            b"Date: Sat, 08 Aug 2026 12:00:00 +0000\r\n"
            b"Message-ID: <unique-plain-123@domain.com>\r\n"
            b"\r\n"
            b"Hello world, visit https://secure-bank.local/login"
        )
        parsed = parse_raw_email(raw_eml)
        self.assertEqual(parsed["from"], "sender@domain.com")
        self.assertEqual(len(parsed["to"]), 2)
        self.assertIn("recipient1@target.com", parsed["to"])
        self.assertEqual(parsed["cc"], ["cc@target.com"])
        self.assertEqual(parsed["reply_to"], "reply@domain.com")
        self.assertEqual(parsed["subject"], "Simple Plain Text")
        self.assertIn("Hello world", parsed["text_body"])
        self.assertEqual(parsed["urls"], ["https://secure-bank.local/login"])

    def test_html_email_parsing(self):
        raw_eml = (
            b"From: brand@service.com\r\n"
            b"To: user@target.com\r\n"
            b"Subject: HTML Notice\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"\r\n"
            b"<html><body><h1>Alert</h1><a href=\"https://html-link.com/action\">Click Here</a></body></html>"
        )
        parsed = parse_raw_email(raw_eml)
        self.assertIn("Alert", parsed["html_body"])
        self.assertEqual(parsed["urls"], ["https://html-link.com/action"])

    def test_pdf_and_multiple_attachments_parsing(self):
        # Build multipart MIME with a text part and two attachment parts (including a PDF)
        boundary = "----=_Boundary_12345"
        pdf_content = b"%PDF-1.4 %EOF"
        empty_content = b""

        raw_eml = (
            f"From: sender@domain.com\r\n"
            f"To: target@domain.com\r\n"
            f"Subject: Attachments Test\r\n"
            f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
            f"\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/plain\r\n\r\n"
            f"Please review attached documents.\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
            f"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
            f"JVBERi0xLjQgJUVPRg==\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/plain; name=\"empty.txt\"\r\n"
            f"Content-Disposition: attachment; filename=\"empty.txt\"\r\n\r\n"
            f"\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as temp_dir:
            parsed = parse_raw_email(raw_eml, attachment_storage_dir=temp_dir)
            self.assertEqual(len(parsed["attachments"]), 2)

            pdf_att = next(a for a in parsed["attachments"] if a["filename"] == "invoice.pdf")
            self.assertEqual(pdf_att["mime_type"], "application/pdf")
            self.assertTrue(os.path.exists(pdf_att["storage_path"]))

            empty_att = next(a for a in parsed["attachments"] if a["filename"] == "empty.txt")
            self.assertEqual(empty_att["size"], 0)

    def test_path_traversal_filename_attachment(self):
        boundary = "----=_Boundary_999"
        raw_eml = (
            f"From: attacker@evil.com\r\n"
            f"To: victim@company.com\r\n"
            f"Subject: Traversal Test\r\n"
            f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
            f"\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/plain; name=\"../../evil.sh\"\r\n"
            f"Content-Disposition: attachment; filename=\"../../evil.sh\"\r\n\r\n"
            f"echo Hacked\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as temp_dir:
            parsed = parse_raw_email(raw_eml, attachment_storage_dir=temp_dir)
            self.assertEqual(len(parsed["attachments"]), 1)
            att = parsed["attachments"][0]
            self.assertEqual(att["filename"], "evil.sh")
            self.assertTrue(att["storage_path"].startswith(os.path.abspath(temp_dir)))

    def test_malformed_mime_handling(self):
        raw_eml = b"From: malformed\r\nSubject: Broken\r\n\r\nUnfinished MIME =?invalid?B?broken"
        parsed = parse_raw_email(raw_eml)
        self.assertEqual(parsed["subject"], "Broken")

    def test_large_email_parsing(self):
        large_body = "X" * (1024 * 100)  # 100 KB string
        raw_eml = f"From: big@domain.com\r\nTo: dest@domain.com\r\nSubject: Big\r\n\r\n{large_body}".encode("utf-8")
        parsed = parse_raw_email(raw_eml)
        self.assertEqual(len(parsed["text_body"]), len(large_body))


class MailQueueIntegrationTests(unittest.TestCase):
    """Integration tests for Mail Queue state transitions, retries, and DB persistence."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_full_queue_enqueue_to_parsed_pipeline(self):
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            f.write(b"From: queue@test.com\r\nTo: dest@test.com\r\nSubject: Queue Job Test\r\n\r\nBody Content")
            raw_path = f.name

        try:
            msg_id = "test_queue_job_001"
            q_entry = enqueue_message(raw_path, message_id=msg_id)
            self.assertEqual(q_entry.status, MailQueue.STATUS_QUEUED)

            # Process job
            success = process_queue_job(msg_id)
            self.assertTrue(success)

            # Check MailQueue state -> READY_FOR_ANALYSIS
            updated_q = MailQueue.query.filter_by(message_id=msg_id).first()
            self.assertEqual(updated_q.status, MailQueue.STATUS_READY_FOR_ANALYSIS)
            self.assertIsNotNone(updated_q.completed_at)

            # Check EmailMessage record in DB
            email_msg = EmailMessage.query.filter_by(message_id=msg_id).first()
            self.assertIsNotNone(email_msg)
            self.assertEqual(email_msg.from_address, "queue@test.com")
            self.assertEqual(email_msg.subject, "Queue Job Test")
            self.assertEqual(email_msg.status, "READY_FOR_ANALYSIS")
        finally:
            if os.path.exists(raw_path):
                os.remove(raw_path)

    def test_duplicate_message_enqueue_prevention(self):
        msg_id = "dup_msg_123"
        q1 = enqueue_message("/tmp/dummy1.eml", message_id=msg_id)
        q2 = enqueue_message("/tmp/dummy2.eml", message_id=msg_id)
        self.assertEqual(q1.id, q2.id)

    def test_queue_retry_and_failure(self):
        msg_id = "retry_msg_999"
        q_entry = enqueue_message("/nonexistent/file/path.eml", message_id=msg_id)

        # 1st processing attempt -> fails, retry_count=1, status=QUEUED
        success1 = process_queue_job(msg_id)
        self.assertFalse(success1)
        q_after1 = MailQueue.query.filter_by(message_id=msg_id).first()
        self.assertEqual(q_after1.retry_count, 1)
        self.assertEqual(q_after1.status, MailQueue.STATUS_QUEUED)

        # 2nd attempt
        process_queue_job(msg_id)
        # 3rd attempt -> fails permanently -> status=FAILED
        process_queue_job(msg_id)

        q_after3 = MailQueue.query.filter_by(message_id=msg_id).first()
        self.assertEqual(q_after3.retry_count, 3)
        self.assertEqual(q_after3.status, MailQueue.STATUS_FAILED)
        self.assertIn("missing", q_after3.error_message)

    def test_process_pending_queue_batch(self):
        paths = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
                f.write(f"From: sender{i}@test.com\r\nSubject: Batch {i}\r\n\r\nBody".encode("utf-8"))
                paths.append(f.name)
                enqueue_message(f.name, message_id=f"batch_job_{i}")

        try:
            count = process_pending_queue(self.app, max_jobs=5)
            self.assertEqual(count, 3)

            for i in range(3):
                q = MailQueue.query.filter_by(message_id=f"batch_job_{i}").first()
                self.assertEqual(q.status, MailQueue.STATUS_READY_FOR_ANALYSIS)
        finally:
            for p in paths:
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
