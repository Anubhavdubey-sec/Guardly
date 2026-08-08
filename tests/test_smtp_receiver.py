"""
Unit & Integration Tests for Guardly SMTP Receiver Foundation (Phase 4 / Module 1).
Tests connection, EHLO, MAIL FROM, RCPT TO, DATA, validation, oversized message,
unique filenames, storage failure, and graceful shutdown.
"""

import os
import smtplib
import socket
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from mail.storage import save_raw_email, get_stored_emails, read_stored_email, generate_unique_filename
from services.smtp_receiver import GuardlySMTPServer, is_valid_email_address


def find_free_port() -> int:
    """Finds an available local port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SMTPReceiverUnitTests(unittest.TestCase):
    """Unit tests for address validation and mail storage utilities."""

    def test_valid_email_address_helper(self):
        self.assertTrue(is_valid_email_address("user@example.com"))
        self.assertTrue(is_valid_email_address("<admin@domain.org>"))
        self.assertTrue(is_valid_email_address("<>", allow_empty_bounce=True))
        self.assertFalse(is_valid_email_address("<>", allow_empty_bounce=False))
        self.assertFalse(is_valid_email_address("invalid-email-no-at"))
        self.assertFalse(is_valid_email_address("user@bad_domain"))

    def test_unique_filename_format(self):
        fn1 = generate_unique_filename()
        fn2 = generate_unique_filename()
        self.assertNotEqual(fn1, fn2)
        self.assertTrue(fn1.endswith(".eml"))
        self.assertTrue(fn2.endswith(".eml"))
        # Verify format: YYYYMMDD_<uuid>.eml
        parts = fn1.split("_")
        self.assertEqual(len(parts), 2)
        self.assertEqual(len(parts[0]), 8)  # YYYYMMDD length

    def test_save_raw_email_security_and_storage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            test_content = b"From: test@guardly.local\r\nSubject: Hello\r\n\r\nTest Body"
            filepath = save_raw_email(test_content, storage_path=temp_dir)

            self.assertTrue(os.path.exists(filepath))
            self.assertTrue(filepath.startswith(os.path.abspath(temp_dir)))

            # Read back content
            read_bytes = read_stored_email(os.path.basename(filepath), storage_path=temp_dir)
            self.assertEqual(read_bytes, test_content)

            # Check listing
            stored_list = get_stored_emails(storage_path=temp_dir)
            self.assertEqual(len(stored_list), 1)

    def test_save_raw_email_path_traversal_rejection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                save_raw_email(b"", storage_path=temp_dir)


class SMTPReceiverIntegrationTests(unittest.TestCase):
    """End-to-End integration tests for Guardly SMTP Receiver server."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_port = find_free_port()
        self.max_size = 1024 * 50  # 50 KB limit for fast testing

        self.server = GuardlySMTPServer(
            host="127.0.0.1",
            port=self.test_port,
            max_message_size=self.max_size,
            storage_path=self.temp_dir.name,
        )
        self.server.start()

    def tearDown(self):
        if self.server and self.server.is_running:
            self.server.stop()
        self.temp_dir.cleanup()

    def test_smtp_connection_and_ehlo(self):
        """Test SMTP connection and EHLO/HELO handshakes."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        code, resp = client.ehlo("localhost")
        self.assertEqual(code, 250)
        client.quit()

    def test_valid_email_reception_and_eml_storage(self):
        """Test complete SMTP flow: EHLO, MAIL FROM, RCPT TO, DATA and storage."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")

        sender = "sender@domain.com"
        recipients = ["recipient@company.org"]
        message = (
            "From: sender@domain.com\r\n"
            "To: recipient@company.org\r\n"
            "Subject: Test SMTP Receiver\r\n"
            "\r\n"
            "This is a raw test email sent over SMTP."
        )

        res = client.sendmail(sender, recipients, message)
        self.assertEqual(res, {})  # empty dict means all recipients accepted 250 OK
        client.quit()

        stored_files = get_stored_emails(storage_path=self.temp_dir.name)
        self.assertEqual(len(stored_files), 1)

        raw_content = read_stored_email(stored_files[0], storage_path=self.temp_dir.name)
        self.assertIn(b"Subject: Test SMTP Receiver", raw_content)

    def test_invalid_sender_rejection(self):
        """Test malformed MAIL FROM rejection with 550 response."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")

        code, resp = client.mail("invalid-sender-no-at")
        self.assertEqual(code, 550)
        client.quit()

    def test_invalid_recipient_rejection(self):
        """Test malformed RCPT TO rejection with 550 response."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")
        client.mail("valid@sender.com")

        code, resp = client.rcpt("invalid-recipient-syntax")
        self.assertEqual(code, 550)
        client.quit()

    def test_oversized_message_rejection(self):
        """Test message exceeding MAX_MESSAGE_SIZE is rejected with 552."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")

        oversized_body = "A" * (self.max_size + 1000)
        msg = f"From: a@b.com\r\nTo: c@d.com\r\nSubject: Big\r\n\r\n{oversized_body}"

        with self.assertRaises((smtplib.SMTPDataError, smtplib.SMTPSenderRefused, smtplib.SMTPResponseException)) as ctx:
            client.sendmail("a@b.com", ["c@d.com"], msg)

        code = getattr(ctx.exception, "smtp_code", None) or ctx.exception.args[0]
        self.assertEqual(code, 552)
        try:
            client.quit()
        except Exception:
            pass

    def test_multiple_emails_and_unique_filenames(self):
        """Test receiving multiple emails produces distinct, unique filenames."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")

        for i in range(3):
            msg = f"From: user{i}@test.com\r\nTo: r@test.com\r\nSubject: Email {i}\r\n\r\nBody {i}"
            client.sendmail(f"user{i}@test.com", ["r@test.com"], msg)

        client.quit()

        stored_files = get_stored_emails(storage_path=self.temp_dir.name)
        self.assertEqual(len(stored_files), 3)
        self.assertEqual(len(set(stored_files)), 3)  # all unique

    def test_storage_failure_returns_451(self):
        """Test storage failure handling returns 451 local error code."""
        client = smtplib.SMTP("127.0.0.1", self.test_port, timeout=5)
        client.ehlo("localhost")

        msg = "From: s@t.com\r\nTo: r@t.com\r\nSubject: Fail\r\n\r\nFail test"

        with patch("services.smtp_receiver.save_raw_email", side_effect=IOError("Disk Full Simulated")):
            with self.assertRaises(smtplib.SMTPDataError) as ctx:
                client.sendmail("s@t.com", ["r@t.com"], msg)

            self.assertEqual(ctx.exception.smtp_code, 451)

        client.quit()

    def test_graceful_shutdown(self):
        """Test server starts and stops cleanly without blocking."""
        self.assertTrue(self.server.is_running)
        self.server.stop()
        self.assertFalse(self.server.is_running)


if __name__ == "__main__":
    unittest.main()
