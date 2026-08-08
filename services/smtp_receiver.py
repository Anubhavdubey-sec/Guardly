"""
Guardly SMTP Receiver Service
Enterprise SMTP Gateway Receiver Foundation for Guardly DFIR Platform.
Receives raw RFC 5322 messages via SMTP, enforces security limits,
and stores complete raw .eml messages to disk.
"""

import os
import re
import logging
from typing import Optional, List
from email.utils import parseaddr

from aiosmtpd.controller import Controller
from mail.storage import save_raw_email

logger = logging.getLogger("guardly.services.smtp_receiver")

# Basic RFC 5321/5322 Email Address Regex for SMTP validation
EMAIL_ADDRESS_PATTERN = re.compile(
    r"^(?:<)?([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)(?:>)?$"
)


def is_valid_email_address(addr: str, allow_empty_bounce: bool = True) -> bool:
    """
    Validates SMTP envelope email address syntax.
    Allows empty bounce address '<>' for MAIL FROM if allow_empty_bounce is True.
    """
    if not addr:
        return False

    cleaned = addr.strip()
    if allow_empty_bounce and cleaned in ("<>", ""):
        return True

    # Strip brackets if present
    if cleaned.startswith("<") and cleaned.endswith(">"):
        cleaned = cleaned[1:-1]

    if not cleaned or len(cleaned) > 254:
        return False

    _, parsed_email = parseaddr(cleaned)
    target = parsed_email or cleaned

    return bool(EMAIL_ADDRESS_PATTERN.match(target))


class GuardlySMTPHandler:
    """
    aiosmtpd Handler implementation enforcing security checks, address validation,
    message size limits, and disk storage delegation.
    """

    def __init__(self, max_message_size: int = 10 * 1024 * 1024, storage_path: Optional[str] = None):
        self.max_message_size = max_message_size
        self.storage_path = storage_path

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        """
        Processes MAIL FROM command. Validates sender address syntax.
        """
        logger.debug(f"SMTP MAIL FROM received from client {session.peer}")
        if not is_valid_email_address(address, allow_empty_bounce=True):
            logger.warning(f"Rejected malformed MAIL FROM address from {session.peer}: {address}")
            return "550 5.1.7 Invalid sender address syntax"

        envelope.mail_from = address
        return "250 2.1.0 Sender OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """
        Processes RCPT TO command. Validates recipient address syntax.
        """
        logger.debug(f"SMTP RCPT TO received from client {session.peer}")
        if not is_valid_email_address(address, allow_empty_bounce=False):
            logger.warning(f"Rejected malformed RCPT TO address from {session.peer}: {address}")
            return "550 5.1.1 Invalid recipient address syntax"

        envelope.rcpt_tos.append(address)
        return "250 2.1.5 Recipient OK"

    async def handle_DATA(self, server, session, envelope):
        """
        Processes DATA command. Enforces max size limit and stores raw .eml message.
        """
        content_bytes = envelope.content
        msg_size = len(content_bytes) if content_bytes else 0

        logger.info(
            f"SMTP DATA received: {msg_size} bytes from peer {session.peer} "
            f"(Sender: {envelope.mail_from}, Recipients: {len(envelope.rcpt_tos)})"
        )

        # Enforce Maximum Message Size Limit
        if msg_size > self.max_message_size:
            logger.warning(
                f"Rejected oversized SMTP message: {msg_size} bytes exceeds limit of {self.max_message_size} bytes"
            )
            return "552 5.3.4 Message size exceeds fixed limit"

        if not content_bytes:
            logger.warning("Rejected empty DATA payload")
            return "550 5.6.0 Empty message payload"

        # Delegate raw message storage to mail/storage.py
        try:
            saved_path = save_raw_email(content_bytes, storage_path=self.storage_path)
            logger.info(f"Accepted and stored raw email message at: {saved_path}")
            return "250 2.0.0 Message accepted for delivery"
        except Exception as exc:
            logger.error(f"Local storage failure handling SMTP DATA: {str(exc)}")
            return "451 4.3.0 Local error in processing"


class GuardlySMTPServer:
    """
    Independent SMTP Server Controller for Guardly.
    Runs asynchronously in a background thread without blocking Flask.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2525,
        max_message_size: int = 10 * 1024 * 1024,
        storage_path: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.max_message_size = max_message_size
        self.storage_path = storage_path
        self.handler = GuardlySMTPHandler(
            max_message_size=self.max_message_size,
            storage_path=self.storage_path
        )
        self.controller = Controller(
            self.handler,
            hostname=self.host,
            port=self.port,
            data_size_limit=self.max_message_size,
        )

    def start(self):
        """
        Starts the SMTP receiver thread non-blockingly.
        """
        logger.info(f"Starting Guardly SMTP Receiver on {self.host}:{self.port}...")
        self.controller.start()
        logger.info(f"Guardly SMTP Receiver running on {self.host}:{self.port}")

    def stop(self):
        """
        Cleanly stops the SMTP receiver thread.
        """
        logger.info("Stopping Guardly SMTP Receiver...")
        try:
            self.controller.stop()
            logger.info("Guardly SMTP Receiver stopped cleanly.")
        except Exception as exc:
            logger.error(f"Error shutting down SMTP Receiver: {str(exc)}")

    @property
    def is_running(self) -> bool:
        """
        Returns True if the SMTP receiver server thread is active.
        """
        t = getattr(self.controller, "_thread", None) or getattr(self.controller, "thread", None)
        return t is not None and t.is_alive()

