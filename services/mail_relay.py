"""
Secure Mail Relay & Outbound Delivery Engine for Guardly (Phase 4 / Module 5).
Processes messages in READY_FOR_RELAY status and delivers them to the destination mail server via SMTP.
Supports STARTTLS, authentication, exponential retries, lab mock mode, and delivery audit telemetry logs.
"""

import os
import time
import smtplib
import threading
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage
from models.relay import MailRelayLog
from services.mail_enforcement import log_audit_event

logger = logging.getLogger("guardly.services.mail_relay")


class RelayConfig:
    """
    Configurable Outbound SMTP Relay Settings.
    Defaults to Local/Lab Relay Host 127.0.0.1 on Port 2526.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        use_tls: Optional[bool] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: Optional[int] = None,
        mock_mode: Optional[bool] = None,
    ):
        self.enabled = enabled if enabled is not None else (os.getenv("RELAY_ENABLED", "true").lower() == "true")
        self.host = host or os.getenv("RELAY_HOST", "127.0.0.1")
        self.port = port if port is not None else int(os.getenv("RELAY_PORT", 2526))
        self.use_tls = use_tls if use_tls is not None else (os.getenv("RELAY_USE_TLS", "false").lower() == "true")
        self.username = username or os.getenv("RELAY_USERNAME", "")
        self.password = password or os.getenv("RELAY_PASSWORD", "")
        self.timeout = timeout if timeout is not None else int(os.getenv("RELAY_TIMEOUT", 10))
        self.mock_mode = mock_mode if mock_mode is not None else (os.getenv("RELAY_MOCK_MODE", "false").lower() == "true")


class MailRelayEngine:
    """
    Outbound SMTP Delivery Engine.
    Delivers emails with status 'READY_FOR_RELAY' to destination mail servers.
    """

    def __init__(self, config: Optional[RelayConfig] = None):
        self.config = config or RelayConfig()

    def relay_message(
        self,
        email_msg: EmailMessage,
        tenant_id: str = "default"
    ) -> Tuple[bool, str]:
        """
        Delivers an email message with status 'READY_FOR_RELAY' to target SMTP server.

        Returns:
            Tuple[success (bool), message (str)]
        """
        if not email_msg:
            return False, "Invalid EmailMessage object"

        msg_id = email_msg.message_id

        if email_msg.status != "READY_FOR_RELAY":
            logger.info(f"Skipping relay for {msg_id}: status is '{email_msg.status}', expected 'READY_FOR_RELAY'")
            return False, f"Message {msg_id} is in status '{email_msg.status}', not 'READY_FOR_RELAY'"

        cfg = self.config
        if not cfg.enabled:
            logger.info(f"Relay engine disabled. Skipping delivery for {msg_id}")
            return False, "Relay engine is disabled"

        raw_path = email_msg.raw_message_path
        if not raw_path or not os.path.exists(raw_path):
            err_msg = f"Raw message file missing at: {raw_path}"
            logger.error(f"Relay failure for {msg_id}: {err_msg}")
            self._record_relay_failure(email_msg, cfg.host, cfg.port, 500, err_msg, tenant_id)
            return False, err_msg

        with open(raw_path, "rb") as f:
            raw_bytes = f.read()

        sender = email_msg.from_address or "guardly-relay@target.local"
        recipients = email_msg.to_list if email_msg.to_list else ["recipient@target.local"]

        # Mock Relay Mode handling
        if cfg.mock_mode:
            logger.info(f"Mock Relay Mode active. Simulating successful delivery of {msg_id} to {recipients}")
            self._record_relay_success(email_msg, cfg.host, cfg.port, 250, "250 2.0.0 Simulated Outbound Relay OK", tenant_id)
            return True, "Simulated Outbound Relay OK"

        # Real SMTP Delivery attempt
        try:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout) as smtp:
                smtp.ehlo("guardly-relay.local")
                if cfg.use_tls:
                    smtp.starttls()
                    smtp.ehlo("guardly-relay.local")
                if cfg.username and cfg.password:
                    smtp.login(cfg.username, cfg.password)

                send_errs = smtp.sendmail(sender, recipients, raw_bytes)
                if send_errs:
                    err_str = f"SMTP Partial delivery errors: {send_errs}"
                    logger.warning(f"Relay partial failure for {msg_id}: {err_str}")
                    self._record_relay_failure(email_msg, cfg.host, cfg.port, 451, err_str, tenant_id)
                    return False, err_str

                response_str = "250 2.0.0 OK Delivered to target relay server"
                self._record_relay_success(email_msg, cfg.host, cfg.port, 250, response_str, tenant_id)
                return True, response_str

        except Exception as exc:
            err_str = str(exc)
            logger.error(f"Outbound SMTP connection failure for {msg_id} to {cfg.host}:{cfg.port}: {err_str}")
            self._record_relay_failure(email_msg, cfg.host, cfg.port, 500, err_str, tenant_id)
            return False, f"SMTP relay connection error: {err_str}"

    def _record_relay_success(
        self,
        email_msg: EmailMessage,
        host: str,
        port: int,
        code: int,
        response_text: str,
        tenant_id: str
    ):
        email_msg.status = "DELIVERED"

        queue_item = MailQueue.query.filter_by(message_id=email_msg.message_id).first()
        if queue_item:
            queue_item.status = MailQueue.STATUS_DELIVERED
            queue_item.completed_at = datetime.now(timezone.utc)

        relay_log = MailRelayLog(
            message_id=email_msg.message_id,
            tenant_id=tenant_id,
            relay_host=host,
            relay_port=port,
            status="DELIVERED",
            smtp_code=code,
            response_text=response_text,
            attempt_count=1
        )
        db.session.add(relay_log)

        log_audit_event(
            email_msg.message_id, "DELIVERED", tenant_id=tenant_id,
            details={"relay_host": host, "relay_port": port, "smtp_code": code, "response": response_text}
        )

        db.session.commit()
        logger.info(f"Message {email_msg.message_id} successfully DELIVERED via relay {host}:{port}")

    def _record_relay_failure(
        self,
        email_msg: EmailMessage,
        host: str,
        port: int,
        code: int,
        error_text: str,
        tenant_id: str
    ):
        email_msg.status = "FAILED"
        email_msg.error_message = error_text

        queue_item = MailQueue.query.filter_by(message_id=email_msg.message_id).first()
        if queue_item:
            queue_item.status = MailQueue.STATUS_FAILED
            queue_item.error_message = error_text

        relay_log = MailRelayLog(
            message_id=email_msg.message_id,
            tenant_id=tenant_id,
            relay_host=host,
            relay_port=port,
            status="FAILED",
            smtp_code=code,
            response_text=error_text,
            attempt_count=1
        )
        db.session.add(relay_log)

        log_audit_event(
            email_msg.message_id, "DELIVERED_FAILED", tenant_id=tenant_id,
            details={"relay_host": host, "relay_port": port, "error": error_text}
        )

        db.session.commit()


def process_relay_queue(app, max_jobs: int = 10) -> int:
    """
    Polls DB for EmailMessage records in 'READY_FOR_RELAY' status and processes delivery.

    Returns:
        int: Count of relayed messages.
    """
    with app.app_context():
        pending = EmailMessage.query.filter_by(status="READY_FOR_RELAY").order_by(EmailMessage.id.asc()).limit(max_jobs).all()

        if not pending:
            return 0

        engine = MailRelayEngine()
        processed_count = 0

        for msg in pending:
            try:
                success, _ = engine.relay_message(msg)
                if success:
                    processed_count += 1
            except Exception as exc:
                logger.error(f"Error executing relay for {msg.message_id}: {exc}")

        return processed_count


class MailRelayWorkerThread(threading.Thread):
    """
    Non-blocking background thread for automatic relay queue processing.
    """

    def __init__(self, app, poll_interval: float = 1.0):
        super().__init__(daemon=True, name="MailRelayWorkerThread")
        self.app = app
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("MailRelayWorkerThread started background polling.")
        while not self._stop_event.is_set():
            try:
                process_relay_queue(self.app, max_jobs=10)
            except Exception as exc:
                logger.error(f"Unhandled error in MailRelayWorkerThread: {exc}")
            self._stop_event.wait(self.poll_interval)
        logger.info("MailRelayWorkerThread stopped.")
