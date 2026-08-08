"""
Gmail Workspace Post-Delivery Threat Scanner for Guardly (Phase 5).
Connects to Google Workspace Gmail REST API (or Service Account with Domain-Wide Delegation),
fetches incoming unread inbox emails, evaluates them through Guardly Threat Analysis Engine,
and automatically trashes or quarantines detected post-delivery phishing threats.
"""

import os
import base64
import logging
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models.user import db
from models.policy import MailQuarantine, MailAuditLog
from models.gmail_scan import GmailPostDeliveryScan
from services.email_parser import parse_raw_email
from services.threat_analysis import ThreatAnalysisEngine
from services.mail_enforcement import log_audit_event

logger = logging.getLogger("guardly.services.gmail_scanner")


class GmailScannerConfig:
    """
    Configuration for Gmail Post-Delivery Scanner API & Remediation settings.
    """

    def __init__(
        self,
        service_account_file: Optional[str] = None,
        delegated_user: Optional[str] = None,
        mock_mode: Optional[bool] = None,
        remediation_action: Optional[str] = None,  # TRASH, QUARANTINE_LABEL
        risk_threshold: Optional[int] = None,       # Default: 65
    ):
        self.service_account_file = service_account_file or os.getenv("GMAIL_SERVICE_ACCOUNT_FILE", "")
        self.delegated_user = delegated_user or os.getenv("GMAIL_DELEGATED_USER", "admin@company.com")
        self.mock_mode = mock_mode if mock_mode is not None else (os.getenv("GMAIL_API_MOCK_MODE", "true").lower() == "true")
        self.remediation_action = remediation_action or os.getenv("GMAIL_REMEDIATION_ACTION", "TRASH").upper()
        self.risk_threshold = risk_threshold if risk_threshold is not None else int(os.getenv("GMAIL_RISK_THRESHOLD", 65))


class GmailPostDeliveryScanner:
    """
    Automated Gmail Inbox Threat Scanner & Remediation Engine.
    """

    def __init__(self, config: Optional[GmailScannerConfig] = None):
        self.config = config or GmailScannerConfig()
        self.threat_engine = ThreatAnalysisEngine()

    def list_user_messages(self, user_email: str, max_results: int = 10, query: str = "in:inbox") -> List[Dict[str, str]]:
        """
        Lists recent messages in specified Gmail user inbox.
        """
        cfg = self.config
        if cfg.mock_mode:
            logger.info(f"[Mock Gmail API] Listing {max_results} messages for {user_email}")
            return [
                {"id": f"mock_gmail_msg_{i}", "threadId": f"thread_{i}"} for i in range(1, min(max_results + 1, 4))
            ]

        # Real Gmail REST API call via google-api-python-client if installed
        try:
            from googleapiclient.discovery import build
            from google.oauth2 import service_account

            scopes = ["https://mail.google.com/"]
            creds = service_account.Credentials.from_service_account_file(
                cfg.service_account_file, scopes=scopes, subject=user_email
            )
            service = build("gmail", "v1", credentials=creds)

            res = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
            messages = res.get("messages", [])
            return messages

        except Exception as exc:
            logger.error(f"Failed to list Gmail messages for {user_email}: {exc}")
            return []

    def get_message_raw_bytes(self, user_email: str, message_id: str) -> Optional[bytes]:
        """
        Fetches full RFC 5322 raw email bytes for a given Gmail message ID.
        """
        cfg = self.config
        if cfg.mock_mode:
            # Generate deterministic sample raw RFC bytes for testing
            if "1" in message_id or "clean" in message_id:
                return (
                    f"Subject: Clean Team Update\r\nFrom: boss@company.com\r\nTo: {user_email}\r\n"
                    "Message-ID: <mock_clean_001@company.com>\r\n\r\n"
                    "Hi, here is the clean weekly status report."
                ).encode("utf-8")
            elif "2" in message_id or "review" in message_id:
                return (
                    f"Subject: Action Required: Confirm Details\r\nFrom: verify@external-service.net\r\nTo: {user_email}\r\n"
                    "Reply-To: support@external-verify.com\r\n"
                    "Message-ID: <mock_review_002@company.com>\r\n\r\n"
                    "Please review the pending document details."
                ).encode("utf-8")
            else:
                return (
                    f"Subject: URGENT: Account Password Expired Immediately\r\n"
                    f"From: PayPal Support <login@paypal-security-alert.top>\r\nTo: {user_email}\r\n"
                    "Reply-To: attacker@evil-domain.com\r\n"
                    "Message-ID: <mock_phish_003@company.com>\r\n\r\n"
                    "Your password has expired. Click http://192.168.1.1/login immediately."
                ).encode("utf-8")

        try:
            from googleapiclient.discovery import build
            from google.oauth2 import service_account

            scopes = ["https://mail.google.com/"]
            creds = service_account.Credentials.from_service_account_file(
                cfg.service_account_file, scopes=scopes, subject=user_email
            )
            service = build("gmail", "v1", credentials=creds)

            msg_res = service.users().messages().get(userId="me", id=message_id, format="raw").execute()
            raw_b64 = msg_res.get("raw", "")
            if raw_b64:
                return base64.urlsafe_b64decode(raw_b64.encode("ASCII"))
            return None

        except Exception as exc:
            logger.error(f"Failed to fetch raw bytes for Gmail msg {message_id}: {exc}")
            return None

    def trash_message(self, user_email: str, message_id: str) -> bool:
        """
        Moves detected phishing email directly to Gmail Trash via Gmail API.
        """
        cfg = self.config
        if cfg.mock_mode:
            logger.info(f"[Mock Gmail API] Trashed threat message {message_id} in {user_email}'s inbox.")
            return True

        try:
            from googleapiclient.discovery import build
            from google.oauth2 import service_account

            scopes = ["https://mail.google.com/"]
            creds = service_account.Credentials.from_service_account_file(
                cfg.service_account_file, scopes=scopes, subject=user_email
            )
            service = build("gmail", "v1", credentials=creds)

            service.users().messages().trash(userId="me", id=message_id).execute()
            logger.info(f"Successfully trashed Gmail message {message_id} for user {user_email}")
            return True

        except Exception as exc:
            logger.error(f"Failed to trash Gmail message {message_id} for {user_email}: {exc}")
            return False

    def scan_user_message(self, user_email: str, message_id: str, tenant_id: str = "default") -> Dict[str, Any]:
        """
        Scans a single Gmail inbox message, evaluates risk, and remediates if threat is detected.
        """
        cfg = self.config
        raw_bytes = self.get_message_raw_bytes(user_email, message_id)
        if not raw_bytes:
            return {"status": "ERROR", "message": "Failed to retrieve raw bytes"}

        parsed = parse_raw_email(raw_bytes, fallback_message_id=message_id)
        analysis_res = self.threat_engine.analyze(parsed)
        risk_score = analysis_res["risk_score"]
        severity = analysis_res["severity"]

        action_taken = "ALLOWED"

        if risk_score >= cfg.risk_threshold:
            # Threat detected post-delivery! Execute automated remediation
            if cfg.remediation_action == "TRASH":
                remediated = self.trash_message(user_email, message_id)
                action_taken = "TRASHED" if remediated else "TRASH_FAILED"

            # Log Audit Event
            log_audit_event(
                message_id,
                "POST_DELIVERY_QUARANTINED",
                tenant_id=tenant_id,
                details={
                    "user_email": user_email,
                    "gmail_message_id": message_id,
                    "risk_score": risk_score,
                    "severity": severity,
                    "action_taken": action_taken,
                }
            )

        # Record Scan Telemetry in DB
        scan_record = GmailPostDeliveryScan(
            tenant_id=tenant_id,
            user_email=user_email,
            gmail_message_id=message_id,
            thread_id=parsed.get("subject", ""),
            sender=parsed.get("from", ""),
            subject=parsed.get("subject", ""),
            risk_score=risk_score,
            severity=severity,
            action_taken=action_taken,
            scanned_at=datetime.now(timezone.utc)
        )
        db.session.add(scan_record)
        db.session.commit()

        logger.info(f"Completed Gmail post-delivery scan for {message_id}: Score={risk_score}, Action={action_taken}")
        return {
            "user_email": user_email,
            "gmail_message_id": message_id,
            "risk_score": risk_score,
            "severity": severity,
            "action_taken": action_taken,
            "subject": parsed.get("subject"),
        }

    def scan_user_inbox(self, user_email: str, max_results: int = 10, tenant_id: str = "default") -> List[Dict[str, Any]]:
        """
        Scans all recent messages in a specified user's Gmail inbox.
        """
        messages = self.list_user_messages(user_email, max_results=max_results)
        results = []
        for msg in messages:
            msg_id = msg.get("id")
            if msg_id:
                res = self.scan_user_message(user_email, msg_id, tenant_id=tenant_id)
                results.append(res)
        return results


def process_gmail_inbox_scans(app, user_emails: List[str], max_results: int = 10) -> Dict[str, Any]:
    """
    Executes post-delivery inbox scans across a list of Google Workspace user emails.
    """
    with app.app_context():
        scanner = GmailPostDeliveryScanner()
        total_scanned = 0
        total_remediated = 0
        summary_results = []

        for user_email in user_emails:
            res_list = scanner.scan_user_inbox(user_email, max_results=max_results)
            total_scanned += len(res_list)
            for r in res_list:
                if r.get("action_taken") in ("TRASHED", "LABELED_QUARANTINE"):
                    total_remediated += 1
            summary_results.extend(res_list)

        return {
            "total_scanned": total_scanned,
            "total_remediated": total_remediated,
            "results": summary_results,
        }
