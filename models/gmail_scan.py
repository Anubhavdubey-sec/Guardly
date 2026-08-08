"""
Gmail Workspace Post-Delivery Scan Database Models for Guardly (Phase 5).
Tracks post-delivery inbox scans, detected threat scores, and automated Gmail API actions (TRASHED / QUARANTINED).
"""

from datetime import datetime, timezone
from models.user import db


class GmailPostDeliveryScan(db.Model):
    """
    Stores historical scan results and automated remediation actions taken via Gmail API.
    """
    __tablename__ = "gmail_post_delivery_scans"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    user_email = db.Column(db.String(255), nullable=False, index=True)
    gmail_message_id = db.Column(db.String(128), nullable=False, index=True)
    thread_id = db.Column(db.String(128), nullable=True)
    sender = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(512), nullable=True)
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(32), nullable=False)
    action_taken = db.Column(db.String(64), nullable=False)  # TRASHED, LABELED_QUARANTINE, ALLOWED
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "user_email": self.user_email,
            "gmail_message_id": self.gmail_message_id,
            "thread_id": self.thread_id,
            "sender": self.sender,
            "subject": self.subject,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "action_taken": self.action_taken,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }
