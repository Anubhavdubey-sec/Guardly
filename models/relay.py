"""
Mail Relay Database Models for Guardly (Phase 4 / Module 5).
Tracks outbound SMTP relay delivery attempts, response codes, and telemetry logs.
"""

from datetime import datetime, timezone
from models.user import db


class MailRelayLog(db.Model):
    """
    Stores outbound SMTP delivery logs and network response codes for relayed messages.
    """
    __tablename__ = "mail_relay_logs"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), db.ForeignKey("email_messages.message_id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    relay_host = db.Column(db.String(255), nullable=False)
    relay_port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(32), nullable=False)  # DELIVERED, FAILED
    smtp_code = db.Column(db.Integer, nullable=True)
    response_text = db.Column(db.Text, nullable=True)
    attempt_count = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "message_id": self.message_id,
            "tenant_id": self.tenant_id,
            "relay_host": self.relay_host,
            "relay_port": self.relay_port,
            "status": self.status,
            "smtp_code": self.smtp_code,
            "response_text": self.response_text,
            "attempt_count": self.attempt_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
