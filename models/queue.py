"""
Mail Queue Database Model for Guardly.
Tracks received email job states: RECEIVED -> QUEUED -> PROCESSING -> PARSED -> READY_FOR_ANALYSIS -> FAILED
"""

from datetime import datetime, timezone
from models.user import db


class MailQueue(db.Model):
    __tablename__ = "mail_queue"

    STATUS_RECEIVED = "RECEIVED"
    STATUS_QUEUED = "QUEUED"
    STATUS_PROCESSING = "PROCESSING"
    STATUS_PARSED = "PARSED"
    STATUS_READY_FOR_ANALYSIS = "READY_FOR_ANALYSIS"
    STATUS_FAILED = "FAILED"

    VALID_STATUSES = {
        STATUS_RECEIVED,
        STATUS_QUEUED,
        STATUS_PROCESSING,
        STATUS_PARSED,
        STATUS_READY_FOR_ANALYSIS,
        STATUS_FAILED,
    }

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), unique=True, nullable=False, index=True)
    status = db.Column(db.String(32), default=STATUS_QUEUED, nullable=False, index=True)
    received_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    retry_count = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    raw_message_path = db.Column(db.String(512), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "message_id": self.message_id,
            "status": self.status,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "retry_count": self.retry_count,
            "error_message": self.error_message,
            "raw_message_path": self.raw_message_path,
        }
