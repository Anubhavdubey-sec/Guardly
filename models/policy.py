"""
Mail Policy & Enforcement Database Models for Guardly (Phase 4 / Module 4).
Stores policy enforcement decisions, isolated quarantine vault records, and auditable telemetry.
"""

import json
from datetime import datetime, timezone
from models.user import db


class MailDecision(db.Model):
    """
    Stores historical enforcement decisions made by PolicyEngine.
    """
    __tablename__ = "mail_decisions"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), db.ForeignKey("email_messages.message_id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    decision = db.Column(db.String(32), nullable=False)  # ALLOW, REVIEW, QUARANTINE, REJECT
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(32), nullable=False)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "message_id": self.message_id,
            "tenant_id": self.tenant_id,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class MailQuarantine(db.Model):
    """
    Tracks quarantined email messages stored in isolated vault storage (quarantine/).
    """
    __tablename__ = "mail_quarantine"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), db.ForeignKey("email_messages.message_id"), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    quarantine_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # QUAR-YYYYMMDD-xxxxxxxx
    original_sender = db.Column(db.String(255), nullable=True)
    recipient = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(512), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(32), nullable=False)
    raw_message_path = db.Column(db.String(512), nullable=True)
    quarantine_file_path = db.Column(db.String(512), nullable=False)
    status = db.Column(db.String(32), default="QUARANTINED", nullable=False, index=True)  # QUARANTINED, RELEASED, PURGED
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    released_at = db.Column(db.DateTime, nullable=True)
    released_by = db.Column(db.String(128), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "message_id": self.message_id,
            "tenant_id": self.tenant_id,
            "quarantine_id": self.quarantine_id,
            "original_sender": self.original_sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "status": self.status,
            "quarantined_at": self.created_at.isoformat() if self.created_at else None,
            "released_at": self.released_at.isoformat() if self.released_at else None,
            "released_by": self.released_by,
        }


class MailAuditLog(db.Model):
    """
    Auditable security telemetry for all mail enforcement & release actions.
    """
    __tablename__ = "mail_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), nullable=False, index=True)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False)  # ALLOW, REVIEW, QUARANTINE, REJECT, RELEASE, FAILED
    actor_id = db.Column(db.String(128), default="system", nullable=False)
    risk_score = db.Column(db.Integer, nullable=True)
    severity = db.Column(db.String(32), nullable=True)
    details_json = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    def to_dict(self):
        details = {}
        if self.details_json:
            try:
                details = json.loads(self.details_json)
            except Exception:
                details = {}

        return {
            "id": self.id,
            "message_id": self.message_id,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "actor_id": self.actor_id,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "details": details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
