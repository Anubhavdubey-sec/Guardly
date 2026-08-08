"""
Email Message & Attachment Database Models for Guardly.
Stores structured email metadata, extracted URLs, body text, and safe attachment references.
"""

import json
from datetime import datetime, timezone
from models.user import db


class EmailMessage(db.Model):
    __tablename__ = "email_messages"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), unique=True, nullable=False, index=True)
    from_address = db.Column(db.String(255), nullable=True, index=True)
    to_addresses = db.Column(db.Text, nullable=True)  # JSON array
    cc_addresses = db.Column(db.Text, nullable=True)  # JSON array
    bcc_addresses = db.Column(db.Text, nullable=True)  # JSON array
    reply_to = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(512), nullable=True)
    email_date = db.Column(db.String(255), nullable=True)
    return_path = db.Column(db.String(255), nullable=True)
    headers_json = db.Column(db.Text, nullable=True)  # JSON dict
    text_body = db.Column(db.Text, nullable=True)
    html_body = db.Column(db.Text, nullable=True)
    urls_json = db.Column(db.Text, nullable=True)  # JSON array
    attachments_json = db.Column(db.Text, nullable=True)  # JSON array
    raw_message_path = db.Column(db.String(512), nullable=True)
    received_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    parsed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="READY_FOR_ANALYSIS", nullable=False)
    error_message = db.Column(db.Text, nullable=True)

    # Threat Analysis Engine Fields (Module 3)
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    severity = db.Column(db.String(32), default="LOW", nullable=False)
    recommendation = db.Column(db.String(32), default="ALLOW", nullable=False)
    findings_json = db.Column(db.Text, nullable=True)  # JSON array of findings
    analysis_json = db.Column(db.Text, nullable=True)  # Complete Analysis Result JSON

    attachments = db.relationship("EmailAttachment", backref="email_message", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "message_id": self.message_id,
            "from": self.from_address,
            "to": self.to_list,
            "cc": self.cc_list,
            "bcc": self.bcc_list,
            "reply_to": self.reply_to,
            "subject": self.subject,
            "date": self.email_date,
            "return_path": self.return_path,
            "headers": self.headers_data,
            "text_body": self.text_body or "",
            "html_body": self.html_body or "",
            "urls": self.urls_list,
            "attachments": self.attachments_list,
            "raw_message_path": self.raw_message_path,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "parsed_at": self.parsed_at.isoformat() if self.parsed_at else None,
            "status": self.status,
        }

    @property
    def to_list(self):
        try:
            return json.loads(self.to_addresses) if self.to_addresses else []
        except Exception:
            return []

    @property
    def cc_list(self):
        try:
            return json.loads(self.cc_addresses) if self.cc_addresses else []
        except Exception:
            return []

    @property
    def bcc_list(self):
        try:
            return json.loads(self.bcc_addresses) if self.bcc_addresses else []
        except Exception:
            return []

    @property
    def urls_list(self):
        try:
            return json.loads(self.urls_json) if self.urls_json else []
        except Exception:
            return []

    @property
    def attachments_list(self):
        try:
            return json.loads(self.attachments_json) if self.attachments_json else []
        except Exception:
            return []

    @property
    def headers_data(self):
        try:
            return json.loads(self.headers_json) if self.headers_json else {}
        except Exception:
            return {}


class EmailAttachment(db.Model):
    __tablename__ = "email_attachments"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), db.ForeignKey("email_messages.message_id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    safe_storage_path = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "filename": self.filename,
            "original_filename": self.original_filename,
            "mime_type": self.mime_type,
            "size": self.size_bytes,
            "sha256": self.sha256_hash,
            "storage_path": self.safe_storage_path,
        }
