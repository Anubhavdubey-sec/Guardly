"""Tenant-scoped investigation cases for analyst triage and collaboration."""

import json
from datetime import datetime, timezone

from models.user import db


class InvestigationCase(db.Model):
    __tablename__ = "investigation_cases"

    STATUSES = ("Open", "Investigating", "Contained", "Closed")
    VERDICT_OVERRIDES = ("", "Low Risk", "Medium Risk", "High Risk", "False Positive")

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(64), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="Open", index=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    tags = db.Column(db.Text, nullable=False, default="[]")
    analyst_notes = db.Column(db.Text, nullable=False, default="")
    verdict_override = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    scan_links = db.relationship(
        "CaseScan", back_populates="case", cascade="all, delete-orphan", order_by="CaseScan.created_at"
    )
    indicators = db.relationship(
        "CaseIndicator", back_populates="case", cascade="all, delete-orphan", order_by="CaseIndicator.created_at"
    )
    notes = db.relationship(
        "CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.created_at"
    )

    @property
    def tags_list(self):
        try:
            return json.loads(self.tags) if self.tags else []
        except (TypeError, ValueError):
            return []

    @property
    def effective_verdict(self):
        return self.verdict_override or "Not overridden"


class CaseScan(db.Model):
    __tablename__ = "case_scans"
    __table_args__ = (db.UniqueConstraint("case_id", "scan_id", name="uq_case_scans_case_scan"),)

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("email_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    added_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    case = db.relationship("InvestigationCase", back_populates="scan_links")
    scan = db.relationship("EmailScan", back_populates="case_links")
    added_by = db.relationship("User", foreign_keys=[added_by_id])


class CaseIndicator(db.Model):
    __tablename__ = "case_indicators"

    INDICATOR_TYPES = ("domain", "ip_address", "url", "hash", "other")

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    source_scan_id = db.Column(db.Integer, nullable=True, index=True)
    indicator_type = db.Column(db.String(32), nullable=False)
    value = db.Column(db.String(512), nullable=False)
    source = db.Column(db.String(32), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    case = db.relationship("InvestigationCase", back_populates="indicators")


class CaseNote(db.Model):
    """An append-only analyst note retained as part of a case audit trail."""

    __tablename__ = "case_notes"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    case = db.relationship("InvestigationCase", back_populates="notes")
    author = db.relationship("User", foreign_keys=[author_id])
