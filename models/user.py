from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    ROLE_ADMIN = "admin"
    ROLE_USER = "user"
    ROLE_ANALYST = "analyst"  # Maintained for legacy backwards-compatibility
    ROLES = {ROLE_ADMIN, ROLE_USER}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=ROLE_USER, nullable=False)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    mfa_secret = db.Column(db.String(64), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_recovery_codes = db.Column(db.Text, nullable=True)
    # Accounts are retained after offboarding so cases and audit events keep
    # their original actor instead of losing referential integrity.
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scans = db.relationship("EmailScan", backref="user", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship("SystemLog", backref="actor", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "mfa_enabled": self.mfa_enabled,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
