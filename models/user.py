from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    ROLE_ADMIN = "admin"
    ROLE_ANALYST = "analyst"
    ROLE_USER = "user"
    ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_USER}

    AUTH_PASSWORD = "password"
    AUTH_GOOGLE = "google"
    AUTH_PHONE = "phone"
    AUTH_PROVIDERS = {AUTH_PASSWORD, AUTH_GOOGLE, AUTH_PHONE}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone_number = db.Column(db.String(32), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), default=ROLE_USER, nullable=False)
    tenant_id = db.Column(db.String(64), default="default", nullable=False, index=True)
    auth_provider = db.Column(db.String(32), default=AUTH_PASSWORD, nullable=False)
    firebase_uid = db.Column(db.String(128), unique=True, nullable=True, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    scans = db.relationship("EmailScan", backref="user", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship("SystemLog", backref="actor", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "phone_number": self.phone_number,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "auth_provider": self.auth_provider,
            "firebase_uid": self.firebase_uid,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
