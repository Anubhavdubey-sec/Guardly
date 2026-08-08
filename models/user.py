from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    ROLE_ADMIN = "admin"
    ROLE_ANALYST = "analyst"
    ROLE_USER = "user"
    ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_USER}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=ROLE_USER, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scans = db.relationship("EmailScan", backref="user", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship("SystemLog", backref="actor", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
