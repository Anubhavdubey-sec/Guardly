import json
from datetime import datetime, timedelta, timezone

from models.user import db


class ThreatIntelligence(db.Model):
    __tablename__ = "threat_intelligence"

    id = db.Column(db.Integer, primary_key=True)
    ioc_value = db.Column(db.String(255), index=True, nullable=False)
    ioc_type = db.Column(db.String(50), nullable=False)  # url, domain, ip, hash, email
    provider = db.Column(db.String(100), default="Consensus Engine")
    confidence = db.Column(db.Float, default=0.0)
    reputation = db.Column(db.String(50), default="Unknown")
    risk_score = db.Column(db.Integer, default=0)
    malicious = db.Column(db.Integer, default=0)
    suspicious = db.Column(db.Integer, default=0)
    harmless = db.Column(db.Integer, default=0)
    unknown = db.Column(db.Integer, default=0)
    country = db.Column(db.String(100), nullable=True)
    asn = db.Column(db.String(100), nullable=True)
    registrar = db.Column(db.String(255), nullable=True)
    whois_data = db.Column(db.Text, default="{}")
    dns_records = db.Column(db.Text, default="{}")
    categories = db.Column(db.Text, default="[]")
    last_analysis = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def whois_json(self):
        try:
            return json.loads(self.whois_data) if self.whois_data else {}
        except Exception:
            return {}

    @property
    def dns_json(self):
        try:
            return json.loads(self.dns_records) if self.dns_records else {}
        except Exception:
            return {}

    @property
    def categories_list(self):
        try:
            return json.loads(self.categories) if self.categories else []
        except Exception:
            return []


class IOCReputation(db.Model):
    __tablename__ = "ioc_reputation"

    id = db.Column(db.Integer, primary_key=True)
    ioc_value = db.Column(db.String(255), index=True, nullable=False)
    provider_name = db.Column(db.String(100), nullable=False)
    verdict = db.Column(db.String(50), default="Unknown")
    score = db.Column(db.Integer, default=0)
    raw_response = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class IOCCache(db.Model):
    __tablename__ = "ioc_cache"

    id = db.Column(db.Integer, primary_key=True)
    cache_key = db.Column(db.String(255), unique=True, index=True, nullable=False)
    data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)

    @property
    def is_expired(self):
        now = datetime.now(timezone.utc)
        exp = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return now > exp
