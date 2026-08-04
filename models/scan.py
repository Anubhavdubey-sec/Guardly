import json
from datetime import datetime, timezone

from models.user import db


class EmailScan(db.Model):
    __tablename__ = "email_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    sender = db.Column(db.String(255), nullable=True)
    receiver = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(255), nullable=True)
    email_date = db.Column(db.String(255), nullable=True)
    reply_to = db.Column(db.String(255), nullable=True)
    email_body = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, default=0)
    verdict = db.Column(db.String(50), default="Low Risk")
    findings = db.Column(db.Text, default="[]")
    urls = db.Column(db.Text, default="[]")
    attachments = db.Column(db.Text, default="[]")
    headers = db.Column(db.Text, default="{}")
    iocs = db.Column(db.Text, default="{}")
    risk_categories = db.Column(db.Text, default="[]")
    reputation_data = db.Column(db.Text, default="{}")
    scan_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def findings_list(self):
        try:
            return json.loads(self.findings) if self.findings else []
        except Exception:
            return []

    @property
    def urls_list(self):
        try:
            return json.loads(self.urls) if self.urls else []
        except Exception:
            return []

    @property
    def attachments_list(self):
        try:
            return json.loads(self.attachments) if self.attachments else []
        except Exception:
            return []

    @property
    def headers_data(self):
        try:
            return json.loads(self.headers) if self.headers else {}
        except Exception:
            return {}

    @property
    def iocs_data(self):
        try:
            return json.loads(self.iocs) if self.iocs else {}
        except Exception:
            return {}

    @property
    def risk_categories_list(self):
        try:
            return json.loads(self.risk_categories) if self.risk_categories else []
        except Exception:
            return []

    @property
    def reputation_data_json(self):
        try:
            return json.loads(self.reputation_data) if self.reputation_data else {}
        except Exception:
            return {}
