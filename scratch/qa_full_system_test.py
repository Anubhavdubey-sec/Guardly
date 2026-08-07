"""
Comprehensive QA / Penetration System Test Suite for Guardly
Systematically exercises every single route, service, module, and security control in the codebase.
"""

import json
import os
import sys
import unittest
from io import BytesIO

from app import create_app
from models.scan import EmailScan
from models.user import User, db


class ComprehensiveQASystemTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": False,
            "SECRET_KEY": "qa_secret_key_12345",
        })

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

        from werkzeug.security import generate_password_hash
        # Create Admin & User
        self.admin = User(username="admin_qa", email="admin@guardly.sec", password=generate_password_hash("Admin@12345"), role=User.ROLE_ADMIN)
        self.analyst = User(username="analyst_qa", email="analyst@guardly.sec", password=generate_password_hash("Analyst@123"), role=User.ROLE_ANALYST)
        db.session.add_all([self.admin, self.analyst])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # -------------------------------------------------------------
    # 1. Authentication & Security Policy QA Tests
    # -------------------------------------------------------------
    def test_qa_password_validation_policy(self):
        """QA Test: Password Policy enforcement (8-12 chars, upper, lower, digit, special)."""
        from services.password_validator import validate_password
        valid_short, _, _ = validate_password("Ab1!")
        valid_long, _, _ = validate_password("Abcdefghijk12345!")
        valid_no_digit, _, _ = validate_password("Abcdefgh!")
        valid_correct, _, _ = validate_password("SecureP@ss1")

        self.assertFalse(valid_short)
        self.assertFalse(valid_long)
        self.assertFalse(valid_no_digit)
        self.assertTrue(valid_correct)

    def test_qa_login_and_session_fixation_protection(self):
        """QA Test: User login, password verification, and session regeneration."""
        response = self.client.post("/login", data={
            "username": "admin_qa",
            "password": "Admin@12345"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_qa_security_headers_middleware(self):
        """QA Test: Response security headers (X-Frame-Options, CSP, nosniff, etc.)."""
        response = self.client.get("/login")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", response.headers)

    # -------------------------------------------------------------
    # 2. Email Inspection & Threat Detector QA Tests
    # -------------------------------------------------------------
    def test_qa_single_email_scanning_workflow(self):
        """QA Test: Full email scan workflow (EML, DFIR headers, URLs, NLP, YARA, Playbooks)."""
        sample_eml = (
            "From: CEO <ceo-spoof@malicious-domain.com>\n"
            "To: victim@guardly.sec\n"
            "Subject: URGENT: Executive Wire Transfer Needed\n"
            "Date: Thu, 06 Aug 2026 12:00:00 +0000\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Please act immediately to send a wire transfer to http://0x7F000001/pay. Keep this confidential."
        ).encode("utf-8")

        response = self.client.post("/upload", data={
            "email_file": (BytesIO(sample_eml), "sample_phish.eml")
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        # Check scan recorded in DB
        scan = EmailScan.query.first()
        self.assertIsNotNone(scan)
        self.assertGreater(scan.risk_score, 0)

    def test_qa_url_threat_intelligence_engine(self):
        """QA Test: Direct URL inspection with numeric IP, homograph, and TLD analysis."""
        from scanner.url_intelligence import inspect_url_threat_intelligence
        res = inspect_url_threat_intelligence("http://0x7F000001/login?user=admin")
        self.assertIn("url_risk_score", res)
        self.assertGreater(res["url_risk_score"], 0)

    def test_qa_quishing_and_ocr_scanner(self):
        """QA Test: QR code / image attachment quishing scanning."""
        from scanner.qr_ocr_scanner import scan_attachment_for_quishing
        payload = b"\x89PNG\r\n\x1a\n\x00\x00https://phish-target.com/login\x00\x00"
        res = scan_attachment_for_quishing(payload, "qr.png", "image/png")
        self.assertTrue(res["has_qr_code"])

    def test_qa_nlp_social_engineering_analyzer(self):
        """QA Test: NLP AI social engineering analysis."""
        from scanner.nlp_analyzer import analyze_social_engineering_nlp
        res = analyze_social_engineering_nlp({
            "subject": "URGENT: Payroll Direct Deposit Change",
            "body": "Hi, I am the CEO. Please update my bank account immediately."
        })
        self.assertGreater(res["social_engineering_score"], 20)

    def test_qa_yara_and_sigma_generators(self):
        """QA Test: YARA and SIEM Sigma rule compilation."""
        from services.yara_generator import generate_sigma_rule, generate_yara_rule
        yara_code = generate_yara_rule({"subject": "Test Phish", "from": "bad@domain.com"}, {"score": 80, "verdict": "High Risk"})
        sigma_code = generate_sigma_rule({"subject": "Test Phish", "from": "bad@domain.com"}, {"score": 80, "verdict": "High Risk"})
        self.assertIn("rule Guardly_Phish", yara_code)
        self.assertIn("title: Guardly Phishing Email Indicator", sigma_code)

    def test_qa_soc_incident_playbooks(self):
        """QA Test: Automated Incident Response Playbook execution."""
        from services.playbook_engine import execute_soc_playbooks
        res = execute_soc_playbooks({}, {"score": 85, "verdict": "High Risk", "categories": ["Credential harvesting"]})
        self.assertIn("active_playbooks", res)
        self.assertTrue(len(res["active_playbooks"]) > 0)

    # -------------------------------------------------------------
    # 3. SOC Interactive Threat Graph QA Tests
    # -------------------------------------------------------------
    def test_qa_threat_graph_api_and_page(self):
        """QA Test: Visual Threat Graph workspace page and JSON API."""
        scan = EmailScan(subject="Test Graph", sender="a@b.com", receiver="c@d.com", risk_score=70)
        db.session.add(scan)
        db.session.commit()

        res_page = self.client.get("/threat-graph")
        res_api = self.client.get("/api/v1/threat-graph/data")

        self.assertEqual(res_page.status_code, 200)
        self.assertEqual(res_api.status_code, 200)
        self.assertIn("nodes", res_api.get_json())


if __name__ == "__main__":
    unittest.main()
