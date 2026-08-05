import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from werkzeug.security import generate_password_hash

from app import create_app
from models.scan import EmailScan
from models.user import User, db


class ScannerRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        root = self.temp_directory.name.replace("\\", "/")
        self.app = create_app(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
                "SECRET_KEY": "test-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "UPLOAD_FOLDER": os.path.join(self.temp_directory.name, "uploads"),
                "PUBLIC_LOOKUPS_ENABLED": False,
            }
        )
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            admin = User(
                username="Admin",
                email="admin@example.com",
                password=generate_password_hash("admin-password"),
                role=User.ROLE_ADMIN,
            )
            normal_user = User(
                username="Legacy user",
                email="legacy@example.com",
                password=generate_password_hash("normal-password"),
                role=User.ROLE_USER,
            )
            db.session.add_all([admin, normal_user])
            db.session.commit()
            self.admin_id = admin.id
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            for engine in db.engines.values():
                engine.dispose()
        self.temp_directory.cleanup()

    def _login_as_admin(self):
        with self.client.session_transaction() as session:
            session.clear()
            session["user_id"] = self.admin_id
            session["username"] = "Admin"

    def test_home_page_opens_public_email_scanner(self):
        response = self.client.get("/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Guardly", response.data)
        self.assertIn(b"Choose file", response.data)

    def test_public_upload_creates_anonymous_record_and_hides_staff_actions(self):
        email = b"""From: Newsletter <news@community.example>\nTo: test@example.com\nSubject: July update\n\nThis is a normal newsletter."""
        response = self.client.post(
            "/upload",
            data={"email_file": (io.BytesIO(email), "newsletter.eml")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Email threat report", response.data)
        self.assertNotIn(b"Download PDF", response.data)
        self.assertNotIn(b"Export JSON", response.data)
        with self.app.app_context():
            scan = db.session.scalar(db.select(EmailScan))
            self.assertIsNotNone(scan)
            self.assertIsNone(scan.user_id)
            self.assertEqual(scan.verdict, "Low Risk")
            self.assertEqual(scan.reputation_data_json["provider"], "Public RDAP and IP network context")
            scan_id = scan.id
        self.assertEqual(os.listdir(self.app.config["UPLOAD_FOLDER"]), [])

        self.assertEqual(self.client.get("/history").status_code, 302)
        self.assertEqual(self.client.get(f"/scans/{scan_id}").status_code, 302)
        self.assertEqual(self.client.get(f"/scans/{scan_id}/report.pdf").status_code, 302)

    def test_admin_can_review_export_and_delete_public_report(self):
        email = b"""From: Security Team <security@gmail.com>\nTo: test@example.com\nReply-To: help@unrelated.example\nSubject: Urgent account suspended\nAuthentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=boundary\n\n--boundary\nContent-Type: text/html; charset=utf-8\n\n<html><body>Verify your password. <a href=\"http://192.0.2.1/login\">Click here</a></body></html>\n--boundary\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"invoice.exe\"\nContent-Transfer-Encoding: base64\n\nZXZpbA==\n--boundary--\n"""
        upload = self.client.post(
            "/upload",
            data={"email_file": (io.BytesIO(email), "risk-test.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 200)
        with self.app.app_context():
            scan = db.session.scalar(db.select(EmailScan))
            scan_id = scan.id
            self.assertEqual(scan.verdict, "High Risk")
            self.assertIn("Executable attachments", scan.risk_categories_list)

        self._login_as_admin()
        history = self.client.get("/history", query_string={"q": "Urgent", "verdict": "High Risk"})
        self.assertEqual(history.status_code, 200)
        self.assertIn(b"Public visitor", history.data)
        self.assertIn(b"Urgent account suspended", history.data)

        # Verify searching by "Public visitor" or "public" matches unassigned public scans
        public_search = self.client.get("/history", query_string={"q": "public"})
        self.assertEqual(public_search.status_code, 200)
        self.assertIn(b"Urgent account suspended", public_search.data)

        self.assertEqual(self.client.get(f"/scans/{scan_id}").status_code, 200)
        csv_export = self.client.get("/history/export.csv", query_string={"verdict": "High Risk"})
        self.assertEqual(csv_export.status_code, 200)
        self.assertIn(b"High Risk", csv_export.data)
        exported = self.client.get(f"/scans/{scan_id}/export.json")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.json["analysis"]["verdict"], "High Risk")
        report = self.client.get(f"/scans/{scan_id}/report.pdf")
        self.assertEqual(report.status_code, 200)
        self.assertTrue(report.data.startswith(b"%PDF"))

        self.assertEqual(self.client.post(f"/scans/{scan_id}/delete").status_code, 302)
        with self.app.app_context():
            self.assertIsNone(db.session.get(EmailScan, scan_id))

    def test_normal_user_login_is_disabled(self):
        response = self.client.post("/staff/login", data={"email": "legacy@example.com", "password": "normal-password"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"restricted to administrators and analysts", response.data)

    def test_scan_url_dedicated_page(self):
        response = self.client.get("/scan/url?url=http://login-verify-account.example.com")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"URL ANALYSIS", response.data)
        self.assertIn(b"login-verify-account.example.com", response.data)
        self.assertIn(b"Local Heuristic &amp; Inspection Rule Modules", response.data)

    def test_scan_ioc_dedicated_page(self):
        response = self.client.get("/scan/ioc?q=192.168.1.1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"IOC SEARCH", response.data)
        self.assertIn(b"192.168.1.1", response.data)
        self.assertIn(b"IPv4 Address", response.data)


if __name__ == "__main__":
    unittest.main()
