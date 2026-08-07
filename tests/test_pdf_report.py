import unittest

from app import create_app
from models.scan import EmailScan
from models.user import db
from services.pdf_report_generator import generate_pdf_scan_report


class PDFReportGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.scan = EmailScan(
            subject="PDF Export Test Email",
            sender="admin@phish-domain.com",
            receiver="victim@company.com",
            risk_score=90,
            verdict="High Risk",
        )
        db.session.add(self.scan)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_pdf_generation_bytes_output(self):
        email_data = {"subject": "Test PDF", "from": "a@b.com", "to": "c@d.com"}
        analysis = {"verdict": "High Risk", "score": 90, "findings": ["Credential lure"]}
        pdf_bytes = generate_pdf_scan_report(email_data, analysis, 1)
        self.assertTrue(len(pdf_bytes) > 0)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_pdf_download_route_endpoint(self):
        client = self.app.test_client()
        res = client.get(f"/scan/{self.scan.id}/pdf")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/pdf")
        self.assertTrue(res.data.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
