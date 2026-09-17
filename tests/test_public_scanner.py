import io
import unittest
from datetime import datetime, timedelta, timezone
from app import create_app
from models.scan import EmailScan
from models.user import User, db
from services.retention import cleanup_expired_guest_scans
from scanner.qr_ocr_scanner import decode_qr_code_from_image, scan_attachment_for_quishing
import zxingcpp
from PIL import Image

class PublicScannerTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
        })
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_guest_upload_generates_guest_token(self):
        eml_content = (
            b"From: billing@paypal-secure.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Confirm Account\r\n"
            b"Date: Mon, 15 Sep 2026 12:00:00 +0000\r\n"
            b"\r\n"
            b"Please verify your account.\r\n"
        )
        res = self.client.post(
            "/upload",
            data={"email_file": (io.BytesIO(eml_content), "test.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 200)

        scan = EmailScan.query.first()
        self.assertIsNotNone(scan)
        self.assertIsNone(scan.user_id)
        self.assertIsNotNone(scan.guest_token)
        self.assertTrue(len(scan.guest_token) >= 32)

        # Guest result accessible via guest_token
        guest_res = self.client.get(f"/result/{scan.guest_token}")
        self.assertEqual(guest_res.status_code, 200)
        self.assertIn(b"Confirm Account", guest_res.data)

        # Guest PDF download accessible via guest_token
        guest_pdf = self.client.get(f"/result/{scan.guest_token}/pdf")
        self.assertEqual(guest_pdf.status_code, 200)
        self.assertEqual(guest_pdf.mimetype, "application/pdf")
        self.assertTrue(guest_pdf.data.startswith(b"%PDF"))

    def test_quishing_scanner_with_real_qr_code(self):
        bc = zxingcpp.create_barcode("https://evil-quishing.example.com/login", zxingcpp.BarcodeFormat.QRCode)
        zimg = zxingcpp.write_barcode_to_image(bc)
        pimg = Image.fromarray(zimg)
        buf = io.BytesIO()
        pimg.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        # Direct QR decode test
        urls = decode_qr_code_from_image(png_bytes)
        self.assertIn("https://evil-quishing.example.com/login", urls)

        # Attachment quishing scan test
        res = scan_attachment_for_quishing(png_bytes, filename="invoice_qr.png", content_type="image/png")
        self.assertTrue(res["has_qr_code"])
        self.assertIn("https://evil-quishing.example.com/login", res["qr_urls"])
        self.assertEqual(res["quishing_score"], 45)

    def test_guest_retention_cleanup(self):
        # Create expired guest scan (25h old)
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        expired_scan = EmailScan(
            guest_token="expired_token_123",
            user_id=None,
            subject="Expired Guest Scan",
            scan_time=old_time,
            risk_score=10,
        )

        # Create fresh guest scan (1h old)
        fresh_time = datetime.now(timezone.utc) - timedelta(hours=1)
        fresh_scan = EmailScan(
            guest_token="fresh_token_456",
            user_id=None,
            subject="Fresh Guest Scan",
            scan_time=fresh_time,
            risk_score=10,
        )

        # Create registered user scan (also 25h old, but owned by user)
        user = User(username="retention_user", email="ret@example.com", password="pwd", role=User.ROLE_USER)
        db.session.add(user)
        db.session.commit()

        user_scan = EmailScan(
            user_id=user.id,
            subject="User Protected Scan",
            scan_time=old_time,
            risk_score=10,
        )
        db.session.add_all([expired_scan, fresh_scan, user_scan])
        db.session.commit()

        # Run cleanup with 24h threshold
        result = cleanup_expired_guest_scans(max_age_hours=24)
        self.assertEqual(result["scans_purged"], 1)

        # Expired guest scan deleted
        self.assertIsNone(EmailScan.query.filter_by(guest_token="expired_token_123").first())

        # Fresh guest scan preserved
        self.assertIsNotNone(EmailScan.query.filter_by(guest_token="fresh_token_456").first())

        # Registered user scan preserved (never deleted by guest retention)
        self.assertIsNotNone(EmailScan.query.filter_by(subject="User Protected Scan").first())

if __name__ == "__main__":
    unittest.main()
