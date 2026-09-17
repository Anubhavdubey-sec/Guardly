import unittest

from scanner.nlp_analyzer import analyze_social_engineering_nlp
from scanner.qr_ocr_scanner import decode_qr_code_from_image, scan_attachment_for_quishing


class QuishingAndNLPTests(unittest.TestCase):
    def test_qr_code_url_decoding_from_payload(self):
        sample_img_payload = b"\x89PNG\r\n\x1a\n\x00\x00https://malicious-qr-target.com/login\x00\x00"
        urls = decode_qr_code_from_image(sample_img_payload)
        self.assertIn("https://malicious-qr-target.com/login", urls)

    def test_scan_attachment_for_quishing_positive(self):
        sample_payload = b"\x89PNG\r\n\x1a\n\x00\x00http://phish-qr.zip/login\x00\x00"
        res = scan_attachment_for_quishing(sample_payload, "qrcode.png", "image/png")
        self.assertTrue(res["is_image"])
        self.assertTrue(res["has_qr_code"])
        self.assertIn("http://phish-qr.zip/login", res["qr_urls"])
        self.assertGreater(res["quishing_score"], 0)

    def test_scan_attachment_for_quishing_negative(self):
        res = scan_attachment_for_quishing(b"clean pdf content", "report.pdf", "application/pdf")
        self.assertFalse(res["is_image"])
        self.assertFalse(res["has_qr_code"])

    def test_nlp_executive_impersonation_detection(self):
        email_data = {
            "subject": "URGENT: Executive Wire Transfer Instructions",
            "body": "Hi, I am the CEO. Please act immediately within 1 hour to update payroll direct deposit bank details. Keep this confidential and do not call my desk.",
        }
        res = analyze_social_engineering_nlp(email_data)
        self.assertGreater(res["social_engineering_score"], 50)
        self.assertIn("Executive & Authority Impersonation", res["tactics"])
        self.assertIn("Coercive Urgency Pressure", res["tactics"])
        self.assertIn("Financial Payment Routing Lure", res["tactics"])
        self.assertIn("Out-of-Band Secrecy Lure", res["tactics"])

    def test_nlp_clean_email_detection(self):
        email_data = {
            "subject": "Weekly Team Meeting Agenda",
            "body": "Hi team, here is the agenda for our weekly sync. Let me know if you have any topics to add.",
        }
        res = analyze_social_engineering_nlp(email_data)
        self.assertEqual(res["social_engineering_score"], 0)
        self.assertEqual(len(res["tactics"]), 0)


if __name__ == "__main__":
    unittest.main()
