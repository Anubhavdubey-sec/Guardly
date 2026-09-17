import base64
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from reportlab.pdfgen import canvas

from scanner.email_parser import parse_email
from scanner.pdf_scanner import extract_pdf_intel
from scanner.phishing_detector import analyze_email


def create_sample_pdf(text=None, link_url=None):
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    if text:
        c.drawString(100, 700, text)
    if link_url:
        # Adds link annotation with rect
        c.linkURL(link_url, (100, 650, 300, 670), relative=1)
    c.save()
    return buf.getvalue()


class PDFScannerTests(unittest.TestCase):
    def test_extract_pdf_intel_plain_text_and_annotation(self):
        pdf_bytes = create_sample_pdf(
            text="Please read report at https://example.com/report",
            link_url="http://paypal-verify-secure.com/login",
        )
        intel = extract_pdf_intel(pdf_bytes)
        self.assertIsNone(intel["error"])
        self.assertEqual(intel["page_count"], 1)
        self.assertIn("https://example.com/report", intel["urls"])
        self.assertIn("http://paypal-verify-secure.com/login", intel["urls"])
        self.assertIn("Please read report", intel["text"])

    def test_extract_pdf_intel_corrupt_payload(self):
        corrupt_bytes = b"%PDF-1.4 corrupt data"
        intel = extract_pdf_intel(corrupt_bytes)
        self.assertIsNotNone(intel["error"])
        self.assertEqual(intel["urls"], [])
        self.assertEqual(intel["page_count"], 0)

    def test_email_with_pdf_hidden_link(self):
        pdf_bytes = create_sample_pdf(
            text="Invoice attached. Click button below to pay.",
            link_url="http://paypal-security-update.com/verify",
        )

        b64_pdf = base64.b64encode(pdf_bytes).decode("utf-8")
        eml_content = (
            "From: billing@company.com\n"
            "To: target@example.com\n"
            "Subject: Important Invoice PDF\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="BOUNDARY"\n\n'
            "--BOUNDARY\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Please view the attached invoice.\n\n"
            "--BOUNDARY\n"
            "Content-Type: application/pdf\n"
            'Content-Disposition: attachment; filename="invoice.pdf"\n'
            "Content-Transfer-Encoding: base64\n\n"
            + b64_pdf
            + "\n--BOUNDARY--\n"
        )

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".eml") as tmp:
            tmp.write(eml_content)
            tmp_path = tmp.name

        try:
            parsed = parse_email(tmp_path)
            self.assertIn("http://paypal-security-update.com/verify", parsed["urls"])
            self.assertIn("http://paypal-security-update.com/verify", parsed["pdf_urls"])

            analysis = analyze_email(parsed)
            self.assertIn("Link hidden in attachment", analysis["categories"])
            self.assertIn("Suspicious URL", analysis["categories"])
            self.assertGreaterEqual(analysis["score"], 45)

            findings_text = " ".join(analysis["findings"])
            self.assertIn("PDF attachment 'invoice.pdf' contains 1 embedded link(s)", findings_text)
            self.assertIn("PDF attachment: http://paypal-security-update.com/verify", findings_text)
            self.assertIn("URL is embedded inside a PDF attachment rather than the message body.", findings_text)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_email_with_pdf_no_links_unaffected(self):
        pdf_bytes = create_sample_pdf(text="Just plain invoice text with no links.")

        b64_pdf = base64.b64encode(pdf_bytes).decode("utf-8")
        eml_content = (
            "From: info@company.com\n"
            "To: target@example.com\n"
            "Subject: Clean Document\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="BOUNDARY"\n\n'
            "--BOUNDARY\n"
            "Content-Type: text/plain\n\n"
            "Here is your document.\n\n"
            "--BOUNDARY\n"
            "Content-Type: application/pdf\n"
            'Content-Disposition: attachment; filename="clean.pdf"\n'
            "Content-Transfer-Encoding: base64\n\n"
            + b64_pdf
            + "\n--BOUNDARY--\n"
        )

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".eml") as tmp:
            tmp.write(eml_content)
            tmp_path = tmp.name

        try:
            parsed = parse_email(tmp_path)
            self.assertEqual(parsed["pdf_urls"], [])

            analysis = analyze_email(parsed)
            self.assertNotIn("Link hidden in attachment", analysis["categories"])
            self.assertLess(analysis["score"], 20)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
