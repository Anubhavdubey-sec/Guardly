import io
import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from models.scan import EmailScan
from models.user import User, db
from services.csrf import generate_csrf_token
from services.report_generator import build_scan_report
from services.ssrf import is_ip_private_or_internal, validate_url_ssrf


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        root = self.temp_directory.name.replace("\\", "/")
        self.app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": True,  # Enable CSRF explicitly for security testing
            "SECRET_KEY": "test-security-secret-key-32-bytes-long",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{root}/security_test.db",
            "UPLOAD_FOLDER": os.path.join(self.temp_directory.name, "uploads"),
            "PUBLIC_LOOKUPS_ENABLED": False,
        })
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        self.temp_directory.cleanup()

    def test_csrf_protection_blocks_untokenized_post_requests(self):
        client = self.app.test_client()
        response = client.post("/staff/login", data={"email": "hacker@evil.sec", "password": "password123"})
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"CSRF token missing or invalid", response.data)

    def test_csrf_protection_allows_valid_tokenized_post_requests(self):
        client = self.app.test_client()

        # Obtain a valid session CSRF token
        with client.session_transaction() as sess:
            sess["csrf_token"] = "valid_test_csrf_token_1234567890"

        response = client.post(
            "/staff/login",
            data={
                "csrf_token": "valid_test_csrf_token_1234567890",
                "email": "invalid@enterprise.sec",
                "password": "wrongpassword",
            },
        )
        # Should proceed to auth check (returning 401 or login error, not 403 CSRF error)
        self.assertNotEqual(response.status_code, 403)

    def test_ssrf_ipaddress_validation_blocks_internal_subnets(self):
        # Restricted loopback, RFC1918, link-local, and cloud metadata targets
        self.assertTrue(is_ip_private_or_internal("127.0.0.1"))
        self.assertTrue(is_ip_private_or_internal("10.0.0.1"))
        self.assertTrue(is_ip_private_or_internal("192.168.1.100"))
        self.assertTrue(is_ip_private_or_internal("172.16.0.5"))
        self.assertTrue(is_ip_private_or_internal("169.254.169.254"))
        self.assertTrue(is_ip_private_or_internal("::1"))

        # Public internet IPs should be permitted
        self.assertFalse(is_ip_private_or_internal("8.8.8.8"))
        self.assertFalse(is_ip_private_or_internal("1.1.1.1"))
        self.assertFalse(is_ip_private_or_internal("9.9.9.9"))

    def test_ssrf_url_validation_blocks_restricted_schemes_and_hosts(self):
        # Non-HTTP/HTTPS schemes
        is_valid, reason, _ip = validate_url_ssrf("file:///etc/passwd")
        self.assertFalse(is_valid)

        is_valid, reason, _ip = validate_url_ssrf("gopher://127.0.0.1:70")
        self.assertFalse(is_valid)

        # Restricted loopback and metadata hosts
        is_valid, reason, _ip = validate_url_ssrf("http://127.0.0.1:5000/dashboard")
        self.assertFalse(is_valid)

        is_valid, reason, _ip = validate_url_ssrf("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_valid)

        is_valid, reason, _ip = validate_url_ssrf("http://localhost:8080")
        self.assertFalse(is_valid)

    def test_reportlab_pdf_generator_builds_valid_pdf_buffer(self):
        with self.app.app_context():
            scan = EmailScan(
                sender="phisher@bad-domain.com",
                receiver="victim@enterprise.sec",
                subject="Urgent Account Verification Required",
                risk_score=85,
                verdict="High Risk",
            )
            db.session.add(scan)
            db.session.commit()

            email_data = {
                "subject": scan.subject,
                "from": scan.sender,
                "from_address": scan.sender,
                "to": scan.receiver,
                "date": "2026-08-05 02:00 UTC",
                "attachments": [],
                "urls": ["http://phish-site-example.com/login"],
                "iocs": {"domains": ["phish-site-example.com"], "ip_addresses": ["198.51.100.22"]},
            }
            analysis = {
                "score": 85,
                "verdict": "High Risk",
                "findings": ["Executable attachment detected", "Brand impersonation attempt"],
                "categories": ["Executable", "Phishing"],
            }

            pdf_buffer = build_scan_report(scan, email_data, analysis)
            pdf_bytes = pdf_buffer.getvalue()

            self.assertTrue(isinstance(pdf_bytes, bytes))
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
            self.assertIn(b"ReportLab", pdf_bytes)

    def test_ssrf_safe_http_get_blocks_redirect_to_private_ip(self):
        from services.ssrf import safe_http_get
        # Direct private IP target
        with self.assertRaises(ValueError) as ctx:
            safe_http_get("http://127.0.0.1:5000/internal-status")
        self.assertIn("SSRF Firewall Blocked Target", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            safe_http_get("http://169.254.169.254/latest/meta-data/")
        self.assertIn("SSRF Firewall Blocked Target", str(ctx.exception))

    def test_ssrf_hardened_ipv6_unresolvable_and_dns_rebinding(self):
        from unittest.mock import patch, MagicMock
        from services.ssrf import is_ip_private_or_internal, validate_url_ssrf, safe_http_get

        # 1. IPv6 Validation Tests
        self.assertTrue(is_ip_private_or_internal("::1"))
        self.assertTrue(is_ip_private_or_internal("fe80::1"))
        self.assertTrue(is_ip_private_or_internal("fd00::1"))
        self.assertFalse(is_ip_private_or_internal("2607:f8b0:4005:805::200e"))

        # 2. Private IPv4/IPv6 & Internal TLDs in validate_url_ssrf
        self.assertFalse(validate_url_ssrf("http://192.168.1.1/")[0])
        self.assertFalse(validate_url_ssrf("http://10.0.0.1/")[0])
        self.assertFalse(validate_url_ssrf("http://172.16.0.1/")[0])
        self.assertFalse(validate_url_ssrf("http://[::1]/")[0])
        self.assertFalse(validate_url_ssrf("http://[fe80::1]/")[0])
        self.assertFalse(validate_url_ssrf("http://server.local/")[0])
        self.assertFalse(validate_url_ssrf("http://server.internal/")[0])

        # 3. Unresolvable Hostnames
        is_valid, reason, pinned_ip = validate_url_ssrf("http://nonexistent-domain-99999.invalid/")
        self.assertFalse(is_valid)
        self.assertIsNone(pinned_ip)

        # safe_http_get on unresolvable host must raise ValueError without socket connection
        with self.assertRaises(ValueError) as ctx:
            safe_http_get("http://nonexistent-domain-99999.invalid/")
        self.assertIn("SSRF Firewall Blocked Target", str(ctx.exception))

        # 4. DNS Rebinding Pinning Verification
        # Mock getaddrinfo returning a valid public IP 93.184.216.34 for example.org
        mock_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        with patch("socket.getaddrinfo", return_value=mock_addr) as mock_gai:
            with patch("socket.create_connection") as mock_conn:
                mock_sock = MagicMock()
                mock_conn.return_value = mock_sock
                # Mock http.client response
                with patch("http.client.HTTPConnection") as mock_http_cls:
                    mock_conn_inst = MagicMock()
                    mock_http_cls.return_value = mock_conn_inst
                    mock_resp = MagicMock()
                    mock_resp.status = 200
                    mock_resp.getheaders.return_value = [("Content-Type", "text/html")]
                    mock_resp.read.return_value = b"OK"
                    mock_conn_inst.getresponse.return_value = mock_resp

                    status, body, final_url, banner, ctype, pinned_ip, redirect_hops = safe_http_get("http://example.org/test")
                    
                    # Verify socket.create_connection was called directly with pinned_ip ("93.184.216.34", 80)
                    mock_conn.assert_called_once_with(("93.184.216.34", 80), timeout=2.5)
                    self.assertEqual(pinned_ip, "93.184.216.34")
                    # Verify getaddrinfo was only called once during validation, not during connection
                    self.assertEqual(mock_gai.call_count, 1)

    def test_login_rate_limiting_blocks_brute_force_attempts(self):
        from services.limiter import limiter
        limiter.enabled = True
        limiter.reset()

        rate_app = create_app({
            "TESTING": True,
            "RATELIMIT_ENABLED": True,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "test-rate-limit-secret-key",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "PUBLIC_LOOKUPS_ENABLED": False,
        })
        client = rate_app.test_client()

        # Perform 5 failed login attempts (allowed by rate limit of 5 per minute)
        for i in range(5):
            res = client.post("/staff/login", data={"email": "brute@evil.sec", "password": f"wrong{i}"})
            self.assertNotEqual(res.status_code, 429)

        # 6th attempt should be blocked with 429 Too Many Requests
        res = client.post("/staff/login", data={"email": "brute@evil.sec", "password": "wrong6"})
        self.assertEqual(res.status_code, 429)
        self.assertIn(b"Too many login attempts", res.data)

    def test_admin_self_lockout_prevention(self):
        with self.app.app_context():
            admin = User(username="SoleAdmin", email="admin@enterprise.sec", password="password", role=User.ROLE_ADMIN)
            db.session.add(admin)
            db.session.commit()
            admin_id = admin.id

        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id
            sess["username"] = "SoleAdmin"
            sess["csrf_token"] = "test_csrf_token_admin"

        # Attempt to demote sole admin to analyst
        res = client.post(
            f"/admin/users/{admin_id}/role",
            data={"csrf_token": "test_csrf_token_admin", "role": User.ROLE_ANALYST},
            follow_redirects=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Cannot remove the last administrator account", res.data)

        with self.app.app_context():
            check_user = db.session.get(User, admin_id)
            self.assertEqual(check_user.role, User.ROLE_ADMIN)


    def test_security_response_headers(self):
        client = self.app.test_client()
        res = client.get("/upload")
        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Permissions-Policy", res.headers)
        self.assertIn("Content-Security-Policy", res.headers)


if __name__ == "__main__":
    unittest.main()
