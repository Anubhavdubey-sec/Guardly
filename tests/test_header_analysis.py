import unittest

from scanner.header_analyzer import analyze_email_headers
from services.auth_results import analyze_email_authentication, parse_authentication_results_header
from services.header_validator import fingerprint_mail_client, validate_message_id_and_headers
from services.received_parser import classify_ip_address, parse_received_chain, parse_single_received_header
from services.sender_analysis import analyze_sender_identity


class HeaderAnalysisDFIRTests(unittest.TestCase):
    def test_authentication_results_parsing_spf_dkim_dmarc_pass(self):
        auth_header = (
            "mx.google.com; "
            "dkim=pass header.i=@example.com; "
            "spf=pass (google.com: domain of user@example.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=user@example.com; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"
        )
        parsed = parse_authentication_results_header(auth_header)
        self.assertEqual(parsed["spf"]["status"], "PASS")
        self.assertEqual(parsed["dkim"]["status"], "PASS")
        self.assertEqual(parsed["dmarc"]["status"], "PASS")
        self.assertEqual(parsed["dmarc"]["policy"], "REJECT")

    def test_authentication_results_parsing_fail(self):
        auth_header = "mx.google.com; dkim=fail; spf=fail (google.com: domain of attacker@evil.sec does not designate 10.0.0.1); dmarc=fail"
        parsed = parse_authentication_results_header(auth_header)
        self.assertEqual(parsed["spf"]["status"], "FAIL")
        self.assertEqual(parsed["dkim"]["status"], "FAIL")
        self.assertEqual(parsed["dmarc"]["status"], "FAIL")

    def test_sender_identity_reply_to_mismatch(self):
        headers = {
            "From": "Support Team <support@bank.com>",
            "Reply-To": "hacker@evil.sec",
        }
        sender_res = analyze_sender_identity(headers)
        self.assertTrue(sender_res["reply_to_mismatch"])
        self.assertGreater(sender_res["spoofing_score"], 0)
        self.assertTrue(any(a["finding"] == "Reply-To Mismatch" for a in sender_res["anomalies"]))

    def test_sender_identity_free_email_brand_impersonation(self):
        headers = {
            "From": "Microsoft Security Team <security-alert@gmail.com>",
        }
        sender_res = analyze_sender_identity(headers)
        self.assertTrue(sender_res["display_name_spoofing"])
        self.assertTrue(any("Brand Impersonation" in a["finding"] for a in sender_res["anomalies"]))

    def test_received_chain_parsing_and_clock_skew(self):
        headers = {
            "Received": [
                "from mx2.recv.com by mail.target.com with ESMTP id 12345; Fri, 07 Aug 2026 02:00:00 +0000",
                "from mail.sender.com ([192.168.1.50]) by mx1.recv.com with ESMTP; Fri, 07 Aug 2026 02:05:00 +0000",
            ]
        }
        chain_res = parse_received_chain(headers)
        self.assertEqual(chain_res["hop_count"], 2)
        self.assertGreaterEqual(chain_res["private_relay_count"], 1)

    def test_message_id_validation_malformed(self):
        headers = {
            "From": "user@example.com",
            "Message-ID": "invalid-message-id-without-brackets-or-at",
        }
        validator_res = validate_message_id_and_headers(headers, from_domain="example.com")
        self.assertFalse(validator_res["is_valid_syntax"])
        self.assertTrue(any("Malformed Message-ID" in a["finding"] for a in validator_res["anomalies"]))

    def test_mail_client_fingerprinting(self):
        headers_outlook = {"User-Agent": "Microsoft Outlook 16.0"}
        headers_apple = {"X-Mailer": "Apple Mail (2.3654.120)"}
        
        fp_outlook = fingerprint_mail_client(headers_outlook)
        fp_apple = fingerprint_mail_client(headers_apple)

        self.assertIn("Outlook", fp_outlook["client_name"])
        self.assertIn("Apple Mail", fp_apple["client_name"])

    def test_ip_classification(self):
        pub_ip = classify_ip_address("8.8.8.8")
        priv_ip = classify_ip_address("192.168.1.1")
        loop_ip = classify_ip_address("127.0.0.1")

        self.assertFalse(pub_ip["is_private"])
        self.assertTrue(priv_ip["is_private"])
        self.assertEqual(loop_ip["category"], "Loopback")

    def test_full_header_analyzer_workflow(self):
        headers = {
            "From": "Security Alert <support@microsoft.com>",
            "Reply-To": "hacker@evil.sec",
            "Message-ID": "<202608070200.12345@microsoft.com>",
            "Authentication-Results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
            "Received": "from mail.microsoft.com ([20.190.160.1]) by mx.google.com with ESMTP id abc; Fri, 07 Aug 2026 02:00:00 +0000",
        }
        res = analyze_email_headers(headers)
        self.assertIn("header_security_score", res)
        self.assertIn("findings", res)
        self.assertTrue(any("Reply-To Mismatch" in f["finding"] for f in res["findings"]))


if __name__ == "__main__":
    unittest.main()
