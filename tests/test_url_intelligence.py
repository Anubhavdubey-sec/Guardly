import unittest

from scanner.url_intelligence import inspect_url_threat_intelligence
from services.entropy import calculate_shannon_entropy
from services.homograph import analyze_homograph_and_brand_impersonation
from services.punycode import analyze_punycode_domain
from services.tld_analysis import analyze_tld_and_shortener
from services.url_parser import decode_numeric_ip, parse_and_normalize_url


class URLThreatIntelligenceTests(unittest.TestCase):
    def test_hexadecimal_ip_decoding(self):
        decoded = decode_numeric_ip("0x7F000001")
        self.assertEqual(decoded, "127.0.0.1")

    def test_decimal_integer_ip_decoding(self):
        decoded = decode_numeric_ip("2130706433")
        self.assertEqual(decoded, "127.0.0.1")

    def test_octal_ip_decoding(self):
        decoded = decode_numeric_ip("0177.0.0.1")
        self.assertEqual(decoded, "127.0.0.1")

    def test_url_parser_embedded_credentials(self):
        parsed = parse_and_normalize_url("http://admin:secret123@example.com/login")
        self.assertTrue(parsed["has_credentials"])
        self.assertEqual(parsed["username"], "admin")
        self.assertEqual(parsed["password"], "secret123")

    def test_punycode_domain_detection(self) -> None:
        res = analyze_punycode_domain("xn--e1afmkfd.xn--p1ai")
        self.assertTrue(res["is_punycode"])
        self.assertGreater(res["risk"], 0)

    def test_homograph_brand_impersonation(self):
        res1 = analyze_homograph_and_brand_impersonation("micr0soft-login.com")
        res2 = analyze_homograph_and_brand_impersonation("paypaI.com")
        res3 = analyze_homograph_and_brand_impersonation("g00gle-security.com")

        self.assertTrue(res1["is_homograph"])
        self.assertEqual(res1["impersonated_brand"], "Microsoft")
        self.assertTrue(res2["is_homograph"])
        self.assertTrue(res3["is_homograph"])

    def test_tld_and_shortener_analysis(self):
        res_short = analyze_tld_and_shortener("bit.ly", "bit.ly")
        res_zip = analyze_tld_and_shortener("update.zip", "update.zip")
        res_xyz = analyze_tld_and_shortener("malicious.xyz", "malicious.xyz")

        self.assertTrue(res_short["is_shortener"])
        self.assertTrue(res_zip["is_suspicious_tld"])
        self.assertEqual(res_zip["tld"], ".zip")
        self.assertTrue(res_xyz["is_suspicious_tld"])

    def test_shannon_entropy_calculation(self):
        ent_low = calculate_shannon_entropy("google.com")
        ent_high = calculate_shannon_entropy("a8f9d0c2e1b3456789abcdef0123456789.com")
        self.assertGreater(ent_high, ent_low)

    def test_full_url_threat_intelligence_inspection(self):
        res = inspect_url_threat_intelligence("http://admin:pass@micr0soft-update.zip/login?token=a8f9d0c2e1b3456789")
        self.assertIn("url_risk_score", res)
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreater(res["url_risk_score"], 60)
        self.assertTrue(any("Embedded Credentials" in f["finding"] for f in res["findings"]))


if __name__ == "__main__":
    unittest.main()
