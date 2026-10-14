import unittest
from unittest.mock import MagicMock, patch

from services.threat_intelligence.base_provider import BaseThreatProvider
from services.threat_intelligence.whois_lookup import WhoisLookupProvider
from services.threat_intelligence.dns_lookup import DNSLookupProvider
from services.threat_intelligence.urlhaus import URLHausProvider
from services.threat_intelligence.enrichment_service import ThreatEnrichmentService
from app import create_app


class ThreatIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
        self.client = self.app.test_client()

    def test_whois_lookup_provider_domain_analysis(self):
        provider = WhoisLookupProvider(timeout=2)
        mock_rdap = {
            "ldhName": "example.com",
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
                }
            ],
        }

        with patch.object(provider, "_query_rdap", return_value=mock_rdap):
            res = provider.analyze("example.com", "domain")
            self.assertEqual(res["verdict"], "Info")
            self.assertEqual(res["raw_data"]["registrar"], "Example Registrar Inc.")
            self.assertGreater(res["raw_data"]["age_days"], 365)

    def test_whois_lookup_provider_young_domain(self):
        provider = WhoisLookupProvider(timeout=2)
        mock_rdap = {
            "ldhName": "phishing-bank-update.com",
            "events": [
                {"eventAction": "registration", "eventDate": "2026-10-01T00:00:00Z"},
            ],
            "entities": [],
        }

        with patch.object(provider, "_query_rdap", return_value=mock_rdap):
            res = provider.analyze("phishing-bank-update.com", "domain")
            self.assertEqual(res["verdict"], "Suspicious")
            self.assertEqual(res["suspicious"], 1)
            self.assertGreaterEqual(res["score"], 35)

    def test_dns_lookup_provider_resolution(self):
        provider = DNSLookupProvider(timeout=2)
        mock_records = {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["10 mail.example.com"],
            "TXT": ["v=spf1 -all"],
            "NS": ["ns1.example.com"],
        }

        with patch.object(provider, "_resolve_all", return_value=mock_records), \
             patch.object(provider, "_resolve_record", return_value=["v=DMARC1; p=reject;"]):
            res = provider.analyze("example.com", "domain")
            self.assertEqual(res["verdict"], "Clean")
            self.assertEqual(res["raw_data"]["a"], ["93.184.216.34"])
            self.assertEqual(res["raw_data"]["dmarc"], ["v=DMARC1; p=reject;"])

    def test_urlhaus_malicious_detection(self):
        provider = URLHausProvider(timeout=2)
        mock_response = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["agenttesla", "exe"],
        }

        with patch.object(provider, "_post_query", return_value=mock_response):
            res = provider.analyze("http://evil-malware-payload.com/setup.exe", "url")
            self.assertEqual(res["verdict"], "Malicious")
            self.assertEqual(res["malicious"], 1)
            self.assertEqual(res["score"], 95)
            self.assertIn("malware_download", res["categories"])

    def test_enrichment_service_consensus(self):
        service = ThreatEnrichmentService(timeout=2)

        # Mock providers
        mock_p1 = MagicMock(spec=BaseThreatProvider)
        mock_p1.name = "MockMalwareFeed"
        mock_p1.analyze.return_value = {
            "provider": "MockMalwareFeed",
            "verdict": "Malicious",
            "score": 90,
            "confidence": 0.9,
            "malicious": 1,
            "suspicious": 0,
            "harmless": 0,
            "categories": ["trojan"],
        }

        service.providers = [mock_p1]
        res = service.enrich_ioc("http://bad-url.com/loader", "url")
        self.assertEqual(res["consensus_verdict"], "Malicious")
        self.assertGreaterEqual(res["risk_score"], 80)
        self.assertEqual(res["malicious_count"], 1)

    def test_scan_ioc_endpoint_with_threat_intelligence(self):
        with self.app.test_client() as client:
            resp = client.get("/scan/ioc?q=example.com&format=json")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn("threat_intel", data)
            self.assertIn("consensus_verdict", data["threat_intel"])


if __name__ == "__main__":
    unittest.main()
