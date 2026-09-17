import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.public_lookup import PublicLookupClient, enrich_analysis_with_public_context


class PublicLookupTests(unittest.TestCase):
    def test_disabled_public_lookup_client(self):
        client = PublicLookupClient(timeout_seconds=1, max_lookups=2)
        result = client.lookup_context(domains=["example.com"], ip_addresses=["1.1.1.1"])
        self.assertIn("provider", result)

    def test_enrich_analysis_with_public_context(self):
        analysis = {
            "score": 10,
            "verdict": "Low Risk",
            "findings": [],
            "categories": [],
            "url_assessments": [],
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        }
        reputation_data = {
            "provider": "Test Provider",
            "message": "Test message",
            "lookups": [],
        }
        enriched = enrich_analysis_with_public_context(analysis, reputation_data)
        self.assertEqual(enriched["reputation_data"]["provider"], "Test Provider")


if __name__ == "__main__":
    unittest.main()
