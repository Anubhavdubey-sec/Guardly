import unittest

from services.playbook_engine import execute_soc_playbooks
from services.yara_generator import generate_sigma_rule, generate_yara_rule


class PlaybookAndYARAGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.sample_email = {
            "subject": "Urgent Password Reset Required",
            "from": "Security Team <security@bank.com>",
            "from_address": "security@bank.com",
            "sender_domain": "bank.com",
            "urls": ["http://phish-bank.com/login"],
            "iocs": {"domains": ["phish-bank.com"], "ip_addresses": ["192.168.1.100"]},
        }
        self.sample_analysis_high_risk = {
            "score": 85,
            "verdict": "High Risk",
            "findings": ["Credential harvesting lure", "Display Name Email Spoofing"],
            "categories": ["Credential harvesting / account security"],
        }
        self.sample_analysis_low_risk = {
            "score": 10,
            "verdict": "Low Risk",
            "findings": [],
            "categories": [],
        }

    def test_yara_rule_generation_valid_syntax(self):
        yara_code = generate_yara_rule(self.sample_email, self.sample_analysis_high_risk)
        self.assertIn("rule Guardly_Phish_Urgent_Password_Reset_Required", yara_code)
        self.assertIn('$subj_1 = "Urgent Password Reset Required" nocase', yara_code)
        self.assertIn("condition:", yara_code)

    def test_sigma_rule_generation_valid_yaml(self):
        sigma_code = generate_sigma_rule(self.sample_email, self.sample_analysis_high_risk)
        self.assertIn("title: Guardly Phishing Email Indicator", sigma_code)
        self.assertIn("EmailSubject|contains: \"Urgent Password Reset Required\"", sigma_code)
        self.assertIn("level: high", sigma_code)

    def test_soc_playbook_execution_high_risk(self):
        pb_res = execute_soc_playbooks(self.sample_email, self.sample_analysis_high_risk)
        self.assertIn("active_playbooks", pb_res)
        playbook_ids = [pb["playbook_id"] for pb in pb_res["active_playbooks"]]
        self.assertIn("PB-101", playbook_ids)  # High Risk Containment
        self.assertIn("PB-102", playbook_ids)  # Credential Theft Defense
        self.assertTrue(len(pb_res["recommended_actions"]) > 0)

    def test_soc_playbook_execution_low_risk(self):
        pb_res = execute_soc_playbooks(self.sample_email, self.sample_analysis_low_risk)
        playbook_ids = [pb["playbook_id"] for pb in pb_res["active_playbooks"]]
        self.assertIn("PB-100", playbook_ids)  # Standard Monitoring


if __name__ == "__main__":
    unittest.main()
