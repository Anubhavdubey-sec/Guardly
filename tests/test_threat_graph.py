import unittest

from app import create_app
from models.scan import EmailScan
from models.user import User, db
from services.graph_builder import build_threat_graph_data


class ThreatGraphEngineTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create sample scan records
        import json
        self.scan1 = EmailScan(
            subject="Urgent Invoice Payment",
            sender="billing@malicious-domain.com",
            receiver="victim@company.com",
            urls=json.dumps(["http://malicious-domain.com/pay"]),
            risk_score=85,
            verdict="High Risk",
        )
        db.session.add(self.scan1)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_build_threat_graph_data_nodes_and_edges(self):
        data = build_threat_graph_data(scan_id=self.scan1.id)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("summary", data)

        node_groups = [n["group"] for n in data["nodes"]]
        self.assertIn("email", node_groups)
        self.assertIn("domain", node_groups)
        self.assertIn("recipient", node_groups)
        self.assertIn("url", node_groups)

    def test_threat_graph_api_endpoint(self):
        client = self.app.test_client()
        res = client.get("/api/v1/threat-graph/data")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertIn("nodes", json_data)
        self.assertIn("edges", json_data)


if __name__ == "__main__":
    unittest.main()
