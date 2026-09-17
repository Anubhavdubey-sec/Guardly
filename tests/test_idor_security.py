import unittest
from werkzeug.security import generate_password_hash
from app import create_app
from models.scan import EmailScan
from models.user import User, db

class IDORSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
        })
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.alice = User(username="alice", email="alice@example.com", password=generate_password_hash("pass12345678"), role=User.ROLE_USER)
        self.bob = User(username="bob", email="bob@example.com", password=generate_password_hash("pass12345678"), role=User.ROLE_USER)
        db.session.add_all([self.alice, self.bob])
        db.session.commit()

        self.alice_scan = EmailScan(user_id=self.alice.id, subject="Alice Secret Financial Statement", risk_score=10, verdict="Low Risk")
        self.bob_scan = EmailScan(user_id=self.bob.id, subject="Bob Medical Records", risk_score=20, verdict="Low Risk")
        self.guest_scan = EmailScan(guest_token="guest_secret_token_1234567890abcdef", subject="Guest Public Scan", risk_score=30, verdict="Low Risk")
        db.session.add_all([self.alice_scan, self.bob_scan, self.guest_scan])
        db.session.commit()

        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _login(self, user):
        with self.client.session_transaction() as sess:
            sess.clear()
            sess["user_id"] = user.id
            sess["username"] = user.username

    def test_unauthenticated_user_cannot_access_private_scans_or_history(self):
        self.assertEqual(self.client.get(f"/scans/{self.alice_scan.id}").status_code, 302)
        self.assertEqual(self.client.get("/history").status_code, 302)
        self.assertEqual(self.client.get("/history/export.csv").status_code, 302)

    def test_alice_cannot_access_or_mutate_bob_scan(self):
        self._login(self.alice)

        # Alice views her own scan -> 200
        res_own = self.client.get(f"/scans/{self.alice_scan.id}")
        self.assertEqual(res_own.status_code, 200)
        self.assertIn(b"Alice Secret Financial Statement", res_own.data)

        # Alice tries to view Bob's scan -> 404 (IDOR prevented)
        res_bob = self.client.get(f"/scans/{self.bob_scan.id}")
        self.assertEqual(res_bob.status_code, 404)

        # Alice tries to export Bob's scan JSON -> 404
        self.assertEqual(self.client.get(f"/scans/{self.bob_scan.id}/export.json").status_code, 404)

        # Alice tries to download Bob's PDF -> 404
        self.assertEqual(self.client.get(f"/scans/{self.bob_scan.id}/report.pdf").status_code, 404)
        self.assertEqual(self.client.get(f"/scan/{self.bob_scan.id}/pdf").status_code, 404)

        # Alice tries to delete Bob's scan -> 404
        self.assertEqual(self.client.post(f"/scans/{self.bob_scan.id}/delete").status_code, 404)
        # Verify scan still exists in DB
        self.assertIsNotNone(db.session.get(EmailScan, self.bob_scan.id))

    def test_guest_token_isolation(self):
        # Guest scan accessible via /result/<token>
        res = self.client.get("/result/guest_secret_token_1234567890abcdef")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Guest Public Scan", res.data)

        # Invalid token returns 404
        self.assertEqual(self.client.get("/result/invalid_token").status_code, 404)

        # Guest scan cannot be queried via standard /scans/<id> without auth
        self.assertEqual(self.client.get(f"/scans/{self.guest_scan.id}").status_code, 302)

if __name__ == "__main__":
    unittest.main()
