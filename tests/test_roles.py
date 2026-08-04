import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from models.scan import EmailScan
from models.system_log import SystemLog
from models.user import User, db


class RoleAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        root = self.temp_directory.name.replace("\\", "/")
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{root}/test.db",
            "UPLOAD_FOLDER": os.path.join(self.temp_directory.name, "uploads"),
            "PUBLIC_LOOKUPS_ENABLED": False,
        })
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.admin = User(username="Admin", email="admin@example.com", password="unused", role=User.ROLE_ADMIN)
            self.analyst = User(username="Analyst", email="analyst@example.com", password="unused", role=User.ROLE_ANALYST)
            self.normal_user = User(username="Normal", email="normal@example.com", password="unused", role=User.ROLE_USER)
            db.session.add_all([self.admin, self.analyst, self.normal_user])
            db.session.flush()
            self.scan = EmailScan(
                user_id=self.normal_user.id,
                sender="sender@example.com",
                receiver="normal@example.com",
                subject="Private report",
                risk_score=10,
                verdict="Low Risk",
            )
            db.session.add(self.scan)
            db.session.commit()
            self.admin_id = self.admin.id
            self.analyst_id = self.analyst.id
            self.normal_user_id = self.normal_user.id
            self.scan_id = self.scan.id
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            for engine in db.engines.values():
                engine.dispose()
        self.temp_directory.cleanup()

    def _login_as(self, user_id, username):
        with self.client.session_transaction() as session:
            session.clear()
            session["user_id"] = user_id
            session["username"] = username

    def test_normal_user_cannot_access_reports_and_analyst_is_read_only(self):
        self._login_as(self.normal_user_id, "Normal")
        self.assertEqual(self.client.get("/admin/").status_code, 302)
        self.assertEqual(self.client.get(f"/scans/{self.scan_id}").status_code, 302)
        self.assertEqual(self.client.get("/upload").status_code, 200)

        self._login_as(self.analyst_id, "Analyst")
        self.assertEqual(self.client.get(f"/scans/{self.scan_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/scans/{self.scan_id}/report.pdf").status_code, 302)
        self.assertEqual(self.client.post(f"/scans/{self.scan_id}/delete").status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(db.session.get(EmailScan, self.scan_id))

    def test_admin_can_manage_roles_and_view_audit_logs(self):
        self._login_as(self.admin_id, "Admin")
        self.assertEqual(self.client.get("/admin/").status_code, 200)
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

        response = self.client.post(
            f"/admin/users/{self.normal_user_id}/role",
            data={"role": User.ROLE_ANALYST},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            user = db.session.get(User, self.normal_user_id)
            self.assertEqual(user.role, User.ROLE_ANALYST)
            event = db.session.scalar(db.select(SystemLog).where(SystemLog.event == "user_role_changed"))
            self.assertIsNotNone(event)

        self.assertEqual(self.client.get("/admin/logs").status_code, 200)


if __name__ == "__main__":
    unittest.main()
