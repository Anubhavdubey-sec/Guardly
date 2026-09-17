import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from models.investigation_case import CaseIndicator, CaseNote, CaseScan, InvestigationCase
from models.scan import EmailScan
from models.system_log import SystemLog
from models.user import User, db


class CaseManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "case-management-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "UPLOAD_FOLDER": os.path.join(self.temp_directory.name, "uploads"),
            "PUBLIC_LOOKUPS_ENABLED": False,
        })
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            self.admin = User(username="Admin", email="admin@example.com", password="unused", role=User.ROLE_ADMIN)
            self.analyst = User(username="Analyst", email="analyst@example.com", password="unused", role=User.ROLE_USER)
            self.other_analyst = User(username="Other", email="other@example.com", password="unused", role=User.ROLE_USER)
            db.session.add_all([self.admin, self.analyst, self.other_analyst])
            db.session.flush()
            self.owned_scan = EmailScan(
                user_id=self.analyst.id,
                sender="billing@evil.example",
                receiver="victim@company.example",
                subject="Credential reset required",
                risk_score=85,
                verdict="High Risk",
                urls=json.dumps(["https://evil.example/login"]),
                iocs=json.dumps({"domains": ["evil.example"], "ip_addresses": ["198.51.100.10"]}),
            )
            self.other_scan = EmailScan(
                user_id=self.other_analyst.id,
                sender="other@private.example",
                subject="Other analyst private scan",
                risk_score=50,
                verdict="Medium Risk",
            )
            self.admin_scan = EmailScan(
                user_id=self.admin.id,
                sender="executive@private.example",
                receiver="security@company.example",
                subject="Admin-only private evidence",
                risk_score=92,
                verdict="High Risk",
            )
            db.session.add_all([self.owned_scan, self.other_scan, self.admin_scan])
            db.session.commit()
            self.admin_id = self.admin.id
            self.analyst_id = self.analyst.id
            self.other_analyst_id = self.other_analyst.id
            self.owned_scan_id = self.owned_scan.id
            self.other_scan_id = self.other_scan.id
            self.admin_scan_id = self.admin_scan.id
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

    def test_analyst_can_create_update_and_link_case_evidence(self):
        self._login_as(self.analyst_id, "Analyst")
        create_response = self.client.post(
            "/cases/new",
            data={
                "title": "Credential theft campaign",
                "status": "Investigating",
                "assigned_to_id": str(self.analyst_id),
                "tags": "Credential-Theft, VIP",
                "initial_note": "Reset affected credentials and review mailbox rules.",
                "verdict_override": "High Risk",
                "scan_ids": [str(self.owned_scan_id)],
            },
        )
        self.assertEqual(create_response.status_code, 302)

        with self.app.app_context():
            case = db.session.scalar(db.select(InvestigationCase))
            self.assertEqual(case.title, "Credential theft campaign")
            self.assertEqual(case.status, "Investigating")
            self.assertEqual(case.assigned_to_id, self.analyst_id)
            self.assertEqual(case.tags_list, ["credential-theft", "vip"])
            self.assertEqual(case.verdict_override, "High Risk")
            self.assertEqual(CaseScan.query.filter_by(case_id=case.id, scan_id=self.owned_scan_id).count(), 1)
            self.assertEqual(CaseNote.query.filter_by(case_id=case.id).count(), 1)
            linked_values = {indicator.value for indicator in CaseIndicator.query.filter_by(case_id=case.id)}
            self.assertEqual(linked_values, {"evil.example", "198.51.100.10", "https://evil.example/login"})
            case_id = case.id

        detail = self.client.get(f"/cases/{case_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"Credential theft campaign", detail.data)
        self.assertIn(b"evil.example", detail.data)

        add_indicator = self.client.post(
            f"/cases/{case_id}/indicators",
            data={"indicator_type": "hash", "value": "a" * 64},
        )
        self.assertEqual(add_indicator.status_code, 302)
        update = self.client.post(
            f"/cases/{case_id}/update",
            data={
                "title": "Credential theft campaign",
                "status": "Contained",
                "assigned_to_id": str(self.analyst_id),
                "tags": "credential-theft, contained",
                "verdict_override": "False Positive",
            },
        )
        self.assertEqual(update.status_code, 302)
        with self.app.app_context():
            case = db.session.get(InvestigationCase, case_id)
            self.assertEqual(case.status, "Contained")
            self.assertEqual(case.verdict_override, "False Positive")
            self.assertIn("contained", case.tags_list)
            self.assertEqual(CaseIndicator.query.filter_by(case_id=case_id, indicator_type="hash").count(), 1)

        note_response = self.client.post(f"/cases/{case_id}/notes", data={"body": "Sender blocked at the gateway."})
        self.assertEqual(note_response.status_code, 302)
        with self.app.app_context():
            notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.id).all()
            self.assertEqual([note.body for note in notes], [
                "Reset affected credentials and review mailbox rules.",
                "Sender blocked at the gateway.",
            ])

    def test_case_and_scan_access_are_isolated_between_analysts(self):
        self._login_as(self.analyst_id, "Analyst")
        response = self.client.post(
            "/cases/new",
            data={"title": "Private triage", "status": "Open", "tags": "private", "analyst_notes": "", "verdict_override": ""},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            case_id = db.session.scalar(db.select(InvestigationCase.id))

        forbidden_link = self.client.post(f"/cases/{case_id}/scans", data={"scan_id": str(self.other_scan_id)})
        self.assertEqual(forbidden_link.status_code, 404)

        self._login_as(self.other_analyst_id, "Other")
        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 404)

    def test_scan_report_offers_case_creation_to_staff_only(self):
        self._login_as(self.analyst_id, "Analyst")
        report = self.client.get(f"/scans/{self.owned_scan_id}")
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"Add to case", report.data)
        self.assertIn(f"/cases/new?scan_id={self.owned_scan_id}".encode(), report.data)

    def test_case_assignment_grants_linked_scan_access_without_opening_other_scans(self):
        self._login_as(self.admin_id, "Admin")
        create_response = self.client.post(
            "/cases/new",
            data={
                "title": "Executive incident",
                "status": "Investigating",
                "assigned_to_id": str(self.analyst_id),
                "tags": "executive",
                "scan_ids": [str(self.admin_scan_id)],
            },
        )
        self.assertEqual(create_response.status_code, 302)
        with self.app.app_context():
            case_id = db.session.scalar(db.select(InvestigationCase.id))

        self._login_as(self.analyst_id, "Analyst")
        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/scans/{self.admin_scan_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/scans/{self.other_scan_id}").status_code, 404)

        self_unassign = self.client.post(
            f"/cases/{case_id}/update",
            data={
                "title": "Executive incident",
                "status": "Investigating",
                "assigned_to_id": "",
                "tags": "executive",
                "verdict_override": "",
            },
        )
        self.assertEqual(self_unassign.status_code, 302)
        with self.app.app_context():
            self.assertEqual(db.session.get(InvestigationCase, case_id).assigned_to_id, self.analyst_id)
        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 200)

    def test_closed_case_rejects_evidence_mutations_and_validates_manual_iocs(self):
        self._login_as(self.analyst_id, "Analyst")
        response = self.client.post(
            "/cases/new",
            data={"title": "Closed triage", "status": "Open", "tags": "closed", "verdict_override": ""},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            case_id = db.session.scalar(db.select(InvestigationCase.id))

        invalid_ioc = self.client.post(
            f"/cases/{case_id}/indicators",
            data={"indicator_type": "ip_address", "value": "not-an-ip"},
        )
        self.assertEqual(invalid_ioc.status_code, 302)
        with self.app.app_context():
            self.assertEqual(CaseIndicator.query.filter_by(case_id=case_id).count(), 0)
            case = db.session.get(InvestigationCase, case_id)
            case.status = "Closed"
            db.session.commit()

        blocked = self.client.post(
            f"/cases/{case_id}/indicators",
            data={"indicator_type": "domain", "value": "evil.example"},
        )
        self.assertEqual(blocked.status_code, 302)
        with self.app.app_context():
            self.assertEqual(CaseIndicator.query.filter_by(case_id=case_id).count(), 0)

    def test_deactivation_retains_case_history_and_password_screen_renders(self):
        self._login_as(self.other_analyst_id, "Other")
        created = self.client.post(
            "/cases/new",
            data={
                "title": "Offboarded analyst case",
                "status": "Open",
                "assigned_to_id": str(self.other_analyst_id),
                "tags": "handover",
                "initial_note": "Preserve this timeline.",
                "verdict_override": "",
            },
        )
        self.assertEqual(created.status_code, 302)
        with self.app.app_context():
            case_id = db.session.scalar(db.select(InvestigationCase.id))

        self._login_as(self.admin_id, "Admin")
        deactivated = self.client.post(f"/admin/users/{self.other_analyst_id}/delete")
        self.assertEqual(deactivated.status_code, 302)
        with self.app.app_context():
            offboarded_user = db.session.get(User, self.other_analyst_id)
            case = db.session.get(InvestigationCase, case_id)
            self.assertFalse(offboarded_user.is_active)
            self.assertEqual(case.created_by_id, self.other_analyst_id)
            self.assertEqual(case.assigned_to_id, self.admin_id)
            self.assertEqual(CaseNote.query.filter_by(case_id=case_id, author_id=self.other_analyst_id).count(), 1)
            self.assertIsNotNone(db.session.scalar(db.select(SystemLog).where(SystemLog.event == "user_deactivated")))

        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 200)
        self._login_as(self.other_analyst_id, "Other")
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        self._login_as(self.analyst_id, "Analyst")
        change_password = self.client.get("/change-password")
        self.assertEqual(change_password.status_code, 200)
        self.assertIn(b"Change password", change_password.data)


if __name__ == "__main__":
    unittest.main()
