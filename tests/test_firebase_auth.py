"""
Unit & Integration Test Suite for Guardly Authentication Upgrade (Google Sign-In & Phone OTP).
Tests Existing Username/Password Login, Google ID Token Verification, Phone OTP Token Verification,
Account Linking for Existing Users, New User Creation, Inactive User Rejection, Tenant/Role Security,
Session Creation, and Backward Compatibility.
"""

import unittest
from werkzeug.security import generate_password_hash

from app import create_app
from models.user import User, db
from services.firebase_auth import (
    verify_firebase_id_token,
    get_or_create_firebase_user,
)


class FirebaseAuthUnitAndIntegrationTests(unittest.TestCase):
    """Unit and Integration Tests for Firebase Authentication (Google & Phone OTP)."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "WTF_CSRF_ENABLED": False})
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.client = self.app.test_client()

        # Seed existing staff users
        self.admin = User(
            username="admin_user",
            email="admin@guardly.sec",
            password=generate_password_hash("AdminPass123!"),
            role=User.ROLE_ADMIN,
            tenant_id="Tenant_A",
            auth_provider=User.AUTH_PASSWORD,
        )
        self.analyst = User(
            username="analyst_user",
            email="analyst@guardly.sec",
            password=generate_password_hash("AnalystPass123!"),
            role=User.ROLE_ANALYST,
            tenant_id="Tenant_A",
            auth_provider=User.AUTH_PASSWORD,
        )
        db.session.add(self.admin)
        db.session.add(self.analyst)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_existing_password_login_preserved(self):
        res = self.client.post("/login", data={"email": "admin@guardly.sec", "password": "AdminPass123!"}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/dashboard", res.location)

    def test_google_token_verification_valid(self):
        claims = verify_firebase_id_token("mock_token_google_valid_user@guardly.sec")
        self.assertEqual(claims["provider"], User.AUTH_GOOGLE)
        self.assertEqual(claims["email"], "valid_user@guardly.sec")
        self.assertIsNotNone(claims["uid"])

    def test_google_token_verification_invalid(self):
        with self.assertRaises(ValueError):
            verify_firebase_id_token("mock_token_invalid_123")

    def test_google_token_verification_expired(self):
        with self.assertRaises(ValueError):
            verify_firebase_id_token("mock_token_expired_123")

    def test_phone_authentication_token_valid(self):
        claims = verify_firebase_id_token("mock_token_phone_+15550199")
        self.assertEqual(claims["provider"], User.AUTH_PHONE)
        self.assertEqual(claims["phone_number"], "+15550199")
        self.assertIsNotNone(claims["uid"])

    def test_account_linking_existing_email(self):
        # User analyst@guardly.sec exists with password auth
        claims = {
            "uid": "google_uid_analyst_999",
            "email": "analyst@guardly.sec",
            "phone_number": None,
            "provider": User.AUTH_GOOGLE,
        }
        user, created = get_or_create_firebase_user(claims)
        self.assertFalse(created)
        self.assertEqual(user.id, self.analyst.id)
        self.assertEqual(user.firebase_uid, "google_uid_analyst_999")
        self.assertEqual(user.auth_provider, User.AUTH_GOOGLE)

        # Check DB user count hasn't duplicated
        self.assertEqual(User.query.filter_by(email="analyst@guardly.sec").count(), 1)

    def test_new_user_creation_via_google(self):
        claims = {
            "uid": "google_new_uid_001",
            "email": "new_staff@company.com",
            "phone_number": None,
            "provider": User.AUTH_GOOGLE,
        }
        user, created = get_or_create_firebase_user(claims)
        self.assertTrue(created)
        self.assertEqual(user.email, "new_staff@company.com")
        self.assertEqual(user.role, User.ROLE_USER)
        self.assertEqual(user.tenant_id, "default")

    def test_new_user_creation_via_phone(self):
        claims = {
            "uid": "phone_new_uid_002",
            "email": None,
            "phone_number": "+15559988",
            "provider": User.AUTH_PHONE,
        }
        user, created = get_or_create_firebase_user(claims)
        self.assertTrue(created)
        self.assertEqual(user.phone_number, "+15559988")
        self.assertEqual(user.role, User.ROLE_USER)

    def test_new_unprivileged_user_login_rejected_and_admin_promotion_workflow(self):
        # 1. Brand new Google user attempts login
        res = self.client.post("/auth/firebase", json={"id_token": "mock_token_google_unprivileged@company.com"})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("restricted to staff members", data["error"].lower())

        # 2. Verify user was created in DB with non-privileged ROLE_USER
        new_user = User.query.filter_by(email="unprivileged@company.com").first()
        self.assertIsNotNone(new_user)
        self.assertEqual(new_user.role, User.ROLE_USER)

        # 3. Admin promotes user to ANALYST
        new_user.role = User.ROLE_ANALYST
        db.session.commit()

        # 4. Same Firebase user logs in again -> Now succeeds with 200
        res_after = self.client.post("/auth/firebase", json={"id_token": "mock_token_google_unprivileged@company.com"})
        self.assertEqual(res_after.status_code, 200)
        data_after = res_after.get_json()
        self.assertTrue(data_after["success"])
        self.assertIn("dashboard", data_after["redirect_url"])

    def test_firebase_login_api_endpoint_success_for_staff(self):
        # Existing staff user analyst@guardly.sec logs in via Firebase
        res = self.client.post("/auth/firebase", json={"id_token": "mock_token_google_analyst@guardly.sec"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("dashboard", data["redirect_url"])

        # Access dashboard with created session
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn("Dashboard", dash_res.get_data(as_text=True))

    def test_firebase_login_api_endpoint_missing_token(self):
        res = self.client.post("/auth/firebase", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])

    def test_inactive_user_rejected(self):
        self.analyst.is_active = False
        db.session.commit()

        res = self.client.post("/auth/firebase", json={"id_token": "mock_token_google_analyst@guardly.sec"})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("disabled", data["error"].lower())

    def test_tenant_and_role_client_forgery_prevention(self):
        # Client tries to pass malicious tenant_id or admin role in payload
        res = self.client.post("/auth/firebase", json={
            "id_token": "mock_token_google_newstaff@company.com",
            "tenant_id": "Tenant_B_Unauthorized",
            "role": "admin"
        })
        self.assertEqual(res.status_code, 403)  # Rejected because created with ROLE_USER

        # Verify Guardly server ignored forged payload and assigned trusted DB values
        new_user = User.query.filter_by(email="newstaff@company.com").first()
        self.assertIsNotNone(new_user)
        self.assertEqual(new_user.tenant_id, "default")
        self.assertEqual(new_user.role, User.ROLE_USER)


if __name__ == "__main__":
    unittest.main()
