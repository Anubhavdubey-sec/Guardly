import json
import unittest
from werkzeug.security import generate_password_hash
from app import create_app
from models.scan import EmailScan
from models.user import User, db
from services.mfa import compute_totp, generate_mfa_secret

class ConsumerAuthTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
        })
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_consumer_registration_and_auto_login(self):
        # Register new personal account
        res = self.client.post(
            "/register",
            data={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "StrongPassword123!",
                "confirm_password": "StrongPassword123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertIn("/dashboard", res.headers.get("Location", ""))

        with self.client.session_transaction() as sess:
            self.assertIsNotNone(sess.get("user_id"))
            self.assertEqual(sess.get("username"), "newuser")

        created = User.query.filter_by(username="newuser").first()
        self.assertIsNotNone(created)
        self.assertEqual(created.role, User.ROLE_USER)

    def test_registration_validation_errors(self):
        # Mismatched passwords
        res = self.client.post(
            "/register",
            data={
                "username": "badpass",
                "email": "badpass@example.com",
                "password": "StrongPassword123!",
                "confirm_password": "DifferentPassword123!",
            },
        )
        self.assertEqual(res.status_code, 400)

        # Invalid email
        res = self.client.post(
            "/register",
            data={
                "username": "bademail",
                "email": "not-an-email",
                "password": "StrongPassword123!",
                "confirm_password": "StrongPassword123!",
            },
        )
        self.assertEqual(res.status_code, 400)

    def test_mfa_setup_and_login_flow(self):
        # Create user
        user = User(username="mfa_user", email="mfa@example.com", password=generate_password_hash("Password123456!"), role=User.ROLE_USER)
        db.session.add(user)
        db.session.commit()

        # Login
        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["username"] = user.username

        # Initiate setup
        setup_page = self.client.get("/account/mfa/setup")
        self.assertEqual(setup_page.status_code, 200)

        with self.client.session_transaction() as sess:
            secret = sess.get("pending_mfa_secret")
        self.assertIsNotNone(secret)

        # Verify OTP
        otp = compute_totp(secret)
        verify_res = self.client.post("/account/mfa/setup", data={"code": otp})
        self.assertEqual(verify_res.status_code, 200)

        db.session.refresh(user)
        self.assertTrue(user.mfa_enabled)
        self.assertIsNotNone(user.mfa_secret)
        self.assertIsNotNone(user.mfa_recovery_codes)

        # Logout
        self.client.post("/logout")

        # Login step 1: primary credentials
        login_res = self.client.post("/login", data={"email": "mfa@example.com", "password": "Password123456!"}, follow_redirects=False)
        self.assertEqual(login_res.status_code, 302)
        self.assertIn("/login/mfa", login_res.headers.get("Location", ""))

        # Login step 2: invalid OTP rejected
        bad_otp = self.client.post("/login/mfa", data={"otp": "000000"})
        self.assertEqual(bad_otp.status_code, 401)

        # Login step 2: valid OTP accepted
        current_otp = compute_totp(user.mfa_secret)
        good_otp = self.client.post("/login/mfa", data={"otp": current_otp}, follow_redirects=False)
        self.assertEqual(good_otp.status_code, 302)
        self.assertIn("/dashboard", good_otp.headers.get("Location", ""))

    def test_account_deletion_purges_personal_scans(self):
        user = User(username="del_user", email="del@example.com", password=generate_password_hash("Password123456!"), role=User.ROLE_USER)
        db.session.add(user)
        db.session.commit()

        scan = EmailScan(user_id=user.id, subject="To be deleted", risk_score=0, verdict="Low Risk")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["username"] = user.username

        # Delete account with correct password
        del_res = self.client.post("/account/delete", data={"password": "Password123456!"}, follow_redirects=False)
        self.assertEqual(del_res.status_code, 302)

        # Verify user and scans are gone
        self.assertIsNone(User.query.filter_by(username="del_user").first())
        self.assertIsNone(db.session.get(EmailScan, scan_id))

if __name__ == "__main__":
    unittest.main()
