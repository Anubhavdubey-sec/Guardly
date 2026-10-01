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

    def test_account_profile_update(self):
        user = User(username="prof_user", email="prof@example.com", password=generate_password_hash("Password123456!"), role=User.ROLE_USER)
        user2 = User(username="other_user", email="other@example.com", password=generate_password_hash("Password123456!"), role=User.ROLE_USER)
        db.session.add_all([user, user2])
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["username"] = user.username

        # Successful profile update
        res = self.client.post("/account/profile", data={"username": "prof_updated", "email": "prof_new@example.com"}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/account", res.headers.get("Location", ""))

        db.session.refresh(user)
        self.assertEqual(user.username, "prof_updated")
        self.assertEqual(user.email, "prof_new@example.com")

        # Conflict check: cannot use another user's email or username
        conflict_res = self.client.post("/account/profile", data={"username": "other_user", "email": "prof_new@example.com"}, follow_redirects=False)
        self.assertEqual(conflict_res.status_code, 302)
        db.session.refresh(user)
        self.assertEqual(user.username, "prof_updated")

    def test_account_password_change(self):
        user = User(username="pwd_user", email="pwd@example.com", password=generate_password_hash("OldPassword123!"), role=User.ROLE_USER)
        db.session.add(user)
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["username"] = user.username

        # Invalid old password
        bad_res = self.client.post("/account/password", data={
            "old_password": "WrongPassword123!",
            "new_password": "NewStrongPassphrase123!",
            "confirm_password": "NewStrongPassphrase123!",
        }, follow_redirects=False)
        self.assertEqual(bad_res.status_code, 302)

        # Successful password update logs out user for re-authentication
        good_res = self.client.post("/account/password", data={
            "old_password": "OldPassword123!",
            "new_password": "NewStrongPassphrase123!",
            "confirm_password": "NewStrongPassphrase123!",
        }, follow_redirects=False)
        self.assertEqual(good_res.status_code, 302)
        self.assertIn("/login", good_res.headers.get("Location", ""))

    def test_mfa_setup_secret_persists_across_typos(self):
        user = User(username="mfa_typo_user", email="mfatypo@example.com", password=generate_password_hash("Password123456!"), role=User.ROLE_USER)
        db.session.add(user)
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["username"] = user.username

        # Initial setup visit generates secret
        self.client.get("/account/mfa/setup")
        with self.client.session_transaction() as sess:
            initial_secret = sess.get("pending_mfa_secret")
        self.assertIsNotNone(initial_secret)

        # User submits wrong code
        bad_post = self.client.post("/account/mfa/setup", data={"code": "000000"}, follow_redirects=False)
        self.assertEqual(bad_post.status_code, 302)

        # Following redirect back to setup MUST preserve the secret
        self.client.get("/account/mfa/setup")
        with self.client.session_transaction() as sess:
            second_secret = sess.get("pending_mfa_secret")
        self.assertEqual(initial_secret, second_secret)

        # Cancel clears the pending secret
        self.client.get("/account/mfa/cancel")
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("pending_mfa_secret"))

if __name__ == "__main__":
    unittest.main()

