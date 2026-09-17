import unittest
from services.password_validator import calculate_password_strength, validate_password


class PasswordValidationTests(unittest.TestCase):
    def test_valid_passwords(self):
        valid_cases = ["quiet meadow sunrise", "K9$mP2!x with more words", "Correct Horse Battery Staple"]
        for pwd in valid_cases:
            is_valid, errors, strength = validate_password(pwd)
            self.assertTrue(is_valid, f"Expected {pwd} to be valid, got errors: {errors}")
            self.assertEqual(errors, [])
            self.assertIn(strength, ["Medium", "Strong", "Excellent"])

    def test_boundary_values(self):
        # Exactly 12 characters
        is_valid_12, errors_12, _ = validate_password("twelve chars")
        self.assertTrue(is_valid_12, f"12-char boundary password rejected: {errors_12}")

    def test_too_short(self):
        is_valid, errors, strength = validate_password("P@1a")
        self.assertFalse(is_valid)
        self.assertTrue(any("at least 12 characters" in e for e in errors))
        self.assertEqual(strength, "Weak")

    def test_too_long(self):
        is_valid, errors, strength = validate_password("a" * 129)
        self.assertFalse(is_valid)
        self.assertTrue(any("no more than 128 characters" in e for e in errors))
        self.assertEqual(strength, "Weak")

    def test_passphrases_do_not_need_composition_rules(self):
        is_valid, errors, _ = validate_password("all lowercase passphrase")
        self.assertTrue(is_valid, errors)

    def test_common_passwords_rejection(self):
        common_cases = ["password123", "admin123", "qwerty123", "pass1234"]
        for pwd in common_cases:
            is_valid, errors, strength = validate_password(pwd)
            self.assertFalse(is_valid, f"Common password {pwd} was incorrectly accepted.")
            self.assertTrue(any("too common" in e for e in errors))
            self.assertEqual(strength, "Weak")

    def test_identical_to_username_or_email(self):
        is_valid_user, errors_user, _ = validate_password("AdminUser12!", username="AdminUser12!")
        self.assertFalse(is_valid_user)
        self.assertTrue(any("identical to your username" in e for e in errors_user))

        is_valid_email, errors_email, _ = validate_password("Admin@Ex.com!", email="Admin@Ex.com!")
        self.assertFalse(is_valid_email)
        self.assertTrue(any("identical to your email" in e for e in errors_email))


if __name__ == "__main__":
    unittest.main()
