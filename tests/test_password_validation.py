import unittest
from services.password_validator import calculate_password_strength, validate_password


class PasswordValidationTests(unittest.TestCase):
    def test_valid_passwords(self):
        valid_cases = ["P@ssw0rd12", "A1#b2C3$d4", "K9$mP2!x"]
        for pwd in valid_cases:
            is_valid, errors, strength = validate_password(pwd)
            self.assertTrue(is_valid, f"Expected {pwd} to be valid, got errors: {errors}")
            self.assertEqual(errors, [])
            self.assertIn(strength, ["Strong", "Excellent"])

    def test_boundary_values(self):
        # Exactly 8 characters
        is_valid_8, errors_8, _ = validate_password("P@ssw0r1")
        self.assertTrue(is_valid_8, f"8-char boundary password rejected: {errors_8}")

        # Exactly 12 characters
        is_valid_12, errors_12, _ = validate_password("P@ssw0rd123!")
        self.assertTrue(is_valid_12, f"12-char boundary password rejected: {errors_12}")

    def test_too_short(self):
        is_valid, errors, strength = validate_password("P@1a")
        self.assertFalse(is_valid)
        self.assertTrue(any("between 8 and 12 characters" in e for e in errors))
        self.assertEqual(strength, "Weak")

    def test_too_long(self):
        is_valid, errors, strength = validate_password("P@ssword123456")
        self.assertFalse(is_valid)
        self.assertTrue(any("between 8 and 12 characters" in e for e in errors))
        self.assertEqual(strength, "Weak")

    def test_missing_uppercase(self):
        is_valid, errors, _ = validate_password("p@ssword123")
        self.assertFalse(is_valid)
        self.assertTrue(any("at least one uppercase letter" in e for e in errors))

    def test_missing_lowercase(self):
        is_valid, errors, _ = validate_password("P@SSWORD123")
        self.assertFalse(is_valid)
        self.assertTrue(any("at least one lowercase letter" in e for e in errors))

    def test_missing_number(self):
        is_valid, errors, _ = validate_password("P@ssword!@#")
        self.assertFalse(is_valid)
        self.assertTrue(any("at least one number" in e for e in errors))

    def test_missing_special_character(self):
        is_valid, errors, _ = validate_password("Password123")
        self.assertFalse(is_valid)
        self.assertTrue(any("at least one special character" in e for e in errors))

    def test_contains_spaces(self):
        is_valid, errors, _ = validate_password("P@ss word12")
        self.assertFalse(is_valid)
        self.assertTrue(any("cannot contain spaces" in e for e in errors))

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
