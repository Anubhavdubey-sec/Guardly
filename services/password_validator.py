"""Password policy helpers for staff accounts.

The policy permits long passphrases and Unicode characters, while blocking weak
and contextual values. Privileged-account MFA is handled independently.
"""

import math
import re
from typing import List, Optional, Tuple


MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

COMMON_PASSWORDS = {
    "password123", "password", "qwerty123", "admin123", "pass1234",
    "welcome123", "letmein123", "monkey123", "12345678", "123456789",
    "abc12345", "password1", "p@ssword1", "admin1234", "phishguard1",
    "guardly123",
}


def _is_contextual_match(password: str, username: Optional[str], email: Optional[str]) -> bool:
    normalized = password.casefold().strip()
    return bool(
        (username and normalized == username.casefold().strip())
        or (email and normalized == email.casefold().strip())
    )


def _has_control_character(password: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in password)


def calculate_password_strength(
    password: str, username: Optional[str] = None, email: Optional[str] = None
) -> Tuple[str, int]:
    """Return a conservative passphrase-strength label and 0-100 score."""
    if not password:
        return "Weak", 0

    normalized = password.casefold().strip()
    if (
        normalized in COMMON_PASSWORDS
        or _is_contextual_match(password, username, email)
        or _has_control_character(password)
        or not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH
    ):
        return "Weak", 10

    unique_chars = len(set(password))
    categories = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]", r"\s")
    )
    estimated_entropy = len(password) * math.log2(max(2, unique_chars))
    score = min(100, round(32 + len(password) * 2 + categories * 5 + estimated_entropy / 6))

    if len(password) >= 20 or score >= 82:
        return "Excellent", score
    if len(password) >= 16 or score >= 65:
        return "Strong", score
    return "Medium", score


def validate_password(
    password: str, username: Optional[str] = None, email: Optional[str] = None
) -> Tuple[bool, List[str], str]:
    """Validate a long-passphrase policy without restrictive composition rules."""
    if not password:
        return False, ["Password is required."], "Weak"

    errors: List[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must be no more than {MAX_PASSWORD_LENGTH} characters long.")
    if _has_control_character(password):
        errors.append("Password cannot contain control characters.")

    normalized = password.casefold().strip()
    if username and normalized == username.casefold().strip():
        errors.append("Password cannot be identical to your username.")
    if email and normalized == email.casefold().strip():
        errors.append("Password cannot be identical to your email address.")
    if normalized in COMMON_PASSWORDS:
        errors.append("Password is too common or easily guessable.")

    strength, _ = calculate_password_strength(password, username, email)
    return not errors, errors, strength
