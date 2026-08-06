"""
Guardly Password Validation & Security Policy Module
Enforces strict enterprise password requirements, common password rejection,
and live entropy/diversity strength estimation.
"""

import math
import re
from typing import List, Optional, Tuple

ALLOWED_SPECIAL_CHARS = set("!@#$%^&*()_+-={}[]:;\"'<>,.?/\\|~")

COMMON_PASSWORDS = {
    "password123",
    "password",
    "qwerty123",
    "admin123",
    "pass1234",
    "welcome123",
    "letmein123",
    "monkey123",
    "12345678",
    "123456789",
    "abc12345",
    "password1",
    "p@ssword1",
    "admin1234",
    "phishguard1",
    "guardly123",
}


def calculate_password_strength(
    password: str, username: Optional[str] = None, email: Optional[str] = None
) -> Tuple[str, int]:
    """
    Calculate live password strength (Weak, Medium, Strong, Excellent) and score (0-100).
    Based on length, character set diversity, common password detection, and entropy estimation.
    """
    if not password:
        return "Weak", 0

    pwd_lower = password.lower().strip()
    if pwd_lower in COMMON_PASSWORDS:
        return "Weak", 15
    if username and pwd_lower == username.lower().strip():
        return "Weak", 10
    if email and pwd_lower == email.lower().strip():
        return "Weak", 10

    if len(password) < 8 or len(password) > 12:
        return "Weak", 20

    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if any(c in ALLOWED_SPECIAL_CHARS for c in password):
        pool += len(ALLOWED_SPECIAL_CHARS)

    if pool == 0:
        return "Weak", 0

    entropy = len(password) * math.log2(pool)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = any(c in ALLOWED_SPECIAL_CHARS for c in password)
    no_spaces = not bool(re.search(r"\s", password))

    diversity_count = sum([has_upper, has_lower, has_digit, has_special, no_spaces])

    if diversity_count < 4 or entropy < 38:
        return "Weak", 30
    elif diversity_count < 5 or entropy < 48:
        return "Medium", 60
    elif entropy < 56:
        return "Strong", 85
    else:
        return "Excellent", 100


def validate_password(
    password: str, username: Optional[str] = None, email: Optional[str] = None
) -> Tuple[bool, List[str], str]:
    """
    Validate a password against Guardly strict security policy:
    - Length: 8 to 12 characters
    - Must contain: 1+ uppercase, 1+ lowercase, 1+ digit, 1+ special char
    - Rejects: spaces, identical to username/email, common passwords

    Returns tuple: (is_valid: bool, error_messages: List[str], strength: str)
    """
    errors: List[str] = []

    if not password:
        return False, ["Password is required."], "Weak"

    # Length Check
    if len(password) < 8 or len(password) > 12:
        errors.append("Password must be between 8 and 12 characters.")

    # Character Composition Checks
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one number.")

    if not any(c in ALLOWED_SPECIAL_CHARS for c in password):
        errors.append("Password must contain at least one special character.")

    if re.search(r"\s", password):
        errors.append("Password cannot contain spaces.")

    # Contextual & Common Password Checks
    pwd_lower = password.lower().strip()
    if username and pwd_lower == username.lower().strip():
        errors.append("Password cannot be identical to your username.")

    if email and pwd_lower == email.lower().strip():
        errors.append("Password cannot be identical to your email.")

    if pwd_lower in COMMON_PASSWORDS:
        errors.append("Password is too common or easily guessable.")

    strength, _ = calculate_password_strength(password, username, email)
    if errors and (len(password) < 8 or len(password) > 12 or pwd_lower in COMMON_PASSWORDS):
        strength = "Weak"

    return len(errors) == 0, errors, strength
