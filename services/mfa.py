"""
Guardly Multi-Factor Authentication (MFA) Subsystem.
Implements zero-dependency RFC 6238 Time-Based One-Time Password (TOTP)
and hashed recovery codes management using Python standard library.
"""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import urllib.parse
from typing import List, Optional, Tuple


def generate_mfa_secret() -> str:
    """
    Generates a cryptographically strong 160-bit base32-encoded secret key
    compatible with standard authenticator applications (Google Authenticator, etc.).
    """
    raw_bytes = os.urandom(20)
    return base64.b32encode(raw_bytes).decode("ascii")


def get_totp_uri(secret: str, username: str, issuer: str = "Guardly") -> str:
    """
    Constructs a standard otpauth:// URI for QR code generation or authenticator apps.
    """
    label = f"{issuer}:{username}"
    params = {
        "secret": secret.upper().strip(),
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
    return f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"


def compute_totp(secret: str, timestamp: Optional[float] = None, interval: int = 30, digits: int = 6) -> str:
    """
    Computes an RFC 6238 TOTP passcode for the given base32 secret and timestamp.
    """
    if timestamp is None:
        timestamp = time.time()

    counter = int(timestamp // interval)
    cleaned_secret = secret.strip().replace(" ", "").upper()
    # Add padding if needed
    missing_padding = len(cleaned_secret) % 8
    if missing_padding:
        cleaned_secret += "=" * (8 - missing_padding)

    key = base64.b32decode(cleaned_secret, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return f"{code:0{digits}d}"


def verify_totp(secret: str, code: str, window: int = 1, interval: int = 30) -> bool:
    """
    Validates a 6-digit TOTP passcode against the secret key.
    Checks the current time step and +/- window time steps to handle clock skew.
    """
    if not secret or not code:
        return False

    clean_code = str(code).strip().replace(" ", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    now = time.time()
    for step_offset in range(-window, window + 1):
        step_time = now + (step_offset * interval)
        try:
            expected = compute_totp(secret, timestamp=step_time, interval=interval, digits=6)
            if hmac.compare_digest(expected, clean_code):
                return True
        except Exception:
            continue

    return False


def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[str]]:
    """
    Generates a set of one-time emergency recovery codes.
    Returns (plain_codes, hashed_codes).
    Only hashed codes should be saved to the database.
    """
    plain_codes = []
    hashed_codes = []

    for _ in range(count):
        # Format: xxxx-xxxx (alphanumeric)
        chunk1 = secrets.token_hex(2).upper()
        chunk2 = secrets.token_hex(2).upper()
        code = f"{chunk1}-{chunk2}"
        plain_codes.append(code)

        # SHA-256 hash for secure storage
        h = hashlib.sha256(code.encode("utf-8")).hexdigest()
        hashed_codes.append(h)

    return plain_codes, hashed_codes


def hash_recovery_code(code: str) -> str:
    """Hashes a recovery code for comparison."""
    clean = str(code).strip().upper()
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()
