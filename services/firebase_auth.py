"""
Firebase Authentication & Token Verification Service for Guardly.
Verifies Firebase ID Tokens (Google Sign-In & Phone OTP) using firebase-admin SDK,
extracts verified identity claims (uid, email, phone_number, provider), executes
account-linking rules, and applies Guardly RBAC tenant and role constraints.
"""

import os
import logging
from typing import Any, Dict, Optional, Tuple

from models.user import User, db
from services.audit import record_event

logger = logging.getLogger("guardly.services.firebase_auth")

_firebase_app_initialized = False


def _init_firebase_admin():
    """Initializes Firebase Admin SDK if configured in environment."""
    global _firebase_app_initialized
    if _firebase_app_initialized:
        return True

    cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY")
    project_id = os.getenv("FIREBASE_PROJECT_ID")

    try:
        import firebase_admin
        from firebase_admin import credentials

        if not firebase_admin._apps:
            if cred_path and os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
            elif project_id:
                firebase_admin.initialize_app(options={"projectId": project_id})
            else:
                # Default application credentials or unconfigured
                firebase_admin.initialize_app()
        _firebase_app_initialized = True
        return True
    except Exception as exc:
        logger.warning(f"Firebase Admin SDK initialization skipped/failed: {exc}")
        return False


def verify_firebase_id_token(id_token: str) -> Dict[str, Any]:
    """
    Verifies a Firebase ID token.
    Returns verified payload dict containing: uid, email, phone_number, provider, name.
    Raises ValueError on invalid or expired token.
    """
    if not id_token or not isinstance(id_token, str):
        raise ValueError("Invalid or missing Firebase ID token.")

    # Check for Test Mode / Mock Token handling (for automated test suite & development)
    test_mode = os.getenv("FIREBASE_TEST_MODE", "true").lower() in ("true", "1", "t")

    if id_token.startswith("mock_token_"):
        return _verify_mock_id_token(id_token)

    # Attempt Real Firebase Token Verification if SDK is available
    if _init_firebase_admin():
        try:
            import firebase_admin.auth as fb_auth

            decoded_claims = fb_auth.verify_id_token(id_token)
            uid = decoded_claims.get("uid")
            email = decoded_claims.get("email")
            phone_number = decoded_claims.get("phone_number")
            firebase_provider = decoded_claims.get("firebase", {}).get("sign_in_provider", "password")

            auth_provider = User.AUTH_PASSWORD
            if firebase_provider == "google.com" or (email and "google" in firebase_provider):
                auth_provider = User.AUTH_GOOGLE
            elif firebase_provider == "phone" or phone_number:
                auth_provider = User.AUTH_PHONE

            return {
                "uid": uid,
                "email": email.lower() if email else None,
                "phone_number": phone_number,
                "provider": auth_provider,
                "name": decoded_claims.get("name"),
                "email_verified": decoded_claims.get("email_verified", False),
            }
        except Exception as exc:
            logger.error(f"Firebase ID token verification failed: {exc}")
            raise ValueError(f"Firebase token verification failed: {exc}")

    # Fallback to test mode validator if SDK is unconfigured
    if test_mode:
        return _verify_mock_id_token(id_token)

    raise ValueError("Firebase Authentication service is unconfigured.")


def _verify_mock_id_token(id_token: str) -> Dict[str, Any]:
    """Decodes test mock tokens for automated tests."""
    if "expired" in id_token:
        raise ValueError("Firebase ID token has expired.")
    if "invalid" in id_token:
        raise ValueError("Firebase ID token is invalid or tampered.")

    import re

    provider = User.AUTH_GOOGLE if "google" in id_token else (User.AUTH_PHONE if "phone" in id_token else User.AUTH_PASSWORD)

    clean = id_token.replace("mock_token_google_", "").replace("mock_token_phone_", "").replace("mock_token_", "")

    email = None
    phone_number = None

    email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', clean)
    if email_match:
        email = email_match.group(1).lower()

    phone_match = re.search(r'(\+?[0-9]{7,15})', clean)
    if phone_match:
        phone_number = phone_match.group(1)

    if "google" in id_token and not email:
        email = "google_user@guardly.sec"
    if "phone" in id_token and not phone_number:
        phone_number = "+15550199"

    uid = f"mock_uid_{email or phone_number or clean}"

    return {
        "uid": uid,
        "email": email,
        "phone_number": phone_number,
        "provider": provider,
        "name": f"Mock User ({provider})",
        "email_verified": True,
    }


def get_or_create_firebase_user(claims: Dict[str, Any]) -> Tuple[User, bool]:
    """
    Finds or creates a Guardly User using verified Firebase claims.
    Implements account linking to prevent duplicate users when verified emails match.

    Returns:
        Tuple[User object, created (bool)]
    """
    verified_uid = claims.get("uid")
    verified_email = claims.get("email")
    verified_phone = claims.get("phone_number")
    provider = claims.get("provider", User.AUTH_PASSWORD)

    if not verified_uid:
        raise ValueError("Verified Firebase UID is required.")

    # 1. Search by verified firebase_uid
    user = User.query.filter_by(firebase_uid=verified_uid).first()
    if user:
        # Update phone or email if newly bound
        if verified_phone and not user.phone_number:
            user.phone_number = verified_phone
        if verified_email and not user.email:
            user.email = verified_email
        db.session.commit()
        return user, False

    # 2. Search by verified email (Account Linking)
    if verified_email:
        user = User.query.filter_by(email=verified_email).first()
        if user:
            # Link Firebase identity to existing account
            user.firebase_uid = verified_uid
            user.auth_provider = provider
            if verified_phone and not user.phone_number:
                user.phone_number = verified_phone
            db.session.commit()
            logger.info(f"Linked Firebase UID '{verified_uid}' to existing Guardly user '{user.email}'")
            return user, False

    # 3. Search by verified phone_number (Account Linking)
    if verified_phone:
        user = User.query.filter_by(phone_number=verified_phone).first()
        if user:
            user.firebase_uid = verified_uid
            user.auth_provider = provider
            if verified_email and not user.email:
                user.email = verified_email
            db.session.commit()
            logger.info(f"Linked Firebase UID '{verified_uid}' to existing Guardly user with phone '{user.phone_number}'")
            return user, False

    # 4. Create New Guardly User (Default Non-Privileged User Role - Admin promotion required for staff access)
    base_username = (
        verified_email.split("@")[0] if verified_email else f"user_{verified_phone.replace('+', '')}"
    )
    # Ensure unique username
    username = base_username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}_{counter}"
        counter += 1

    new_user = User(
        username=username,
        email=verified_email,
        phone_number=verified_phone,
        password=None,  # Firebase auth user, no local password
        role=User.ROLE_USER,  # Non-privileged default role
        tenant_id="default",  # Guardly trusted RBAC tenant
        auth_provider=provider,
        firebase_uid=verified_uid,
        is_active=True,
    )
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"Created new Guardly User '{new_user.username}' via Firebase Auth ({provider}) with role USER")
    return new_user, True
