import os
import logging
from typing import Optional
from authlib.integrations.flask_client import OAuth
from flask import current_app

logger = logging.getLogger("guardly.oauth")

oauth = OAuth()


def init_oauth(app):
    """Initializes OAuth with Flask application."""
    oauth.init_app(app)

    client_id = (app.config.get("GOOGLE_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID", "")).strip().strip('"\'')
    client_secret = (app.config.get("GOOGLE_CLIENT_SECRET") or os.getenv("GOOGLE_CLIENT_SECRET", "")).strip().strip('"\'')

    if client_id and client_secret:
        oauth.register(
            name="google",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
        logger.info("Google OAuth provider registered successfully.")
    else:
        logger.info("Google OAuth client ID/Secret not set. Google Sign-In running in standby mode.")


def is_google_auth_configured() -> bool:
    """Returns True if Google Client ID and Secret are configured."""
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip().strip('"\'')
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip().strip('"\'')
    if current_app:
        client_id = (current_app.config.get("GOOGLE_CLIENT_ID") or client_id).strip().strip('"\'')
        client_secret = (current_app.config.get("GOOGLE_CLIENT_SECRET") or client_secret).strip().strip('"\'')
    return bool(client_id and client_secret)
