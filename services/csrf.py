import secrets
from flask import abort, current_app, request, session


def generate_csrf_token():
    """Generate or retrieve a cryptographically secure CSRF token for the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(token_to_check):
    """Validate the provided token against the current session's CSRF token."""
    session_token = session.get("csrf_token")
    if not session_token or not token_to_check:
        return False
    return secrets.compare_digest(session_token, token_to_check)


def init_csrf(app):
    """Register CSRF token generation context processor and before_request verification hook."""
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf_token)

    @app.before_request
    def csrf_protect():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return

        # Allow disabling CSRF in testing mode only
        if app.config.get("TESTING") and not app.config.get("WTF_CSRF_ENABLED", True):
            return

        # Token can be provided in form data or headers
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken")
        if not token or not validate_csrf_token(token):
            current_app.logger.warning(
                "CSRF validation failed for endpoint %s from IP %s",
                request.endpoint,
                request.remote_addr,
            )
            abort(403, description="CSRF token missing or invalid.")
