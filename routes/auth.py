import json
import re
import time
from functools import wraps

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from models.scan import EmailScan
from models.user import User, db
from services.audit import record_event
from services.limiter import limiter
from services.mfa import (
    generate_mfa_secret,
    generate_recovery_codes,
    get_totp_uri,
    hash_recovery_code,
    verify_totp,
)
from services.password_validator import validate_password

auth_bp = Blueprint("auth", __name__)


@auth_bp.app_context_processor
def inject_current_user():
    return {"current_user": getattr(g, "current_user", None)}


@auth_bp.before_app_request
def load_current_user():
    """Make the signed-in user available to both public and authenticated pages."""
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if user_id and (not user or not user.is_active):
        session.clear()
        user = None
    g.current_user = user


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not getattr(g, "current_user", None):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped_view


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user or user.role not in allowed_roles:
                flash("You do not have permission to access that resource.", "danger")
                return redirect(url_for("scanner.upload"))
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


@auth_bp.route("/")
def home():
    """Send visitors straight to the no-account email scanner."""
    return redirect(url_for("scanner.upload"))


@auth_bp.route("/staff/login", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if getattr(g, "current_user", None):
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and not user.is_active:
            record_event(
                "login_failed",
                target_type="auth",
                detail=f"Deactivated account login attempt for {email}.",
                actor_name="Unknown",
            )
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash("This account has been deactivated. Please contact an administrator.", "danger")
            return render_template("login.html"), 403

        if user and check_password_hash(user.password, password):
            # MFA Enforcement: If MFA is enabled, require second factor verification
            if user.mfa_enabled:
                session.clear()
                session["mfa_pending_user_id"] = user.id
                session["mfa_pending_expires"] = time.time() + 300  # 5 minutes expiry
                record_event(
                    "mfa_prompted",
                    target_type="user",
                    target_id=user.id,
                    detail="Password correct. Prompted for MFA OTP.",
                    actor=user,
                )
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                return redirect(url_for("auth.login_mfa"))

            # Standard successful authentication
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session.permanent = True
            record_event("login_succeeded", target_type="user", target_id=user.id, detail="User logged in.", actor=user)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("auth.dashboard"))

        record_event("login_failed", target_type="auth", detail="Invalid login attempt.", actor_name="Unknown")
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/login/mfa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login_mfa():
    """Second-factor verification step for accounts with MFA enabled."""
    pending_user_id = session.get("mfa_pending_user_id")
    expires = session.get("mfa_pending_expires", 0)

    if not pending_user_id or expires < time.time():
        session.clear()
        flash("Your authentication session has expired. Please sign in again.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_user_id)
    if not user or not user.is_active or not user.mfa_enabled:
        session.clear()
        flash("MFA session is invalid. Please sign in again.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        # 1. Check TOTP Passcode
        if user.mfa_secret and verify_totp(user.mfa_secret, otp):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session.permanent = True
            record_event("mfa_login_succeeded", target_type="user", target_id=user.id, detail="TOTP verified.", actor=user)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("auth.dashboard"))

        # 2. Check Emergency Recovery Codes
        if user.mfa_recovery_codes:
            try:
                recovery_hashes = json.loads(user.mfa_recovery_codes)
            except Exception:
                recovery_hashes = []

            input_hash = hash_recovery_code(otp)
            if input_hash in recovery_hashes:
                recovery_hashes.remove(input_hash)
                user.mfa_recovery_codes = json.dumps(recovery_hashes)
                session.clear()
                session["user_id"] = user.id
                session["username"] = user.username
                session.permanent = True
                record_event(
                    "mfa_recovery_code_used",
                    target_type="user",
                    target_id=user.id,
                    detail=f"Emergency recovery code used ({len(recovery_hashes)} remaining).",
                    actor=user,
                )
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                flash("Emergency recovery code verified. Please generate new recovery codes in your account settings.", "warning")
                return redirect(url_for("auth.dashboard"))

        record_event("mfa_login_failed", target_type="user", target_id=user.id, detail="Invalid OTP entered.", actor=user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash("Invalid authentication code or recovery code.", "danger")
        return render_template("login_mfa.html", error="Invalid verification code."), 401

    return render_template("login_mfa.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if getattr(g, "current_user", None):
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Required field validation
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", username=username, email=email), 400

        # 2. Username format and length
        if len(username) < 3 or len(username) > 80:
            flash("Username must be between 3 and 80 characters.", "danger")
            return render_template("register.html", username=username, email=email), 400

        if not re.match(r"^[a-zA-Z0-9_\.\-]+$", username):
            flash("Username may contain only letters, numbers, hyphens, periods, and underscores.", "danger")
            return render_template("register.html", username=username, email=email), 400

        # 3. Email syntax and length
        if len(email) > 120 or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", username=username, email=email), 400

        # 4. Password confirmation match
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email), 400

        # 5. Password complexity validation
        is_valid, errors, _ = validate_password(password, username=username, email=email)
        if not is_valid:
            for err in errors:
                flash(err, "danger")
            return render_template("register.html", username=username, email=email), 400

        # 6. Duplicate account check
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash("An account with that email or username already exists.", "danger")
            return render_template("register.html", username=username, email=email), 400

        # 7. Create user account with salted hash
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=User.ROLE_USER,
            is_active=True,
        )
        db.session.add(user)
        db.session.flush()

        record_event(
            "user_registered",
            target_type="user",
            target_id=user.id,
            detail=f"Personal user account registered: {username}.",
            actor=user,
        )

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Failed to create account. Please try again.", "danger")
            return render_template("register.html"), 500

        # 8. Log in newly created user
        session.clear()
        session["user_id"] = user.id
        session["username"] = user.username
        session.permanent = True
        flash("Welcome to Guardly! Your personal account has been created.", "success")
        return redirect(url_for("auth.dashboard"))

    return render_template("register.html")


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    """Personal Security Dashboard: displays strictly the authenticated user's own scans."""
    user = g.current_user
    scans = EmailScan.query.filter_by(user_id=user.id).order_by(EmailScan.scan_time.desc()).all()

    total_scans = len(scans)
    high_risk = sum(1 for scan in scans if scan.verdict == "High Risk")
    medium_risk = sum(1 for scan in scans if scan.verdict == "Medium Risk")
    low_risk = sum(1 for scan in scans if scan.verdict == "Low Risk")
    avg_score = round(sum(scan.risk_score for scan in scans) / total_scans) if total_scans else 0

    stats = {
        "total": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "average_score": avg_score,
    }

    return render_template(
        "dashboard.html",
        username=user.username,
        stats=stats,
        recent_scans=scans[:5],
    )


@auth_bp.route("/account", methods=["GET"])
@login_required
def account():
    """Personal Account Settings & Security Management."""
    user = g.current_user
    scans_count = EmailScan.query.filter_by(user_id=user.id).count()
    return render_template("account.html", user=user, scans_count=scans_count)


@auth_bp.route("/account/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    """Initializes MFA secret and presents authenticator URI / verification challenge."""
    user = g.current_user
    if user.mfa_enabled:
        flash("MFA is already enabled on your account.", "info")
        return redirect(url_for("auth.account"))

    if request.method == "POST":
        secret = session.get("pending_mfa_secret")
        code = request.form.get("code", "").strip()

        if not secret or not verify_totp(secret, code):
            flash("Invalid authentication code. Please ensure your authenticator app is synced.", "danger")
            return redirect(url_for("auth.mfa_setup"))

        # Generate emergency recovery codes
        plain_recovery, hashed_recovery = generate_recovery_codes(8)

        user.mfa_secret = secret
        user.mfa_enabled = True
        user.mfa_recovery_codes = json.dumps(hashed_recovery)
        session.pop("pending_mfa_secret", None)

        record_event("mfa_enabled", target_type="user", target_id=user.id, detail="User enabled MFA.", actor=user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Failed to activate MFA.", "danger")
            return redirect(url_for("auth.account"))

        flash("Two-Factor Authentication is now enabled! Save your recovery codes in a safe place.", "success")
        return render_template("account.html", user=user, recovery_codes=plain_recovery, show_recovery=True)

    # GET: Generate temporary secret and show setup instructions
    secret = generate_mfa_secret()
    session["pending_mfa_secret"] = secret
    totp_uri = get_totp_uri(secret, user.username)

    return render_template("account.html", user=user, mfa_setup_secret=secret, totp_uri=totp_uri, show_setup=True)


@auth_bp.route("/account/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    """Disables MFA after re-authenticating with current password."""
    user = g.current_user
    password = request.form.get("password", "")

    if not check_password_hash(user.password, password):
        flash("Current password is required to disable Multi-Factor Authentication.", "danger")
        return redirect(url_for("auth.account"))

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_codes = None

    record_event("mfa_disabled", target_type="user", target_id=user.id, detail="User disabled MFA.", actor=user)
    try:
        db.session.commit()
        flash("Multi-Factor Authentication has been disabled.", "info")
    except Exception:
        db.session.rollback()
        flash("Failed to disable MFA.", "danger")

    return redirect(url_for("auth.account"))


@auth_bp.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    """Allows a registered user to delete their own account and personal scan data."""
    user = g.current_user
    password = request.form.get("password", "")

    if not check_password_hash(user.password, password):
        flash("Current password is required to delete your account.", "danger")
        return redirect(url_for("auth.account"))

    # Protect against deleting the last administrator
    if user.role == User.ROLE_ADMIN:
        admin_count = User.query.filter_by(role=User.ROLE_ADMIN, is_active=True).count()
        if admin_count <= 1:
            flash("Cannot delete the last remaining administrator account.", "danger")
            return redirect(url_for("auth.account"))

    user_id = user.id
    username = user.username

    # Delete all scans owned by this user
    EmailScan.query.filter_by(user_id=user_id).delete()

    # Delete user record
    db.session.delete(user)
    record_event("account_deleted", target_type="user", target_id=user_id, detail=f"User {username} deleted their account.", actor_name=username)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash("Failed to delete account.", "danger")
        return redirect(url_for("auth.account"))

    session.clear()
    flash("Your account and all associated personal scan data have been permanently deleted.", "info")
    return redirect(url_for("scanner.upload"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = g.current_user
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not check_password_hash(user.password, old_password):
            flash("Current password is incorrect.", "danger")
            return render_template("change_password.html")

        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "danger")
            return render_template("change_password.html")

        is_valid, errors, _strength = validate_password(new_password, username=user.username, email=user.email)
        if not is_valid:
            for err in errors:
                flash(err, "danger")
            return render_template("change_password.html")

        user.password = generate_password_hash(new_password)
        record_event("password_changed", target_type="user", target_id=user.id, detail="User changed password.", actor=user)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Failed to update password.", "danger")
            return render_template("change_password.html")

        # Session invalidation after password change for security
        session.clear()
        flash("Password updated successfully. Please sign in with your new password.", "success")
        return redirect(url_for("auth.login"))

    return render_template("change_password.html")


@auth_bp.route("/api/v1/password/validate", methods=["POST"])
def validate_password_api():
    """Live password validation API endpoint for real-time frontend feedback & strength meter."""
    data = request.get_json(silent=True) or request.form
    password = data.get("password", "")
    username = data.get("username", "")
    email = data.get("email", "")

    is_valid, errors, strength = validate_password(password, username=username, email=email)
    return {
        "valid": is_valid,
        "errors": errors,
        "strength": strength,
    }


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user = g.current_user
    record_event("logout", target_type="user", target_id=user.id, detail="User logged out.", actor=user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
