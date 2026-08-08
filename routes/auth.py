from functools import wraps

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from models.scan import EmailScan
from models.user import User, db
from services.audit import record_event
from services.limiter import limiter
from services.password_validator import validate_password


auth_bp = Blueprint("auth", __name__)


@auth_bp.app_context_processor
def inject_current_user():
    return {"current_user": getattr(g, "current_user", None)}


@auth_bp.before_app_request
def load_current_user():
    """Make the signed-in staff member available to both public and staff pages."""
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if user_id and (not user or user.role == User.ROLE_USER):
        session.clear()
        user = None
    g.current_user = user


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not getattr(g, "current_user", None):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped_view


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user or user.role not in allowed_roles:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("scanner.upload"))
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


@auth_bp.route("/")
def home():
    """Send every visitor straight to the no-account email scanner."""
    return redirect(url_for("scanner.upload"))


@auth_bp.route("/staff/login", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if getattr(g, "current_user", None) and g.current_user.role in {User.ROLE_ADMIN, User.ROLE_ANALYST}:
        return redirect(url_for("auth.dashboard"))
    if getattr(g, "current_user", None):
        session.clear()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.role in {User.ROLE_ADMIN, User.ROLE_ANALYST} and check_password_hash(user.password, password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            record_event("login_succeeded", target_type="user", target_id=user.id, detail="User logged in.", actor=user)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            return redirect(url_for("auth.dashboard"))

        record_event("login_failed", target_type="auth", detail="An invalid or disabled-account login attempt was rejected.", actor_name="Unknown")
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash("This sign-in is restricted to administrators and analysts.", "danger")

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    flash("Public email scanning does not require an account.", "info")
    return redirect(url_for("scanner.upload"))


@auth_bp.route("/dashboard")
@login_required
@roles_required(User.ROLE_ADMIN, User.ROLE_ANALYST)
def dashboard():
    user = g.current_user
    scans = EmailScan.query.filter_by(user_id=user.id).order_by(EmailScan.scan_time.desc()).all()
    scan_scope = "my reports"

    total_scans = len(scans)
    stats = {
        "total": total_scans,
        "high_risk": sum(scan.verdict == "High Risk" for scan in scans),
        "average_score": round(sum(scan.risk_score for scan in scans) / total_scans) if total_scans else 0,
    }
    return render_template(
        "dashboard.html",
        username=user.username,
        stats=stats,
        recent_scans=scans[:5],
        scan_scope=scan_scope,
    )


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = g.current_user
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")

        if not check_password_hash(user.password, old_password):
            flash("Current password is incorrect.", "danger")
            return render_template("change_password.html")

        is_valid, errors, strength = validate_password(new_password, username=user.username, email=user.email)
        if not is_valid:
            for err in errors:
                flash(err, "danger")
            return render_template("change_password.html")

        user.password = generate_password_hash(new_password)
        record_event("password_changed", target_type="user", target_id=user.id, detail="User changed password.", actor=user)
        try:
            db.session.commit()
            flash("Password updated successfully.", "success")
            return redirect(url_for("auth.dashboard"))
        except Exception as e:
            db.session.rollback()
            flash("Failed to update password.", "danger")

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
