from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from models.scan import EmailScan
from models.system_log import SystemLog
from models.user import User, db
from routes.auth import login_required, roles_required
from services.audit import record_event
from services.password_validator import validate_password

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_bp.route("/dashboard")
@login_required
@roles_required(User.ROLE_ADMIN)
def dashboard():
    # Import Mail Enforcement Models (Module 4)
    from models.policy import MailDecision, MailQuarantine
    from models.email_message import EmailMessage

    users_count = User.query.count()
    scans_count = EmailScan.query.count()
    high_risk_count = EmailScan.query.filter_by(verdict="High Risk").count()
    recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(10).all()

    total_received = EmailMessage.query.count()
    allowed_count = MailDecision.query.filter_by(decision="ALLOW").count()
    review_count = EmailMessage.query.filter_by(status="REVIEW").count()
    quarantined_count = MailQuarantine.query.filter_by(status="QUARANTINED").count()
    rejected_count = MailDecision.query.filter_by(decision="REJECT").count()
    recent_decisions = MailDecision.query.order_by(MailDecision.created_at.desc()).limit(10).all()

    stats = {
        "users": users_count,
        "scans": scans_count,
        "high_risk": high_risk_count,
        "total_received": total_received,
        "allowed": allowed_count,
        "review": review_count,
        "quarantined": quarantined_count,
        "rejected": rejected_count,
    }
    return render_template("admin_dashboard.html", stats=stats, recent_logs=recent_logs, recent_decisions=recent_decisions)


@admin_bp.route("/users")
@login_required
@roles_required(User.ROLE_ADMIN)
def users():
    q = request.args.get("q", "").strip()
    role = request.args.get("role", "").strip()
    query = User.query
    if q:
        pattern = f"%{q}%"
        query = query.filter(User.username.ilike(pattern) | User.email.ilike(pattern))
    if role in User.ROLES:
        query = query.filter_by(role=role)
    users_list = query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users_list, roles=User.ROLES, search=q, selected_role=role)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@roles_required(User.ROLE_ADMIN)
def change_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.users"))

    new_role = request.form.get("role")
    if new_role not in User.ROLES:
        flash("Invalid role.", "danger")
        return redirect(url_for("admin.users"))

    # Prevent admin self-lockout if this is the last administrator account
    if user.role == User.ROLE_ADMIN and new_role != User.ROLE_ADMIN:
        admin_count = User.query.filter_by(role=User.ROLE_ADMIN).count()
        if admin_count <= 1:
            flash("Cannot remove the last administrator account.", "danger")
            return redirect(url_for("admin.users"))

    user.role = new_role
    record_event(
        "user_role_changed",
        target_type="user",
        target_id=user.id,
        detail=f"Changed role for {user.username} to {new_role}.",
    )
    db.session.commit()
    flash(f"Updated role for {user.username}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/create", methods=["GET", "POST"])
@login_required
@roles_required(User.ROLE_ADMIN)
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", User.ROLE_ANALYST)

        if not username or not email:
            flash("Username and email are required.", "danger")
            return render_template("admin_user_create.html", roles=User.ROLES)

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash("A user with that email or username already exists.", "danger")
            return render_template("admin_user_create.html", roles=User.ROLES)

        is_valid, errors, _ = validate_password(password, username=username, email=email)
        if not is_valid:
            for err in errors:
                flash(err, "danger")
            return render_template("admin_user_create.html", roles=User.ROLES)

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role if role in User.ROLES else User.ROLE_ANALYST,
        )
        db.session.add(user)
        db.session.flush()
        record_event("user_created", target_type="user", target_id=user.id, detail=f"Created user {username} with role {user.role}.", actor=g.current_user)
        db.session.commit()
        flash(f"User {username} created successfully.", "success")
        return redirect(url_for("admin.users"))

    return render_template("admin_user_create.html", roles=User.ROLES)


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@roles_required(User.ROLE_ADMIN)
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.users"))

    if user.id == g.current_user.id:
        flash("You cannot delete your own active administrator account.", "danger")
        return redirect(url_for("admin.users"))

    if user.role == User.ROLE_ADMIN:
        admin_count = User.query.filter_by(role=User.ROLE_ADMIN).count()
        if admin_count <= 1:
            flash("Cannot delete the last administrator account.", "danger")
            return redirect(url_for("admin.users"))

    username = user.username
    db.session.delete(user)
    record_event("user_deleted", target_type="user", target_id=user_id, detail=f"Deleted user {username}.", actor=g.current_user)
    db.session.commit()
    flash(f"User {username} deleted successfully.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@roles_required(User.ROLE_ADMIN)
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.users"))

    new_password = request.form.get("new_password", "")
    is_valid, errors, _ = validate_password(new_password, username=user.username, email=user.email)
    if not is_valid:
        for err in errors:
            flash(err, "danger")
        return redirect(url_for("admin.users"))

    user.password = generate_password_hash(new_password)
    record_event("admin_reset_user_password", target_type="user", target_id=user.id, detail=f"Admin reset password for {user.username}.", actor=g.current_user)
    db.session.commit()
    flash(f"Password reset for {user.username}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/logs")
@login_required
@roles_required(User.ROLE_ADMIN)
def logs():
    logs_list = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(100).all()
    return render_template("admin_logs.html", logs=logs_list)
