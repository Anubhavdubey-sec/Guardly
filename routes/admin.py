from flask import Blueprint, flash, redirect, render_template, request, url_for

from models.scan import EmailScan
from models.system_log import SystemLog
from models.user import User, db
from routes.auth import login_required, roles_required
from services.audit import record_event

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_bp.route("/dashboard")
@login_required
@roles_required(User.ROLE_ADMIN)
def dashboard():
    users_count = User.query.count()
    scans_count = EmailScan.query.count()
    high_risk_count = EmailScan.query.filter_by(verdict="High Risk").count()
    recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(10).all()
    stats = {
        "users": users_count,
        "scans": scans_count,
        "high_risk": high_risk_count,
    }
    return render_template("admin_dashboard.html", stats=stats, recent_logs=recent_logs)


@admin_bp.route("/users")
@login_required
@roles_required(User.ROLE_ADMIN)
def users():
    q = request.args.get("q", "").strip()
    query = User.query
    if q:
        pattern = f"%{q}%"
        query = query.filter(User.username.ilike(pattern) | User.email.ilike(pattern))
    users_list = query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users_list, roles=User.ROLES)


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


@admin_bp.route("/logs")
@login_required
@roles_required(User.ROLE_ADMIN)
def logs():
    logs_list = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(100).all()
    return render_template("admin_logs.html", logs=logs_list)
