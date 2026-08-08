import os
import sqlite3
from datetime import datetime, timezone

import click
from flask import Flask, render_template
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config
from models.migrations import apply_schema_migrations
from models.scan import EmailScan
from models.system_log import SystemLog
from models.user import User, db
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.scanner import scanner_bp
from services.audit import record_event
from services.csrf import init_csrf
from services.limiter import limiter
from services.password_validator import validate_password


def initialize_database():
    """Create the relational schema and apply safe additive migrations."""
    db.create_all()
    apply_schema_migrations()


def ensure_mysql_database():
    """Create the configured MySQL database before creating its tables."""
    if db.engine.dialect.name != "mysql":
        return

    database_name = db.engine.url.database
    if not database_name or not database_name.replace("_", "").isalnum():
        raise click.UsageError("MYSQL_DATABASE may contain only letters, numbers, and underscores.")

    server_engine = create_engine(db.engine.url.set(database=None), pool_pre_ping=True)
    try:
        with server_engine.begin() as connection:
            connection.execute(text(
                f"CREATE DATABASE IF NOT EXISTS `{database_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            ))
    finally:
        server_engine.dispose()


def _sqlite_value(row, column_name, default=None):
    return row[column_name] if column_name in row.keys() and row[column_name] is not None else default


def _sqlite_datetime(value):
    if not value or isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed and parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _sqlite_role(value):
    return value if value in User.ROLES else User.ROLE_USER


def _sqlite_risk_score(value):
    try:
        return min(100, max(0, int(value)))
    except (TypeError, ValueError):
        return 0


def _sqlite_verdict(value, score):
    valid_verdicts = {"Low Risk", "Medium Risk", "High Risk"}
    if value in valid_verdicts:
        return value
    if score >= 50:
        return "High Risk"
    if score >= 20:
        return "Medium Risk"
    return "Low Risk"


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    if "RATELIMIT_ENABLED" not in app.config:
        app.config["RATELIMIT_ENABLED"] = not app.config.get("TESTING", False)

    db.init_app(app)
    init_csrf(app)
    limiter.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(admin_bp)
    from routes.graph import graph_bp
    app.register_blueprint(graph_bp)

    if app.config["AUTO_CREATE_SCHEMA"]:
        with app.app_context():
            initialize_database()

    @app.errorhandler(400)
    def handle_bad_request(error):
        msg = getattr(error, "description", "Bad Request.")
        return render_template("upload.html", error=msg), 400

    @app.errorhandler(403)
    def handle_forbidden(error):
        msg = getattr(error, "description", "Access Forbidden.")
        return render_template("upload.html", error=msg), 403

    @app.errorhandler(404)
    def handle_not_found(_error):
        return render_template("upload.html", error="The requested resource was not found."), 404

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_error):
        return (
            render_template(
                "upload.html",
                error=f"The email file is too large. The limit is {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB.",
            ),
            413,
        )

    @app.errorhandler(429)
    def handle_rate_limit_exceeded(_error):
        return (
            render_template(
                "login.html",
                error="Too many login attempts. Please wait a minute before trying again.",
            ),
            429,
        )

    @app.errorhandler(500)
    def handle_internal_error(error):
        app.logger.error("Internal Server Error: %s", error, exc_info=True)
        return (
            render_template(
                "upload.html",
                error="An internal security exception occurred. Please try your request again.",
            ),
            500,
        )

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "img-src 'self' data: https: https://*.basemaps.cartocdn.com https://*.tile.openstreetmap.org; "
            "font-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none';"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    return app


app = create_app()


@app.cli.command("init-db")
def init_db():
    """Create or safely update the configured database schema."""
    ensure_mysql_database()
    initialize_database()
    click.echo("Database schema is ready.")


@app.cli.command("migrate-sqlite-data")
@click.option(
    "--source",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str),
    default=os.path.join(os.path.dirname(__file__), "database", "users.db"),
    show_default=True,
    help="Path to the existing PhishGuard SQLite database.",
)
def migrate_sqlite_data(source):
    """Copy users, scans, and audit logs from SQLite into the configured MySQL database."""
    if db.engine.dialect.name != "mysql":
        raise click.UsageError("Set DATABASE_URL to a MySQL database before running this command.")

    ensure_mysql_database()
    initialize_database()
    source_db = sqlite3.connect(source)
    source_db.row_factory = sqlite3.Row
    try:
        source_tables = {
            row["name"]
            for row in source_db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        migrated = {"users": 0, "email_scans": 0, "system_logs": 0}

        if "users" in source_tables:
            for row in source_db.execute("SELECT * FROM users ORDER BY id"):
                if db.session.get(User, row["id"]):
                    continue
                db.session.add(User(
                    id=row["id"],
                    username=_sqlite_value(row, "username", "Unknown user"),
                    email=_sqlite_value(row, "email", f"migrated-{row['id']}@invalid.local"),
                    password=_sqlite_value(row, "password", "!"),
                    role=_sqlite_role(_sqlite_value(row, "role", User.ROLE_USER)),
                ))
                migrated["users"] += 1
            db.session.flush()

        if "email_scans" in source_tables:
            for row in source_db.execute("SELECT * FROM email_scans ORDER BY id"):
                if db.session.get(EmailScan, row["id"]):
                    continue
                risk_score = _sqlite_risk_score(_sqlite_value(row, "risk_score", 0))
                db.session.add(EmailScan(
                    id=row["id"],
                    user_id=_sqlite_value(row, "user_id"),
                    sender=_sqlite_value(row, "sender"),
                    receiver=_sqlite_value(row, "receiver"),
                    subject=_sqlite_value(row, "subject"),
                    email_date=_sqlite_value(row, "email_date"),
                    reply_to=_sqlite_value(row, "reply_to"),
                    email_body=_sqlite_value(row, "email_body"),
                    risk_score=risk_score,
                    verdict=_sqlite_verdict(_sqlite_value(row, "verdict"), risk_score),
                    findings=_sqlite_value(row, "findings", "[]"),
                    urls=_sqlite_value(row, "urls", "[]"),
                    attachments=_sqlite_value(row, "attachments", "[]"),
                    headers=_sqlite_value(row, "headers", "{}"),
                    iocs=_sqlite_value(row, "iocs", "{}"),
                    risk_categories=_sqlite_value(row, "risk_categories", "[]"),
                    reputation_data=_sqlite_value(row, "reputation_data", "{}"),
                    scan_time=_sqlite_datetime(_sqlite_value(row, "scan_time")) or datetime.now(timezone.utc),
                ))
                migrated["email_scans"] += 1
            db.session.flush()

        if "system_logs" in source_tables:
            for row in source_db.execute("SELECT * FROM system_logs ORDER BY id"):
                if db.session.get(SystemLog, row["id"]):
                    continue
                db.session.add(SystemLog(
                    id=row["id"],
                    actor_id=_sqlite_value(row, "actor_id"),
                    actor_name=_sqlite_value(row, "actor_name", "System"),
                    event=_sqlite_value(row, "event", "legacy_event"),
                    target_type=_sqlite_value(row, "target_type", "system"),
                    target_id=_sqlite_value(row, "target_id"),
                    detail=_sqlite_value(row, "detail", ""),
                    created_at=_sqlite_datetime(_sqlite_value(row, "created_at")) or datetime.now(timezone.utc),
                ))
                migrated["system_logs"] += 1

        db.session.flush()
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    finally:
        source_db.close()

    click.echo(
        "Migration complete: "
        f"{migrated['users']} users, {migrated['email_scans']} scans, and "
        f"{migrated['system_logs']} system logs copied."
    )


@app.cli.command("create-admin")
@click.option("--username", prompt=True, help="Administrator display name")
@click.option("--email", prompt=True, help="Administrator email address")
def create_admin(username, email):
    """Create or promote an administrator without exposing a password in command history."""
    username = username.strip()
    email = email.strip().lower()
    user = User.query.filter_by(email=email).first()
    if user:
        user.role = User.ROLE_ADMIN
        record_event("user_promoted_to_admin", target_type="user", target_id=user.id, detail=f"Promoted {user.username} to admin.", actor=user)
        db.session.commit()
        click.echo(f"Promoted {user.email} to administrator.")
        return

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    is_valid, errors, _ = validate_password(password, username=username, email=email)
    if not is_valid:
        raise click.UsageError(f"Password rejected: {' '.join(errors)}")
    user = User(username=username, email=email, password=generate_password_hash(password), role=User.ROLE_ADMIN)
    db.session.add(user)
    db.session.flush()
    record_event("admin_created", target_type="user", target_id=user.id, detail=f"Created administrator {user.username}.", actor=user)
    db.session.commit()
    click.echo(f"Created administrator {user.email}.")


@app.cli.command("reset-admin-password")
@click.option("--email", prompt=True, help="Administrator email address")
def reset_admin_password(email):
    """Reset an existing administrator password without exposing it in shell history."""
    email = email.strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user or user.role != User.ROLE_ADMIN:
        raise click.UsageError("No administrator account was found for that email address.")

    password = click.prompt("New password", hide_input=True, confirmation_prompt=True)
    is_valid, errors, _ = validate_password(password, username=user.username, email=user.email)
    if not is_valid:
        raise click.UsageError(f"Password rejected: {' '.join(errors)}")

    user.password = generate_password_hash(password)
    record_event(
        "admin_password_reset",
        target_type="user",
        target_id=user.id,
        detail=f"Administrator password reset from the local CLI for {user.username}.",
        actor_name="CLI",
    )
    db.session.commit()
    click.echo(f"Password updated for administrator {user.email}.")


@app.cli.command("run-smtp")
@click.option("--host", default=None, help="Host interface to bind the SMTP receiver.")
@click.option("--port", type=int, default=None, help="Port to listen on.")
@click.option("--with-worker/--no-worker", default=True, help="Run background mail queue worker thread.")
def run_smtp_cmd(host, port, with_worker):
    """Start the Guardly SMTP Receiver and Mail Queue Worker."""
    from services.smtp_receiver import GuardlySMTPServer
    from services.mail_queue import MailQueueWorkerThread

    smtp_host = host or app.config.get("SMTP_HOST", "127.0.0.1")
    smtp_port = port or app.config.get("SMTP_PORT", 2525)
    storage_path = app.config.get("MAIL_STORAGE_PATH")
    max_size = app.config.get("MAX_MESSAGE_SIZE", 10 * 1024 * 1024)

    server = GuardlySMTPServer(
        host=smtp_host,
        port=smtp_port,
        max_message_size=max_size,
        storage_path=storage_path,
    )
    worker = None
    if with_worker:
        worker = MailQueueWorkerThread(app)
        worker.start()

    click.echo(f"Starting Guardly SMTP Receiver on {smtp_host}:{smtp_port}...")
    server.start()
    click.echo("SMTP Receiver & Queue Worker active. Press Ctrl+C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nStopping Services...")
        if worker:
            worker.stop()
        server.stop()
        click.echo("Guardly SMTP Receiver and Queue Worker stopped.")


@app.cli.command("run-mail-worker")
def run_mail_worker_cmd():
    """Start standalone Guardly Mail Queue Worker."""
    from services.mail_queue import MailQueueWorkerThread
    worker = MailQueueWorkerThread(app)
    worker.start()
    click.echo("Guardly Mail Queue Worker active. Press Ctrl+C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nStopping Mail Queue Worker...")
        worker.stop()


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])

