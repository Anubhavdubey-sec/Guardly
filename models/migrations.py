from sqlalchemy import inspect, text
from models.user import db


def apply_schema_migrations(engine=None):
    """Apply safe additive schema migrations for both SQLite and MySQL/Postgres if needed."""
    try:
        if engine is None:
            engine = db.engine
        inspector = inspect(engine)

        if inspector.has_table("users"):
            user_cols = {col["name"] for col in inspector.get_columns("users")}
            with engine.connect() as conn:
                if "role" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user' NOT NULL"))
                if "created_at" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME"))
                if "tenant_id" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default' NOT NULL"))
                if "mfa_secret" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64)"))
                if "mfa_enabled" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0 NOT NULL"))
                if "mfa_recovery_codes" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT"))
                if "is_active" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1 NOT NULL"))
                # Migrate any legacy enterprise analyst/staff accounts to standard user
                conn.execute(text("UPDATE users SET role = 'user' WHERE role IN ('analyst', 'staff')"))
                conn.commit()

        if inspector.has_table("email_scans"):
            scan_cols = {col["name"] for col in inspector.get_columns("email_scans")}
            with engine.connect() as conn:
                if "reply_to" not in scan_cols:
                    conn.execute(text("ALTER TABLE email_scans ADD COLUMN reply_to VARCHAR(255)"))
                if "risk_categories" not in scan_cols:
                    conn.execute(text("ALTER TABLE email_scans ADD COLUMN risk_categories TEXT"))
                if "reputation_data" not in scan_cols:
                    conn.execute(text("ALTER TABLE email_scans ADD COLUMN reputation_data TEXT"))
                if "tenant_id" not in scan_cols:
                    conn.execute(text("ALTER TABLE email_scans ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default' NOT NULL"))
                if "guest_token" not in scan_cols:
                    conn.execute(text("ALTER TABLE email_scans ADD COLUMN guest_token VARCHAR(64)"))
                conn.commit()

        if inspector.has_table("system_logs"):
            log_cols = {col["name"] for col in inspector.get_columns("system_logs")}
            with engine.connect() as conn:
                if "actor_name" not in log_cols:
                    conn.execute(text("ALTER TABLE system_logs ADD COLUMN actor_name VARCHAR(80)"))
                if "created_at" not in log_cols:
                    conn.execute(text("ALTER TABLE system_logs ADD COLUMN created_at DATETIME"))
                if "tenant_id" not in log_cols:
                    conn.execute(text("ALTER TABLE system_logs ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default' NOT NULL"))
                conn.commit()

        for table_name in ("email_messages", "mail_queue"):
            if inspector.has_table(table_name):
                columns = {col["name"] for col in inspector.get_columns(table_name)}
                if "tenant_id" not in columns:
                    with engine.connect() as conn:
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default' NOT NULL"))
                        conn.commit()

        # Ensure Phase 4 Module 2 tables exist
        db.create_all()
    except Exception as e:
        print(f"[Schema Migration] Notice: {e}")

