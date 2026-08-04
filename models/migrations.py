from sqlalchemy import inspect, text
from models.user import db


def apply_schema_migrations():
    """Apply safe additive schema migrations for both SQLite and MySQL/Postgres if needed."""
    try:
        engine = db.engine
        inspector = inspect(engine)

        if inspector.has_table("users"):
            user_cols = {col["name"] for col in inspector.get_columns("users")}
            with engine.connect() as conn:
                if "role" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user' NOT NULL"))
                if "created_at" not in user_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME"))
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
                conn.commit()

        if inspector.has_table("system_logs"):
            log_cols = {col["name"] for col in inspector.get_columns("system_logs")}
            with engine.connect() as conn:
                if "actor_name" not in log_cols:
                    conn.execute(text("ALTER TABLE system_logs ADD COLUMN actor_name VARCHAR(80)"))
                if "created_at" not in log_cols:
                    conn.execute(text("ALTER TABLE system_logs ADD COLUMN created_at DATETIME"))
                conn.commit()
    except Exception as e:
        print(f"[Schema Migration] Notice: {e}")
