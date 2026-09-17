"""
Data Retention & Privacy Lifecycle Management Service for Guardly.
Enforces automated cleanup of expired guest scan telemetry and legacy evidence files.
"""

from datetime import datetime, timedelta, timezone
import logging
import os
from typing import Dict, Any

from flask import current_app
from models.scan import EmailScan
from models.user import db
from services.audit import record_event

logger = logging.getLogger(__name__)


def cleanup_expired_guest_scans(max_age_hours: int = None) -> Dict[str, Any]:
    """
    Deletes anonymous guest scans older than the configured retention threshold
    (defaults to Config.GUEST_RETENTION_HOURS, or 24 hours).
    Personal scans owned by registered users (user_id IS NOT NULL) are NEVER touched.
    """
    if max_age_hours is None:
        try:
            max_age_hours = current_app.config.get("GUEST_RETENTION_HOURS", 24)
        except RuntimeError:
            max_age_hours = 24

    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

    try:
        # Strict filter: guest scans only (user_id is None, guest_token is not None)
        expired_query = EmailScan.query.filter(
            EmailScan.user_id.is_(None),
            EmailScan.guest_token.isnot(None),
            EmailScan.scan_time < cutoff,
        )
        count = expired_query.count()

        if count > 0:
            expired_query.delete(synchronize_session=False)
            db.session.commit()
            record_event(
                "guest_retention_cleanup",
                target_type="scan",
                detail=f"Purged {count} expired guest scan(s) older than {max_age_hours}h.",
                actor_name="RetentionEngine",
            )
            logger.info("Purged %d expired guest scan(s).", count)

        return {"status": "success", "scans_purged": count, "cutoff": cutoff.isoformat()}
    except Exception as exc:
        db.session.rollback()
        logger.error("Failed to execute guest retention cleanup: %s", exc)
        return {"status": "error", "error": str(exc), "scans_purged": 0}


def cleanup_orphaned_uploads(max_age_hours: int = 2) -> Dict[str, Any]:
    """
    Purges temporary uploaded .eml files left in the uploads folder older than max_age_hours.
    """
    try:
        upload_folder = current_app.config.get("UPLOAD_FOLDER")
    except RuntimeError:
        upload_folder = None

    if not upload_folder or not os.path.exists(upload_folder):
        return {"status": "skipped", "files_removed": 0}

    cutoff_timestamp = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).timestamp()
    removed = 0

    try:
        for fname in os.listdir(upload_folder):
            fpath = os.path.join(upload_folder, fname)
            if os.path.isfile(fpath):
                try:
                    if os.path.getmtime(fpath) < cutoff_timestamp:
                        os.remove(fpath)
                        removed += 1
                except OSError:
                    pass
        return {"status": "success", "files_removed": removed}
    except Exception as exc:
        logger.error("Error cleaning orphaned uploads: %s", exc)
        return {"status": "error", "error": str(exc), "files_removed": removed}
