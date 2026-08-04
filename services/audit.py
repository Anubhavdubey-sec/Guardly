import logging
from flask import g
from sqlalchemy.exc import SQLAlchemyError

from models.system_log import SystemLog
from models.user import db

logger = logging.getLogger("phishguard.audit")


def record_event(event, target_type=None, target_id=None, detail="", actor=None, actor_name=None):
    """Record a security audit log event safely using isolated savepoints and structured logging.
    
    Guarantees that database failures during audit log generation never interrupt
    authentication flows or user actions.
    """
    try:
        current_actor = actor or getattr(g, "current_user", None)
        actor_id = getattr(current_actor, "id", None) if current_actor else None
        resolved_actor_name = actor_name or (getattr(current_actor, "username", "System") if current_actor else "System")
        resolved_target_type = target_type or ("auth" if "login" in event or "logout" in event else "system")

        with db.session.begin_nested():
            log_entry = SystemLog(
                actor_id=actor_id,
                actor_name=resolved_actor_name,
                event=event,
                target_type=resolved_target_type,
                target_id=target_id,
                detail=detail,
            )
            db.session.add(log_entry)
    except SQLAlchemyError as exc:
        logger.exception("Database exception while recording audit event '%s': %s", event, exc)
    except Exception as exc:
        logger.exception("Unexpected error while recording audit event '%s': %s", event, exc)
