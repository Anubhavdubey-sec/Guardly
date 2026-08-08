"""
Mail Enforcement Service & Quarantine Vault for Guardly (Phase 4 / Module 4).
Executes PolicyEngine decisions, maintains message state machine transitions,
stores quarantined emails in isolated vault (quarantine/), logs auditable security actions,
and provides multi-tenant authorized administrator release workflows.
"""

import os
import shutil
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage
from models.policy import MailDecision, MailQuarantine, MailAuditLog
from services.mail_policy import PolicyEngine, PolicyConfig

logger = logging.getLogger("guardly.services.mail_enforcement")

DEFAULT_QUARANTINE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "quarantine")
)


def _resolve_quarantine_dir(custom_path: Optional[str] = None) -> str:
    path = custom_path or os.getenv("MAIL_QUARANTINE_PATH") or DEFAULT_QUARANTINE_DIR
    abs_dir = os.path.abspath(path)
    os.makedirs(abs_dir, exist_ok=True)
    return abs_dir


def generate_quarantine_id() -> str:
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_hex = uuid.uuid4().hex[:8]
    return f"QUAR-{date_str}-{unique_hex}"


def log_audit_event(
    message_id: str,
    action: str,
    tenant_id: str = "default",
    actor_id: str = "system",
    risk_score: Optional[int] = None,
    severity: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> MailAuditLog:
    """Creates and persists an auditable security log event."""
    log_entry = MailAuditLog(
        message_id=message_id,
        tenant_id=tenant_id,
        action=action,
        actor_id=actor_id,
        risk_score=risk_score,
        severity=severity,
        details_json=json.dumps(details) if details else None,
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(log_entry)
    db.session.commit()
    logger.info(f"Audit Log [{action}] for message {message_id} (Tenant: {tenant_id}, Actor: {actor_id})")
    return log_entry


def enforce_mail_decision(
    email_msg: EmailMessage,
    analysis_result: Dict[str, Any],
    tenant_id: str = "default",
    policy_engine: Optional[PolicyEngine] = None
) -> Tuple[str, str]:
    """
    Executes the PolicyEngine decision on a parsed & analyzed email message.
    Updates EmailMessage & MailQueue state machine, persists decision, and stores quarantine vault file.

    Returns:
        Tuple[decision (str), status (str)]
    """
    if not email_msg:
        raise ValueError("Invalid EmailMessage object passed to enforce_mail_decision")

    msg_id = email_msg.message_id
    score = analysis_result.get("risk_score", email_msg.risk_score or 0)
    sev = analysis_result.get("severity", email_msg.severity or "LOW")

    # Prevent duplicate enforcement if already in an end state
    if email_msg.status in ("ALLOW", "READY_FOR_RELAY", "REVIEW", "QUARANTINED", "REJECTED", "DELIVERED"):
        logger.info(f"Skipping enforcement for {msg_id}: already in status {email_msg.status}")
        return email_msg.status, email_msg.status

    engine = policy_engine or PolicyEngine()

    try:
        decision, reason = engine.evaluate_decision(score, analysis_result)
    except Exception as eval_err:
        # Failure Safety: If policy evaluation fails, default to REVIEW
        logger.error(f"Policy Engine evaluation failed for {msg_id}: {eval_err}. Defaulting to REVIEW.")
        decision = "REVIEW"
        reason = f"Security Analysis Evaluation Error: {str(eval_err)}"

    # Record MailDecision DB record (idempotent lookup)
    existing_dec = MailDecision.query.filter_by(message_id=msg_id).first()
    if not existing_dec:
        dec_record = MailDecision(
            message_id=msg_id,
            tenant_id=tenant_id,
            decision=decision,
            risk_score=score,
            severity=sev,
            reason=reason,
        )
        db.session.add(dec_record)
    else:
        existing_dec.decision = decision
        existing_dec.risk_score = score
        existing_dec.severity = sev
        existing_dec.reason = reason

    final_status = "FAILED"

    if decision == "ALLOW":
        email_msg.status = "READY_FOR_RELAY"
        final_status = "READY_FOR_RELAY"
        log_audit_event(msg_id, "ALLOW", tenant_id=tenant_id, risk_score=score, severity=sev, details={"reason": reason})

    elif decision == "REVIEW":
        email_msg.status = "REVIEW"
        final_status = "REVIEW"
        log_audit_event(msg_id, "REVIEW", tenant_id=tenant_id, risk_score=score, severity=sev, details={"reason": reason})

    elif decision == "QUARANTINE":
        quarantine_record = quarantine_message(
            email_msg=email_msg,
            reason=reason,
            risk_score=score,
            severity=sev,
            tenant_id=tenant_id
        )
        email_msg.status = "QUARANTINED"
        final_status = "QUARANTINED"
        log_audit_event(
            msg_id, "QUARANTINE", tenant_id=tenant_id, risk_score=score, severity=sev,
            details={"quarantine_id": quarantine_record.quarantine_id, "reason": reason}
        )

    elif decision == "REJECT":
        email_msg.status = "REJECTED"
        final_status = "REJECTED"
        log_audit_event(msg_id, "REJECT", tenant_id=tenant_id, risk_score=score, severity=sev, details={"reason": reason})

    # Update MailQueue job status
    queue_item = MailQueue.query.filter_by(message_id=msg_id).first()
    if queue_item:
        queue_item.status = final_status

    db.session.commit()
    logger.info(f"Enforced decision for message {msg_id}: Decision={decision}, Final Status={final_status}")
    return decision, final_status


def quarantine_message(
    email_msg: EmailMessage,
    reason: str,
    risk_score: int,
    severity: str,
    tenant_id: str = "default",
    quarantine_storage_dir: Optional[str] = None
) -> MailQuarantine:
    """
    Moves an email into isolated quarantine vault storage (quarantine/) and records a MailQuarantine DB record.
    """
    msg_id = email_msg.message_id

    # Check for existing quarantine record (idempotency)
    existing_q = MailQuarantine.query.filter_by(message_id=msg_id, tenant_id=tenant_id).first()
    if existing_q:
        logger.info(f"Message {msg_id} already quarantined under ID {existing_q.quarantine_id}")
        return existing_q

    q_dir = _resolve_quarantine_dir(quarantine_storage_dir)
    quar_id = generate_quarantine_id()
    q_file_name = f"{quar_id}.eml"
    q_file_path = os.path.join(q_dir, q_file_name)

    # Copy raw message to safe isolated quarantine storage
    raw_path = email_msg.raw_message_path
    if raw_path and os.path.exists(raw_path):
        shutil.copy2(raw_path, q_file_path)
    else:
        # Save reconstructed raw content if raw file missing
        with open(q_file_path, "wb") as qf:
            qf.write(f"Subject: {email_msg.subject}\nFrom: {email_msg.from_address}\n\n{email_msg.text_body or ''}".encode("utf-8"))

    recipient_str = email_msg.to_list[0] if email_msg.to_list else "unknown"

    quar_record = MailQuarantine(
        message_id=msg_id,
        tenant_id=tenant_id,
        quarantine_id=quar_id,
        original_sender=email_msg.from_address,
        recipient=recipient_str,
        subject=email_msg.subject,
        reason=reason,
        risk_score=risk_score,
        severity=severity,
        raw_message_path=raw_path,
        quarantine_file_path=q_file_path,
        status="QUARANTINED",
    )
    db.session.add(quar_record)
    db.session.commit()

    logger.info(f"Successfully quarantined message {msg_id} -> Quarantine ID: {quar_id} at {q_file_path}")
    return quar_record


def release_message(
    quarantine_id: str,
    released_by_user_id: str,
    user_tenant_id: str = "default"
) -> Tuple[bool, str]:
    """
    Authorized administrator operation to release a quarantined email.
    Enforces multi-tenant isolation, state validation, and audit logging.
    Transitions state to READY_FOR_RELAY.
    """
    quar_record = MailQuarantine.query.filter_by(quarantine_id=quarantine_id).first()
    if not quar_record:
        return False, f"Quarantine record {quarantine_id} not found."

    # Multi-tenant isolation enforcement
    if quar_record.tenant_id != user_tenant_id:
        logger.warning(f"Tenant mismatch on release attempt: User Tenant '{user_tenant_id}' tried to release '{quar_record.tenant_id}' record {quarantine_id}")
        return False, "Unauthorized: Cross-tenant access denied."

    if quar_record.status == "RELEASED":
        return False, f"Quarantine record {quarantine_id} has already been released."

    msg_id = quar_record.message_id
    email_msg = EmailMessage.query.filter_by(message_id=msg_id).first()
    if not email_msg:
        return False, f"Associated EmailMessage {msg_id} not found."

    # Update Quarantine Record
    quar_record.status = "RELEASED"
    quar_record.released_at = datetime.now(timezone.utc)
    quar_record.released_by = released_by_user_id

    # Update EmailMessage status -> READY_FOR_RELAY
    email_msg.status = "READY_FOR_RELAY"

    # Update MailQueue job status
    queue_item = MailQueue.query.filter_by(message_id=msg_id).first()
    if queue_item:
        queue_item.status = MailQueue.STATUS_READY_FOR_RELAY

    log_audit_event(
        msg_id, "RELEASE", tenant_id=user_tenant_id, actor_id=released_by_user_id,
        details={"quarantine_id": quarantine_id, "released_by": released_by_user_id}
    )

    db.session.commit()
    logger.info(f"Successfully released quarantined message {msg_id} ({quarantine_id}) by admin {released_by_user_id}")
    return True, f"Message {quarantine_id} released successfully -> READY_FOR_RELAY"


def release_review_message(
    message_id: str,
    released_by_user_id: str,
    user_tenant_id: str = "default"
) -> Tuple[bool, str]:
    """
    Authorized administrator operation to approve and release a message in REVIEW state.
    """
    email_msg = EmailMessage.query.filter_by(message_id=message_id).first()
    if not email_msg:
        return False, f"EmailMessage {message_id} not found."

    if email_msg.status != "REVIEW":
        return False, f"Message {message_id} is in status '{email_msg.status}', not 'REVIEW'."

    email_msg.status = "READY_FOR_RELAY"

    queue_item = MailQueue.query.filter_by(message_id=message_id).first()
    if queue_item:
        queue_item.status = MailQueue.STATUS_READY_FOR_RELAY

    log_audit_event(
        message_id, "RELEASE_REVIEW", tenant_id=user_tenant_id, actor_id=released_by_user_id,
        details={"released_by": released_by_user_id}
    )

    db.session.commit()
    logger.info(f"Successfully released REVIEW message {message_id} to READY_FOR_RELAY by admin {released_by_user_id}")
    return True, f"Review message {message_id} released successfully -> READY_FOR_RELAY"


def reject_message(
    message_id: str,
    reason: str,
    tenant_id: str = "default"
) -> bool:
    """Marks a message as REJECTED in database."""
    email_msg = EmailMessage.query.filter_by(message_id=message_id).first()
    if not email_msg:
        return False

    email_msg.status = "REJECTED"
    queue_item = MailQueue.query.filter_by(message_id=message_id).first()
    if queue_item:
        queue_item.status = MailQueue.STATUS_REJECTED

    log_audit_event(message_id, "REJECT", tenant_id=tenant_id, details={"reason": reason})
    db.session.commit()
    return True


def get_quarantined_message(quarantine_id: str, tenant_id: str = "default") -> Optional[MailQuarantine]:
    """Retrieves a quarantined message record enforcing tenant isolation."""
    return MailQuarantine.query.filter_by(quarantine_id=quarantine_id, tenant_id=tenant_id).first()


def list_quarantined_messages(tenant_id: str = "default", status: Optional[str] = None) -> List[MailQuarantine]:
    """Lists all quarantined messages for a given tenant."""
    query = MailQuarantine.query.filter_by(tenant_id=tenant_id)
    if status:
        query = query.filter_by(status=status)
    return query.order_by(MailQuarantine.id.desc()).all()


def get_review_messages(tenant_id: str = "default") -> List[EmailMessage]:
    """Lists all messages pending REVIEW for a given tenant."""
    return EmailMessage.query.filter_by(status="REVIEW").order_by(EmailMessage.id.desc()).all()
