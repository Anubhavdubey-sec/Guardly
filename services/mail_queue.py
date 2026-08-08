"""
Mail Queue Processing Service for Guardly (Phase 4 / Module 2).
Handles async mail queue state transitions:
RECEIVED -> QUEUED -> PROCESSING -> PARSED -> READY_FOR_ANALYSIS -> FAILED
"""

import os
import json
import time
import uuid
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, List

from models.user import db
from models.queue import MailQueue
from models.email_message import EmailMessage, EmailAttachment
from services.email_parser import parse_raw_email

logger = logging.getLogger("guardly.services.mail_queue")

MAX_RETRIES = 3


def enqueue_message(raw_message_path: str, message_id: Optional[str] = None) -> MailQueue:
    """
    Enqueues a newly received raw email message into the mail queue.
    """
    if not message_id:
        message_id = f"msg_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"

    # Check for existing queue entry (duplicate prevention)
    existing = MailQueue.query.filter_by(message_id=message_id).first()
    if existing:
        logger.info(f"Message ID {message_id} already exists in queue (Status: {existing.status})")
        return existing

    queue_entry = MailQueue(
        message_id=message_id,
        status=MailQueue.STATUS_QUEUED,
        received_at=datetime.now(timezone.utc),
        raw_message_path=os.path.abspath(raw_message_path),
        retry_count=0,
    )
    db.session.add(queue_entry)
    db.session.commit()

    logger.info(f"Enqueued raw message {message_id} (Path: {raw_message_path})")
    return queue_entry


def process_queue_job(message_id: str) -> bool:
    """
    Processes a single mail queue job:
    1. Sets status to PROCESSING
    2. Reads raw .eml message
    3. Calls Email Parser
    4. Saves EmailMessage & EmailAttachment DB records
    5. Sets status to READY_FOR_ANALYSIS
    """
    queue_item = MailQueue.query.filter_by(message_id=message_id).first()
    if not queue_item:
        logger.error(f"Mail queue item not found for ID: {message_id}")
        return False

    # Prevent duplicate processing if already completed
    if queue_item.status in (MailQueue.STATUS_PARSED, MailQueue.STATUS_READY_FOR_ANALYSIS):
        logger.info(f"Skipping job {message_id}: already in status {queue_item.status}")
        return True

    queue_item.status = MailQueue.STATUS_PROCESSING
    queue_item.started_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info(f"Started processing mail queue job {message_id}")

    try:
        raw_path = queue_item.raw_message_path
        if not raw_path or not os.path.exists(raw_path):
            raise FileNotFoundError(f"Raw message file missing at: {raw_path}")

        with open(raw_path, "rb") as f:
            raw_bytes = f.read()

        # Parse complete RFC message
        parsed_data = parse_raw_email(raw_bytes, fallback_message_id=message_id)

        # Execute Threat Analysis Engine (Module 3)
        from services.threat_analysis import ThreatAnalysisEngine
        engine = ThreatAnalysisEngine()
        analysis_res = engine.analyze(parsed_data)

        # Save/Update EmailMessage record in DB
        email_msg = EmailMessage.query.filter_by(message_id=message_id).first()
        if not email_msg:
            email_msg = EmailMessage(message_id=message_id)
            db.session.add(email_msg)

        email_msg.from_address = parsed_data.get("from")
        email_msg.to_addresses = json.dumps(parsed_data.get("to", []))
        email_msg.cc_addresses = json.dumps(parsed_data.get("cc", []))
        email_msg.bcc_addresses = json.dumps(parsed_data.get("bcc", []))
        email_msg.reply_to = parsed_data.get("reply_to")
        email_msg.subject = parsed_data.get("subject")
        email_msg.email_date = parsed_data.get("date")
        email_msg.return_path = parsed_data.get("return_path")
        email_msg.headers_json = json.dumps(parsed_data.get("headers", {}))
        email_msg.text_body = parsed_data.get("text_body")
        email_msg.html_body = parsed_data.get("html_body")
        email_msg.urls_json = json.dumps(parsed_data.get("urls", []))
        email_msg.attachments_json = json.dumps(parsed_data.get("attachments", []))
        email_msg.raw_message_path = raw_path
        email_msg.parsed_at = datetime.now(timezone.utc)
        email_msg.status = "READY_FOR_ANALYSIS"
        email_msg.error_message = None

        # Threat Analysis Results
        email_msg.risk_score = analysis_res.get("risk_score", 0)
        email_msg.severity = analysis_res.get("severity", "LOW")
        email_msg.recommendation = analysis_res.get("recommendation", "ALLOW")
        email_msg.findings_json = json.dumps(analysis_res.get("findings", []))
        email_msg.analysis_json = json.dumps(analysis_res)

        # Save individual attachment records
        for att_info in parsed_data.get("attachments", []):
            existing_att = EmailAttachment.query.filter_by(
                message_id=message_id,
                sha256_hash=att_info["sha256"]
            ).first()
            if not existing_att:
                att_record = EmailAttachment(
                    message_id=message_id,
                    filename=att_info["filename"],
                    original_filename=att_info["original_filename"],
                    mime_type=att_info["mime_type"],
                    size_bytes=att_info["size"],
                    sha256_hash=att_info["sha256"],
                    safe_storage_path=att_info["storage_path"],
                )
                db.session.add(att_record)

        # Sync into EmailScan table for backward compatibility with Guardly Dashboard & Reports
        from models.scan import EmailScan
        verdict_str = f"{analysis_res.get('severity', 'LOW').title()} Risk"
        if verdict_str == "Critical Risk":
            verdict_str = "High Risk"
        elif verdict_str == "Low Risk":
            verdict_str = "Low Risk"

        email_scan = EmailScan.query.filter_by(subject=parsed_data.get("subject"), sender=parsed_data.get("from")).first()
        if not email_scan:
            receiver_str = parsed_data.get("to")[0] if parsed_data.get("to") else "unknown@target.local"
            email_scan = EmailScan(
                sender=parsed_data.get("from"),
                receiver=receiver_str,
                subject=parsed_data.get("subject"),
                email_date=parsed_data.get("date"),
                reply_to=parsed_data.get("reply_to"),
                email_body=parsed_data.get("text_body"),
                risk_score=analysis_res.get("risk_score", 0),
                verdict=verdict_str,
                findings=json.dumps(analysis_res.get("findings", [])),
                urls=json.dumps(parsed_data.get("urls", [])),
                attachments=json.dumps(parsed_data.get("attachments", [])),
                headers=json.dumps(parsed_data.get("headers", {})),
                iocs=json.dumps(analysis_res.get("iocs", {})),
            )
            db.session.add(email_scan)

        # Update queue job status to READY_FOR_ANALYSIS
        queue_item.status = MailQueue.STATUS_READY_FOR_ANALYSIS
        queue_item.completed_at = datetime.now(timezone.utc)
        queue_item.error_message = None

        db.session.commit()
        logger.info(f"Successfully processed mail queue job {message_id} -> READY_FOR_ANALYSIS (Score: {analysis_res.get('risk_score')}, Verdict: {verdict_str})")
        return True

    except Exception as exc:
        db.session.rollback()
        queue_item = MailQueue.query.filter_by(message_id=message_id).first()
        if queue_item:
            queue_item.retry_count += 1
            err_str = str(exc)
            queue_item.error_message = err_str

            if queue_item.retry_count >= MAX_RETRIES:
                queue_item.status = MailQueue.STATUS_FAILED
                logger.error(f"Job {message_id} FAILED permanently after {queue_item.retry_count} retries: {err_str}")
            else:
                queue_item.status = MailQueue.STATUS_QUEUED
                logger.warning(f"Job {message_id} processing failed (Retry {queue_item.retry_count}/{MAX_RETRIES}): {err_str}")

            db.session.commit()
        return False


def process_pending_queue(app, max_jobs: int = 10) -> int:
    """
    Fetches and processes pending QUEUED or RECEIVED jobs in batch.
    """
    processed_count = 0
    with app.app_context():
        pending_jobs = (
            MailQueue.query.filter(
                MailQueue.status.in_([MailQueue.STATUS_QUEUED, MailQueue.STATUS_RECEIVED])
            )
            .order_by(MailQueue.received_at.asc())
            .limit(max_jobs)
            .all()
        )

        for job in pending_jobs:
            if process_queue_job(job.message_id):
                processed_count += 1

    return processed_count


class MailQueueWorkerThread:
    """
    Background worker thread polling the mail queue periodically.
    Runs non-blockingly alongside Flask and the SMTP Receiver.
    """

    def __init__(self, app, poll_interval: float = 1.0):
        self.app = app
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Starts the queue worker thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="GuardlyMailWorker")
        self._thread.start()
        logger.info("Guardly Mail Queue Worker thread started.")

    def stop(self):
        """Stops the queue worker thread cleanly."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
            logger.info("Guardly Mail Queue Worker thread stopped cleanly.")

    def _worker_loop(self):
        while self._running:
            try:
                process_pending_queue(self.app, max_jobs=5)
            except Exception as exc:
                logger.error(f"Error in Mail Queue Worker loop: {exc}")
            time.sleep(self.poll_interval)

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()
