"""
Mail Storage Module for Guardly SMTP Receiver.
Provides secure, atomic storage for received raw RFC 5322 .eml messages.
"""

import os
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger("guardly.mail.storage")

DEFAULT_STORAGE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "received_emails")
)


def _resolve_storage_dir(storage_path: Optional[str] = None) -> str:
    """
    Resolves and creates the absolute canonical storage directory.
    """
    target_path = storage_path or os.getenv("MAIL_STORAGE_PATH") or DEFAULT_STORAGE_PATH
    abs_dir = os.path.abspath(target_path)
    os.makedirs(abs_dir, exist_ok=True)
    return abs_dir


def generate_unique_filename() -> str:
    """
    Generates a secure, non-predictable filename format: YYYYMMDD_<uuid4>.eml
    Does NOT incorporate sender or recipient input to prevent path injection.
    """
    date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_id = uuid.uuid4().hex
    return f"{date_prefix}_{unique_id}.eml"


def save_raw_email(message_bytes: bytes, storage_path: Optional[str] = None) -> str:
    """
    Saves raw .eml RFC message bytes to disk securely.

    Args:
        message_bytes: Complete raw email payload bytes.
        storage_path: Directory path to store the email. Defaults to MAIL_STORAGE_PATH.

    Returns:
        Absolute filepath to the saved .eml file.

    Raises:
        ValueError: If message_bytes is empty or invalid.
        IOError: If storage directory cannot be written to or path traversal is detected.
    """
    if not message_bytes or not isinstance(message_bytes, (bytes, bytearray)):
        raise ValueError("Cannot save empty or non-bytes email payload")

    base_dir = _resolve_storage_dir(storage_path)
    filename = generate_unique_filename()
    target_file = os.path.abspath(os.path.join(base_dir, filename))

    # Strict Path Traversal Check: Ensure target_file is strictly inside base_dir
    if not target_file.startswith(base_dir + os.sep) and target_file != base_dir:
        logger.error(f"Path traversal blocked for generated filename '{filename}' in '{base_dir}'")
        raise IOError("Path traversal security check failed")

    # Atomic write pattern using temp file
    temp_file = f"{target_file}.tmp_{uuid.uuid4().hex}"

    try:
        with open(temp_file, "wb") as f:
            f.write(message_bytes)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_file, target_file)
        logger.info(f"Raw email saved successfully: {target_file} ({len(message_bytes)} bytes)")
        return target_file

    except Exception as exc:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass
        logger.error(f"Failed to write email file to disk: {str(exc)}")
        raise IOError(f"Storage write error: {str(exc)}") from exc


def get_stored_emails(storage_path: Optional[str] = None) -> List[str]:
    """
    Returns a list of all .eml filenames in the storage directory sorted by creation time.
    """
    base_dir = _resolve_storage_dir(storage_path)
    if not os.path.exists(base_dir):
        return []

    files = [
        f for f in os.listdir(base_dir)
        if f.endswith(".eml") and os.path.isfile(os.path.join(base_dir, f))
    ]
    files.sort(key=lambda f: os.path.getmtime(os.path.join(base_dir, f)), reverse=True)
    return files


def read_stored_email(filename_or_path: str, storage_path: Optional[str] = None) -> bytes:
    """
    Safely reads raw email bytes given a filename or absolute path.
    """
    base_dir = _resolve_storage_dir(storage_path)
    if os.path.isabs(filename_or_path):
        target_file = os.path.abspath(filename_or_path)
    else:
        # Sanitize basename to prevent path traversal in filename parameter
        safe_basename = os.path.basename(filename_or_path)
        target_file = os.path.abspath(os.path.join(base_dir, safe_basename))

    if not target_file.startswith(base_dir + os.sep) and target_file != base_dir:
        raise IOError("Path traversal security check failed for read operation")

    if not os.path.exists(target_file):
        raise FileNotFoundError(f"Stored email not found: {filename_or_path}")

    with open(target_file, "rb") as f:
        return f.read()
