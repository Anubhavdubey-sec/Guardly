"""
Email Parser Module for Guardly (Phase 4 / Module 2).
Parses complete RFC 5322 raw email messages, extracts headers, plain text and HTML bodies,
URLs, and safely extracts attachment metadata & files with strict security controls.
"""

import os
import re
import html
import uuid
import hashlib
import logging
import email
from email import policy
from email.header import decode_header
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("guardly.services.email_parser")

# Configuration Defaults
DEFAULT_ATTACHMENT_STORAGE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "extracted_attachments")
)
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25 MB max per attachment
MAX_ATTACHMENT_COUNT = 20              # 20 max attachments per email

# URL Extraction Regex Patterns
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9$-_@.&+!*(),]|%[0-9a-fA-F]{2})+", re.IGNORECASE
)
HTML_HREF_SRC_REGEX = re.compile(
    r'(?:href|src)\s*=\s*["\'](https?://[^"\'>\s]+)["\']', re.IGNORECASE
)


def _resolve_attachment_dir(storage_path: Optional[str] = None) -> str:
    target_dir = storage_path or os.getenv("ATTACHMENT_STORAGE_PATH") or DEFAULT_ATTACHMENT_STORAGE
    abs_dir = os.path.abspath(target_dir)
    os.makedirs(abs_dir, exist_ok=True)
    return abs_dir


def sanitize_filename(filename: Optional[str]) -> str:
    """
    Sanitizes attachment filename to prevent path traversal, directory traversal,
    and command/filename injection.
    """
    if not filename:
        return f"attachment_{uuid.uuid4().hex[:8]}.bin"

    # Strip path indicators and dangerous characters
    cleaned = os.path.basename(filename)
    cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f<>:"/\\|?*]', '_', cleaned)
    cleaned = cleaned.replace("..", "_").strip(". ")

    if not cleaned:
        return f"attachment_{uuid.uuid4().hex[:8]}.bin"

    # Truncate filename if excessively long
    if len(cleaned) > 180:
        base, ext = os.path.splitext(cleaned)
        cleaned = base[:170] + ext[:10]

    return cleaned


def decode_rfc_header(header_value: Optional[str]) -> str:
    """
    Decodes RFC 2047 encoded header words into standard UTF-8 string.
    """
    if not header_value:
        return ""

    decoded_parts = []
    try:
        for text_part, encoding in decode_header(header_value):
            if isinstance(text_part, bytes):
                enc = encoding or "utf-8"
                try:
                    decoded_parts.append(text_part.decode(enc, errors="replace"))
                except Exception:
                    decoded_parts.append(text_part.decode("latin-1", errors="replace"))
            else:
                decoded_parts.append(str(text_part))
        return "".join(decoded_parts)
    except Exception as exc:
        logger.debug(f"RFC header decode fallback for '{header_value}': {exc}")
        return str(header_value)


def _extract_addresses_list(msg: email.message.EmailMessage, header_name: str) -> List[str]:
    """
    Extracts a normalized list of email address strings from a header (To, CC, BCC).
    """
    header_val = msg.get(header_name)
    if not header_val:
        return []

    decoded = decode_rfc_header(str(header_val))
    # Split multiple recipient comma-separated addresses
    raw_addrs = [a.strip() for a in decoded.split(",") if a.strip()]
    return raw_addrs


def extract_urls_from_text_and_html(text_body: str, html_body: str) -> List[str]:
    """
    Extracts unique HTTP/HTTPS URLs from plain text and HTML bodies.
    Deduplicates URLs while preserving discovery order.
    Does NOT execute URLs or perform network HTTP requests.
    """
    urls: List[str] = []
    seen = set()

    def _add_url(u: str):
        cleaned_url = html.unescape(u).strip().rstrip(".,;)>'\"]")
        if cleaned_url and cleaned_url not in seen:
            seen.add(cleaned_url)
            urls.append(cleaned_url)

    # 1. Plain text body URLs
    if text_body:
        for match in URL_REGEX.findall(text_body):
            _add_url(match)

    # 2. HTML body URLs (href, src attributes & embedded text)
    if html_body:
        for match in HTML_HREF_SRC_REGEX.findall(html_body):
            _add_url(match)
        for match in URL_REGEX.findall(html_body):
            _add_url(match)

    return urls


def parse_raw_email(
    raw_bytes: bytes,
    fallback_message_id: Optional[str] = None,
    attachment_storage_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parses a complete raw RFC 5322 email message.

    Args:
        raw_bytes: Complete raw email payload bytes.
        fallback_message_id: Generated message ID if Message-ID header is missing.
        attachment_storage_dir: Directory for storing extracted attachments safely.

    Returns:
        Structured Email Object dictionary.
    """
    if not raw_bytes:
        raise ValueError("Cannot parse empty raw email bytes")

    # Parse message using modern Python email policy
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as exc:
        logger.warning(f"Default email policy parse failed, retrying with compat32: {exc}")
        msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

    # 1. Headers Extraction
    raw_message_id = msg.get("Message-ID") or msg.get("Resent-Message-ID")
    msg_id = decode_rfc_header(str(raw_message_id)).strip("<> ") if raw_message_id else (fallback_message_id or f"msg_{uuid.uuid4().hex[:12]}")

    from_addr = decode_rfc_header(msg.get("From", ""))
    to_list = _extract_addresses_list(msg, "To")
    cc_list = _extract_addresses_list(msg, "Cc")
    bcc_list = _extract_addresses_list(msg, "Bcc")
    reply_to = decode_rfc_header(msg.get("Reply-To", ""))
    subject = decode_rfc_header(msg.get("Subject", ""))
    email_date = decode_rfc_header(msg.get("Date", ""))
    return_path = decode_rfc_header(msg.get("Return-Path", ""))

    # Received Hop headers list
    received_hops = [decode_rfc_header(str(h)) for h in msg.get_all("Received", [])]
    auth_results = decode_rfc_header(msg.get("Authentication-Results", ""))

    headers_dict: Dict[str, Any] = {}
    for h_key in msg.keys():
        h_val = decode_rfc_header(msg.get(h_key))
        if h_key in headers_dict:
            if isinstance(headers_dict[h_key], list):
                headers_dict[h_key].append(h_val)
            else:
                headers_dict[h_key] = [headers_dict[h_key], h_val]
        else:
            headers_dict[h_key] = h_val

    # 2. Body Text & HTML Extraction
    text_body_parts: List[str] = []
    html_body_parts: List[str] = []

    attachment_parts: List[Tuple[email.message.EmailMessage, str]] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disp = str(part.get_content_disposition() or "")
            filename = part.get_filename()

            # Check if this part is an attachment
            is_attachment = (
                "attachment" in content_disp
                or bool(filename)
                or ("inline" in content_disp and content_type not in ("text/plain", "text/html"))
            )

            if is_attachment:
                attachment_parts.append((part, filename))
            elif content_type == "text/plain":
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        text_body_parts.append(payload)
                except Exception:
                    payload_bytes = part.get_payload(decode=True)
                    if payload_bytes:
                        text_body_parts.append(payload_bytes.decode("utf-8", errors="replace"))
            elif content_type == "text/html":
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        html_body_parts.append(payload)
                except Exception:
                    payload_bytes = part.get_payload(decode=True)
                    if payload_bytes:
                        html_body_parts.append(payload_bytes.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type()
        filename = msg.get_filename()
        content_disp = str(msg.get_content_disposition() or "")

        if "attachment" in content_disp or bool(filename):
            attachment_parts.append((msg, filename))
        elif content_type == "text/html":
            try:
                payload = msg.get_content()
                html_body_parts.append(payload if isinstance(payload, str) else str(payload))
            except Exception:
                payload_bytes = msg.get_payload(decode=True)
                if payload_bytes:
                    html_body_parts.append(payload_bytes.decode("utf-8", errors="replace"))
        else:
            try:
                payload = msg.get_content()
                text_body_parts.append(payload if isinstance(payload, str) else str(payload))
            except Exception:
                payload_bytes = msg.get_payload(decode=True)
                if payload_bytes:
                    text_body_parts.append(payload_bytes.decode("utf-8", errors="replace"))

    text_body = "\n".join(text_body_parts)
    html_body = "\n".join(html_body_parts)

    # 3. URL Extraction (non-executing)
    extracted_urls = extract_urls_from_text_and_html(text_body, html_body)

    # 4. Attachment Extraction & Security Verification
    base_attach_dir = _resolve_attachment_dir(attachment_storage_dir)
    attachments_meta: List[Dict[str, Any]] = []

    for idx, (part, orig_fn) in enumerate(attachment_parts):
        if idx >= MAX_ATTACHMENT_COUNT:
            logger.warning(f"Attachment count limit ({MAX_ATTACHMENT_COUNT}) reached for message {msg_id}")
            break

        try:
            payload_bytes = part.get_payload(decode=True)
            if payload_bytes is None:
                payload_bytes = b""

            if len(payload_bytes) > MAX_ATTACHMENT_SIZE:
                logger.warning(
                    f"Attachment '{orig_fn}' ({len(payload_bytes)} bytes) exceeds limit of {MAX_ATTACHMENT_SIZE} bytes"
                )
                continue

            safe_fn = sanitize_filename(orig_fn or f"attachment_{idx+1}.bin")
            sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

            # Safe non-executable storage filename format: <sha256>_<sanitized_filename>
            stored_filename = f"{sha256_hash[:16]}_{safe_fn}"
            target_filepath = os.path.abspath(os.path.join(base_attach_dir, stored_filename))

            # Path Traversal Check
            if not target_filepath.startswith(base_attach_dir + os.sep) and target_filepath != base_attach_dir:
                logger.error(f"Path traversal attempt blocked for attachment: {orig_fn}")
                continue

            # Save attachment bytes securely
            with open(target_filepath, "wb") as af:
                af.write(payload_bytes)

            attach_info = {
                "filename": safe_fn,
                "original_filename": orig_fn or safe_fn,
                "mime_type": part.get_content_type() or "application/octet-stream",
                "size": len(payload_bytes),
                "sha256": sha256_hash,
                "storage_path": target_filepath,
            }
            attachments_meta.append(attach_info)
            logger.info(f"Safely stored attachment '{safe_fn}' ({len(payload_bytes)} bytes, SHA-256: {sha256_hash[:12]})")

        except Exception as attach_err:
            logger.error(f"Failed to extract attachment #{idx+1} ({orig_fn}): {attach_err}")

    # 5. Build Final Structured Email Object
    structured_email = {
        "message_id": msg_id,
        "from": from_addr,
        "to": to_list,
        "cc": cc_list,
        "bcc": bcc_list,
        "reply_to": reply_to,
        "subject": subject,
        "date": email_date,
        "return_path": return_path,
        "received": received_hops,
        "auth_results": auth_results,
        "headers": headers_dict,
        "text_body": text_body,
        "html_body": html_body,
        "urls": extracted_urls,
        "attachments": attachments_meta,
    }

    return structured_email
