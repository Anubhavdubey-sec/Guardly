"""
Header Integrity, Message-ID, Date & Mail Client Fingerprinting Module for Guardly DFIR
Validates Message-ID RFC syntax, domain alignment, duplicate headers, missing mandatory headers,
and classifies mail user agent / mail client software.
"""

from email.utils import parsedate_to_datetime
import re
from typing import Any, Dict, List

CLIENT_FINGERPRINTS = [
    ("Outlook / Exchange", [r"microsoft\s+outlook", r"ms-exchange", r"outlook", r"msoedit"]),
    ("Apple Mail", [r"apple\s+mail", r"mac\s+os\s+x", r"iphone\s+mail"]),
    ("Thunderbird", [r"thunderbird"]),
    ("Gmail Webmail / Google", [r"google\s+smtp", r"gmail"]),
    ("Office 365", [r"office365", r"microsoft365"]),
    ("PHP / Scripted Mailer", [r"php", r"swiftmailer", r"PHPMailer", r"sendmail", r"python"]),
]


def fingerprint_mail_client(headers_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fingerprints the originating mail client from User-Agent, X-Mailer, X-Originating-IP, and X-Priority headers.
    """
    x_mailer = str(headers_dict.get("X-Mailer", "") or headers_dict.get("x-mailer", ""))
    user_agent = str(headers_dict.get("User-Agent", "") or headers_dict.get("user-agent", ""))
    x_originating_ip = str(headers_dict.get("X-Originating-IP", "") or headers_dict.get("x-originating-ip", ""))
    x_priority = str(headers_dict.get("X-Priority", "") or headers_dict.get("x-priority", ""))
    thread_index = str(headers_dict.get("Thread-Index", "") or headers_dict.get("thread-index", ""))

    combined = f"{x_mailer} {user_agent}".strip()
    client_name = "Unknown"

    for name, patterns in CLIENT_FINGERPRINTS:
        if any(re.search(pat, combined, re.IGNORECASE) for pat in patterns):
            client_name = name
            break

    # Clean originating IP (strip brackets if present)
    clean_originating_ip = re.sub(r"[\[\]\s]", "", x_originating_ip)

    return {
        "client_name": client_name,
        "x_mailer": x_mailer,
        "user_agent": user_agent,
        "x_originating_ip": clean_originating_ip,
        "x_priority": x_priority,
        "thread_index": bool(thread_index),
    }


def validate_message_id_and_headers(headers_dict: Dict[str, Any], from_domain: str = "") -> Dict[str, Any]:
    """
    Validates Message-ID RFC syntax, domain alignment with From domain, missing mandatory headers,
    and duplicate header anomalies.
    """
    msg_id = str(headers_dict.get("Message-ID", "") or headers_dict.get("message-id", "")).strip()

    anomalies: List[Dict[str, Any]] = []
    integrity_score_deductions = 0

    # 1. Message-ID Presence & Syntax Check
    is_valid_syntax = True
    msg_id_domain = ""
    if not msg_id:
        integrity_score_deductions += 20
        anomalies.append({
            "finding": "Missing Message-ID Header",
            "severity": "Medium",
            "explanation": "The email lacks a standard RFC 5322 Message-ID header, which is standard for legitimate MTA software.",
            "evidence": "Message-ID: None",
            "recommendation": "Check for automated bulk mailers or non-compliant spam tools.",
        })
    else:
        # Check standard format: <id@domain>
        match = re.search(r"<([^@>]+)@([^>]+)>", msg_id)
        if not match:
            is_valid_syntax = False
            integrity_score_deductions += 15
            anomalies.append({
                "finding": "Malformed Message-ID Syntax",
                "severity": "Medium",
                "explanation": f"The Message-ID '{msg_id}' does not conform to standard RFC 5322 `<local-part@domain>` syntax.",
                "evidence": f"Message-ID: {msg_id}",
                "recommendation": "Inspect for custom spam script generation.",
            })
        else:
            msg_id_domain = match.group(2).lower()
            if from_domain and msg_id_domain and msg_id_domain != from_domain and not from_domain.endswith("." + msg_id_domain) and not msg_id_domain.endswith("." + from_domain):
                # Common for ESPs (e.g., mailchimp/sendgrid), but noteworthy in DFIR
                anomalies.append({
                    "finding": "Message-ID Domain Mismatch",
                    "severity": "Low",
                    "explanation": f"Message-ID domain '{msg_id_domain}' differs from sender domain '{from_domain}'.",
                    "evidence": f"Message-ID: {msg_id}\nFrom Domain: {from_domain}",
                    "recommendation": "Normal if using third-party Email Service Providers (ESPs); verify DKIM alignment.",
                })

    # 2. Mandatory Header Verification (RFC 5322)
    mandatory_headers = ["From", "Date"]
    for mh in mandatory_headers:
        val = headers_dict.get(mh, "") or headers_dict.get(mh.lower(), "")
        if not val:
            integrity_score_deductions += 20
            anomalies.append({
                "finding": f"Missing Mandatory Header: {mh}",
                "severity": "High",
                "explanation": f"The email is missing the required RFC 5322 header '{mh}'.",
                "evidence": f"Header '{mh}' missing.",
                "recommendation": "Highly indicative of malformed spam or direct socket injection.",
            })

    # 3. Duplicate Header Checks (From, Subject, Date, Message-ID)
    # If headers_dict contains list values, duplicate headers were passed
    for dh in ["From", "Subject", "Date", "Message-ID"]:
        val = headers_dict.get(dh)
        if isinstance(val, list) and len(val) > 1:
            integrity_score_deductions += 25
            anomalies.append({
                "finding": f"Duplicate Header Detected: {dh}",
                "severity": "High",
                "explanation": f"Multiple instances of single-value RFC 5322 header '{dh}' were present.",
                "evidence": f"Count: {len(val)}",
                "recommendation": "Defeats mail gateway parsing filters. High indicator of email spoofing.",
            })

    integrity_score = max(0, 100 - integrity_score_deductions)

    return {
        "message_id": msg_id,
        "message_id_domain": msg_id_domain,
        "is_valid_syntax": is_valid_syntax,
        "integrity_score": integrity_score,
        "anomalies": anomalies,
    }
