import csv
import hashlib
import io
import json
import os
import re
import socket
import time
import urllib.parse
import urllib.request
import secrets
import ssl
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from sqlalchemy import and_, or_
from werkzeug.utils import secure_filename

from models.scan import EmailScan
from models.investigation_case import (
    CaseIndicator,
    CaseScan,
    InvestigationCase,
)
from models.user import User, db
from routes.auth import login_required, roles_required

from scanner.url_heuristics import (
    HIGH_RISK_TLDS,
    KNOWN_IMPERSONATED_BRANDS,
    analyze_redirect_chain,
    assess_url,
    calculate_domain_entropy,
    check_brand_impersonation,
    is_ip_literal,
    is_shortener,
)

from services.audit import record_event
from services.email_analysis import EmailAnalysisService
from services.limiter import limiter
from services.report_generator import build_scan_report
from services.public_lookup import (
    PublicLookupClient,
    get_ip_location,
)
from services.ssrf import (
    is_ip_private_or_internal,
    safe_http_get,
    validate_url_ssrf,
)
from services.yara_generator import (
    generate_sigma_rule,
    generate_yara_rule,
)


scanner_bp = Blueprint("scanner", __name__)

ALLOWED_EXTENSIONS = {".eml"}

VERDICTS = (
    "Low Risk",
    "Medium Risk",
    "High Risk",
)

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".dll",
    ".msi",
    ".msp",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".jar",
    ".lnk",
    ".iso",
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|zip)"
    r"\.(?:exe|scr|bat|cmd|com|cpl|dll|msi|msp|js|jse|vbs|vbe|"
    r"wsf|wsh|hta|jar|lnk)$",
    re.IGNORECASE,
)


def is_allowed_email(filename):
    return os.path.splitext(filename.lower())[1] in ALLOWED_EXTENSIONS


def _safe_csv_cell(value):
    """
    Prevent spreadsheet programs from interpreting scanned email
    data as formulas.
    """
    if value is None:
        return ""

    text = str(value)

    if text.lstrip(" \t\r\n").startswith(
        ("=", "+", "-", "@")
    ):
        return "'" + text

    return text


def _as_list(value):
    """
    Normalize a value into a list.

    The database historically stores some fields as strings while
    the canonical parser uses lists.
    """
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    if isinstance(value, set):
        return list(value)

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return []

        return [value]

    return [value]


def _normalize_attachment(attachment):
    """
    Normalize attachment information coming from either the
    canonical parser or the historical scanner schema.
    """
    if isinstance(attachment, str):
        return {
            "filename": attachment,
            "original_filename": attachment,
        }

    if not isinstance(attachment, dict):
        return {
            "filename": str(attachment),
            "original_filename": str(attachment),
        }

    filename = (
        attachment.get("filename")
        or attachment.get("original_filename")
        or attachment.get("name")
        or "unknown"
    )

    normalized = dict(attachment)

    normalized.setdefault("filename", filename)
    normalized.setdefault("original_filename", filename)

    return normalized


def _attachment_filename(attachment):
    normalized = _normalize_attachment(attachment)

    return (
        normalized.get("original_filename")
        or normalized.get("filename")
        or normalized.get("name")
        or ""
    )


def _build_compatibility_categories(email_data, analysis):
    """
    Preserve the category names historically used by Guardly's
    UI/tests/reports while the canonical ThreatAnalysisEngine
    remains responsible for the actual analysis.

    This is a compatibility adapter, not a second phishing engine.
    """
    categories = []

    existing_categories = []

    if isinstance(analysis, dict):
        raw_categories = (
            analysis.get("categories")
            or analysis.get("risk_categories")
            or []
        )

        if isinstance(raw_categories, str):
            existing_categories = [raw_categories]
        elif isinstance(raw_categories, (list, tuple, set)):
            existing_categories = [
                str(item) for item in raw_categories
            ]

    for category in existing_categories:
        if category not in categories:
            categories.append(category)

    attachments = []

    if isinstance(email_data, dict):
        attachments = email_data.get("attachments") or []

    executable_found = False
    double_extension_found = False

    for attachment in attachments:
        filename = _attachment_filename(attachment).strip()

        if not filename:
            continue

        lower_name = filename.lower()

        suffix = Path(lower_name).suffix

        if suffix in EXECUTABLE_EXTENSIONS:
            executable_found = True

        if DOUBLE_EXTENSION_PATTERN.search(lower_name):
            double_extension_found = True

    if executable_found and "Executable attachments" not in categories:
        categories.append("Executable attachments")

    if (
        double_extension_found
        and "Double extension attachments" not in categories
    ):
        categories.append("Double extension attachments")

    return categories


def _parse_auth_results(value):
    """
    Normalize Authentication-Results into the dictionary expected
    by existing report/PDF generators.

    Supports:
      - canonical dictionary data
      - Authentication-Results header strings
      - None
    """
    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
    }

    if isinstance(value, dict):
        for key in ("spf", "dkim", "dmarc"):
            raw = value.get(key)

            if raw is None:
                continue

            if isinstance(raw, dict):
                raw = (
                    raw.get("result")
                    or raw.get("status")
                    or raw.get("value")
                    or "unknown"
                )

            result[key] = str(raw)

        return result

    if value is None:
        return result

    text = str(value).lower()

    for key in ("spf", "dkim", "dmarc"):
        match = re.search(
            rf"\b{key}\s*=\s*([a-z0-9_-]+)",
            text,
            flags=re.IGNORECASE,
        )

        if match:
            result[key] = match.group(1)

    return result


def _canonical_analysis_to_legacy(
    parsed_email,
    analysis,
    reputation_data=None,
    timeline_data=None,
):
    """
    Convert canonical EmailAnalysisService output into the schema
    expected by existing Guardly templates, reports and database
    records.

    The actual detection remains in services.threat_analysis.
    """
    parsed_email = parsed_email or {}
    analysis = analysis or {}

    try:
        score = int(
            float(
                analysis.get(
                    "risk_score",
                    analysis.get("score", 0),
                )
            )
        )
    except (TypeError, ValueError):
        score = 0

    score = max(0, min(100, score))

    severity = str(
        analysis.get("severity") or ""
    ).upper()

    if severity == "CRITICAL":
        verdict = "High Risk"
    elif severity == "HIGH":
        verdict = "High Risk"
    elif severity == "MEDIUM":
        verdict = "Medium Risk"
    elif severity == "LOW":
        verdict = "Low Risk"
    else:
        existing_verdict = analysis.get("verdict")

        if existing_verdict in VERDICTS:
            verdict = existing_verdict
        elif score >= 50:
            verdict = "High Risk"
        elif score >= 20:
            verdict = "Medium Risk"
        else:
            verdict = "Low Risk"

    findings = analysis.get("findings", [])

    if not isinstance(findings, list):
        findings = [str(findings)]

    email_data = {
        "from": parsed_email.get("from") or "",
        "from_address": parsed_email.get("from_address") or "",
        "from_name": parsed_email.get("from_name") or "",
        "to": parsed_email.get("to") or [],
        "cc": parsed_email.get("cc") or [],
        "bcc": parsed_email.get("bcc") or [],
        "subject": parsed_email.get("subject") or "",
        "date": parsed_email.get("date") or "",
        "reply_to": parsed_email.get("reply_to") or "",
        "body": (
            parsed_email.get("text_body")
            or parsed_email.get("body")
            or ""
        ),
        "urls": parsed_email.get("urls") or [],
        "attachments": parsed_email.get("attachments") or [],
        "headers": parsed_email.get("headers") or {},
        "has_html": bool(parsed_email.get("html_body")),
        "has_plain_text": bool(parsed_email.get("text_body")),
        "iocs": parsed_email.get("iocs") or {},
    }

    categories = _build_compatibility_categories(
        email_data,
        analysis,
    )

    authentication = analysis.get("authentication")

    if not isinstance(authentication, dict):
        authentication = _parse_auth_results(
            analysis.get("auth_results")
        )
    else:
        authentication = _parse_auth_results(authentication)

    url_assessments = (
        analysis.get("url_assessments")
        or analysis.get("url_analysis")
        or []
    )

    if isinstance(url_assessments, dict):
        url_assessments = [url_assessments]

    if reputation_data is None:
        reputation_data = {
            "provider": "Public RDAP and IP network context",
            "message": (
                "Public reputation context was not available "
                "for this scan."
            ),
            "lookups": [],
        }

    result = {
        # Legacy fields.
        "score": score,
        "risk_score": score,
        "verdict": verdict,
        "severity": severity or (
            "HIGH"
            if score >= 50
            else "MEDIUM"
            if score >= 20
            else "LOW"
        ),
        "findings": findings,
        "categories": categories,
        "risk_categories": categories,
        "url_assessments": url_assessments,
        "auth_results": authentication,
        "reputation_data": reputation_data,

        # Canonical fields.
        "recommendation": analysis.get(
            "recommendation",
            "ALLOW",
        ),
        "authentication": authentication,
        "sender_analysis": analysis.get(
            "sender_analysis",
            {},
        ),
        "content_analysis": analysis.get(
            "content_analysis",
            {},
        ),
        "url_analysis": analysis.get(
            "url_analysis",
            {},
        ),
        "attachment_analysis": analysis.get(
            "attachment_analysis",
            {},
        ),
        "iocs": analysis.get(
            "iocs",
            parsed_email.get("iocs", {}),
        ),
    }

    if timeline_data is not None:
        result["delivery_timeline"] = timeline_data

    return result


def _canonical_email_from_legacy(email_data):
    """
    Convert an EmailScan/database representation into the canonical
    parser schema required by ThreatAnalysisEngine.
    """
    email_data = email_data or {}

    headers = email_data.get("headers") or {}

    if not isinstance(headers, dict):
        headers = {}

    from_value = (
        email_data.get("from")
        or email_data.get("from_address")
        or ""
    )

    to_value = email_data.get("to") or []

    if isinstance(to_value, str):
        to_value = [
            item.strip()
            for item in re.split(r"[;,]", to_value)
            if item.strip()
        ]

    attachments = [
        _normalize_attachment(item)
        for item in (
            email_data.get("attachments")
            or []
        )
    ]

    canonical = {
        "id": email_data.get("id"),
        "message_id": (
            email_data.get("message_id")
            or headers.get("Message-ID")
            or headers.get("message-id")
        ),
        "from": from_value,
        "from_address": email_data.get(
            "from_address",
            "",
        ),
        "from_name": email_data.get(
            "from_name",
            "",
        ),
        "to": to_value,
        "cc": _as_list(email_data.get("cc")),
        "bcc": _as_list(email_data.get("bcc")),
        "reply_to": email_data.get(
            "reply_to",
            "",
        ),
        "subject": email_data.get(
            "subject",
            "",
        ),
        "date": email_data.get(
            "date",
            "",
        ),
        "return_path": (
            email_data.get("return_path")
            or headers.get("Return-Path")
            or headers.get("return-path")
            or ""
        ),
        "received": _as_list(
            email_data.get(
                "received",
                headers.get("Received")
                or headers.get("received"),
            )
        ),
        "auth_results": (
            email_data.get("auth_results")
            or headers.get("Authentication-Results")
            or headers.get("authentication-results")
            or ""
        ),
        "headers": headers,
        "text_body": (
            email_data.get("text_body")
            or email_data.get("body")
            or ""
        ),
        "html_body": email_data.get(
            "html_body",
            "",
        ),
        "urls": email_data.get(
            "urls",
            [],
        ),
        "attachments": attachments,
        "iocs": email_data.get(
            "iocs",
            {},
        ),
    }

    return canonical


def _build_timeline(email_data):
    """
    Reconstruct the delivery timeline using Received headers.
    """
    timeline_data = email_data.get(
        "delivery_timeline"
    )

    if timeline_data:
        return timeline_data

    try:
        from scanner.timeline import (
            TimelineAnalysis,
            calculate_delivery_delays,
            generate_delivery_summary,
            parse_received_headers,
        )

        received_headers = []

        headers = email_data.get("headers")

        if isinstance(headers, dict):
            raw_received = (
                headers.get("Received")
                or headers.get("received")
                or []
            )

            if isinstance(raw_received, str):
                received_headers = [raw_received]
            elif isinstance(raw_received, list):
                received_headers = raw_received

        if not received_headers:
            received_headers = _as_list(
                email_data.get("received")
            )

        parsed_hops = parse_received_headers(
            received_headers
        )

        if parsed_hops:
            chronological_hops = list(
                reversed(parsed_hops)
            )

            for idx, hop in enumerate(
                chronological_hops,
                start=1,
            ):
                hop.hop_number = idx

            hops_with_delays = calculate_delivery_delays(
                chronological_hops
            )

            summary = generate_delivery_summary(
                hops_with_delays
            )

            return TimelineAnalysis(
                hops=hops_with_delays,
                summary=summary,
                has_timeline=True,
                summary_message=(
                    f"Reconstructed "
                    f"{len(hops_with_delays)} "
                    f"mail server relay hops."
                ),
            ).to_dict()

        return TimelineAnalysis(
            has_timeline=False,
            summary_message=(
                "No delivery path available."
            ),
        ).to_dict()

    except Exception as error:
        current_app.logger.warning(
            "Could not reconstruct email timeline: %s",
            error,
        )

        return {
            "has_timeline": False,
            "summary_message": (
                "Delivery timeline unavailable."
            ),
            "hops": [],
        }


def _get_analysis_service():
    """
    Construct the canonical email analysis service.
    """
    attachment_storage_dir = current_app.config.get(
        "EXTRACTED_ATTACHMENTS_FOLDER"
    )

    if not attachment_storage_dir:
        attachment_storage_dir = current_app.config.get(
            "UPLOAD_FOLDER"
        )

    return EmailAnalysisService(
        attachment_storage_dir=attachment_storage_dir,
    )


def _analyze_canonical_email(parsed_email):
    """
    Run the canonical email parser/analyzer pipeline.
    """
    service = _get_analysis_service()

    return service.analyze_parsed(
        parsed_email
    )


def _analyze_uploaded_file(file_path):
    """
    Run the canonical raw-email analysis pipeline.
    """
    service = _get_analysis_service()

    return service.analyze_file(
        file_path
    )


def _lookup_public_context(email_data):
    """
    Perform optional public enrichment.

    Public lookup failure must never prevent local email analysis.
    """
    if not current_app.config.get(
        "PUBLIC_LOOKUPS_ENABLED",
        False,
    ):
        return {
            "provider": (
                "Public RDAP and IP network context"
            ),
            "message": (
                "Public context lookups are disabled. "
                "Local checks were completed."
            ),
            "lookups": [],
        }

    iocs = email_data.get("iocs") or {}

    domains = iocs.get("domains", [])
    ip_addresses = iocs.get(
        "ip_addresses",
        [],
    )

    try:
        public_lookup = PublicLookupClient(
            current_app.config[
                "PUBLIC_LOOKUP_TIMEOUT_SECONDS"
            ],
            current_app.config[
                "PUBLIC_LOOKUP_MAX_LOOKUPS"
            ],
        )

        return public_lookup.lookup_context(
            domains,
            ip_addresses,
        )

    except Exception as error:
        current_app.logger.warning(
            "Public reputation lookup failed: %s",
            error,
        )

        return {
            "provider": (
                "Public RDAP and IP network context"
            ),
            "message": (
                "Public context was unavailable. "
                "Local checks were still completed."
            ),
            "lookups": [],
        }


def _build_upload_email_data(parsed_email):
    """
    Convert canonical parser output into the legacy email_data
    structure consumed by existing templates.
    """
    parsed_email = parsed_email or {}

    headers = dict(
        parsed_email.get("headers") or {}
    )

    headers["from_address"] = (
        parsed_email.get("from_address")
        or ""
    )

    headers["from_name"] = (
        parsed_email.get("from_name")
        or ""
    )

    headers["content"] = {
        "has_html": bool(
            parsed_email.get("html_body")
        ),
        "has_plain_text": bool(
            parsed_email.get("text_body")
        ),
    }

    return {
        "message_id": parsed_email.get(
            "message_id"
        ),
        "from": parsed_email.get(
            "from",
            "",
        ),
        "from_address": parsed_email.get(
            "from_address",
            "",
        ),
        "from_name": parsed_email.get(
            "from_name",
            "",
        ),
        "to": parsed_email.get(
            "to",
            [],
        ),
        "cc": parsed_email.get(
            "cc",
            [],
        ),
        "bcc": parsed_email.get(
            "bcc",
            [],
        ),
        "subject": parsed_email.get(
            "subject",
            "",
        ),
        "date": parsed_email.get(
            "date",
            "",
        ),
        "reply_to": parsed_email.get(
            "reply_to",
            "",
        ),
        "return_path": parsed_email.get(
            "return_path",
            "",
        ),
        "received": parsed_email.get(
            "received",
            [],
        ),
        "body": (
            parsed_email.get(
                "text_body"
            )
            or ""
        ),
        "text_body": (
            parsed_email.get(
                "text_body"
            )
            or ""
        ),
        "html_body": (
            parsed_email.get(
                "html_body"
            )
            or ""
        ),
        "urls": parsed_email.get(
            "urls",
            [],
        ),
        "attachments": parsed_email.get(
            "attachments",
            [],
        ),
        "headers": headers,
        "has_html": bool(
            parsed_email.get(
                "html_body"
            )
        ),
        "has_plain_text": bool(
            parsed_email.get(
                "text_body"
            )
        ),
        "auth_results": parsed_email.get(
            "auth_results",
            "",
        ),
        "iocs": parsed_email.get(
            "iocs",
            {},
        ),
    }


def _scan_email_data(scan):
    """
    Convert an existing database scan into the email_data structure
    expected by the UI.
    """
    headers = scan.headers_data

    if not isinstance(headers, dict):
        headers = {}

    content = headers.get(
        "content",
        {},
    )

    if not isinstance(content, dict):
        content = {}

    email_ips = (
        scan.iocs_data.get(
            "ip_addresses",
            []
        )
        if isinstance(scan.iocs_data, dict)
        else []
    )

    ip_locations = []

    for ip in email_ips:
        try:
            location = get_ip_location(ip)
        except Exception:
            location = None

        if location:
            ip_locations.append(location)

    return {
        "message_id": (
            headers.get("Message-ID")
            or headers.get("message-id")
        ),
        "from": scan.sender
        or "Unknown sender",
        "from_address": headers.get(
            "from_address",
            "",
        ),
        "from_name": headers.get(
            "from_name",
            "",
        ),
        "to": scan.receiver
        or "Unknown recipient",
        "subject": scan.subject
        or "(no subject)",
        "date": scan.email_date
        or "Unknown date",
        "reply_to": scan.reply_to
        or "",
        "body": scan.email_body
        or "",
        "text_body": scan.email_body
        or "",
        "html_body": "",
        "urls": scan.urls_list,
        "attachments": [
            _normalize_attachment(item)
            for item in scan.attachments_list
        ],
        "headers": headers,
        "has_html": content.get(
            "has_html",
            False,
        ),
        "has_plain_text": content.get(
            "has_plain_text",
            False,
        ),
        "iocs": scan.iocs_data,
        "ip_locations": ip_locations,
    }


def _scan_analysis(scan, email_data):
    """
    Re-analyze a historical scan through the canonical engine.

    The database scan's stored risk result remains the source of
    historical persistence, while the canonical engine supplies the
    current presentation details.
    """
    canonical_email = _canonical_email_from_legacy(
        email_data
    )

    try:
        canonical_analysis = _analyze_canonical_email(
            canonical_email
        )

        reputation_data = (
            scan.reputation_data_json
            or {
                "provider": (
                    "Public RDAP and IP network context"
                ),
                "message": (
                    "This older scan does not include "
                    "public registration or IP context."
                ),
                "lookups": [],
            }
        )

        timeline_data = _build_timeline(
            email_data
        )

        result = _canonical_analysis_to_legacy(
            canonical_email,
            canonical_analysis,
            reputation_data=reputation_data,
            timeline_data=timeline_data,
        )

        # Preserve the score/verdict/categories stored when the
        # historical scan was originally created if available.
        #
        # This prevents opening an old scan from silently changing
        # its persisted historical classification.
        if scan.risk_score is not None:
            result["score"] = int(
                max(
                    0,
                    min(
                        100,
                        scan.risk_score,
                    ),
                )
            )
            result["risk_score"] = result["score"]

        if scan.verdict in VERDICTS:
            result["verdict"] = scan.verdict

        stored_categories = scan.risk_categories_list

        if stored_categories:
            merged_categories = []

            for category in stored_categories:
                if category not in merged_categories:
                    merged_categories.append(category)

            for category in result.get(
                "categories",
                [],
            ):
                if category not in merged_categories:
                    merged_categories.append(category)

            result["categories"] = merged_categories
            result["risk_categories"] = merged_categories

        return result

    except Exception as error:
        current_app.logger.warning(
            "Canonical historical scan analysis failed: %s",
            error,
        )

        # Safe compatibility fallback using persisted data.
        return {
            "score": scan.risk_score,
            "risk_score": scan.risk_score,
            "verdict": scan.verdict,
            "findings": scan.findings_list,
            "categories": scan.risk_categories_list,
            "risk_categories": scan.risk_categories_list,
            "url_assessments": [],
            "auth_results": _parse_auth_results(
                (
                    email_data.get(
                        "headers",
                        {},
                    ).get(
                        "Authentication-Results"
                    )
                    if isinstance(
                        email_data.get(
                            "headers"
                        ),
                        dict,
                    )
                    else None
                )
            ),
            "reputation_data": (
                scan.reputation_data_json
                or {}
            ),
            "delivery_timeline": _build_timeline(
                email_data
            ),
            "authentication": {},
            "sender_analysis": {},
            "content_analysis": {},
            "url_analysis": {},
            "attachment_analysis": {},
            "iocs": email_data.get(
                "iocs",
                {},
            ),
        }


def _scan_scope_query():
    user = getattr(g, "current_user", None)
    if not user:
        # Guests and unauthenticated requests cannot query general scan history
        return EmailScan.query.filter(db.false())
    if user.role == User.ROLE_ADMIN:
        # Administrators can review their own scans, unassigned public visitor scans, and case-linked scans
        return EmailScan.query.filter(
            or_(
                EmailScan.user_id == user.id,
                EmailScan.user_id.is_(None),
                EmailScan.case_links.any(
                    CaseScan.case.has(
                        or_(
                            InvestigationCase.created_by_id == user.id,
                            InvestigationCase.assigned_to_id == user.id,
                        )
                    )
                ),
            )
        )
    # Users only see their own scans, or scans linked to a case they created or are assigned to
    return EmailScan.query.filter(
        or_(
            EmailScan.user_id == user.id,
            EmailScan.case_links.any(
                CaseScan.case.has(
                    or_(
                        InvestigationCase.created_by_id == user.id,
                        InvestigationCase.assigned_to_id == user.id,
                    )
                )
            ),
        )
    )


def _accessible_scan_or_404(scan_id):
    scan = _scan_scope_query().filter(EmailScan.id == scan_id).first()
    if not scan:
        abort(404)
    return scan


def _history_filters():
    search = request.args.get(
        "q",
        "",
    ).strip()

    verdict = request.args.get(
        "verdict",
        "",
    ).strip()

    category = request.args.get(
        "category",
        "",
    ).strip()

    query = _scan_scope_query()

    if search:
        safe_search = (
            search
            .replace(
                "\\",
                r"\\",
            )
            .replace(
                "%",
                r"\%",
            )
            .replace(
                "_",
                r"\_",
            )
        )

        pattern = f"%{safe_search}%"

        conditions = [
            EmailScan.subject.ilike(
                pattern
            ),
            EmailScan.sender.ilike(
                pattern
            ),
            EmailScan.receiver.ilike(
                pattern
            ),
            EmailScan.reply_to.ilike(
                pattern
            ),
            EmailScan.urls.ilike(
                pattern
            ),
            EmailScan.iocs.ilike(
                pattern
            ),
            User.username.ilike(
                pattern
            ),
            User.email.ilike(
                pattern
            ),
        ]

        if search.isdigit():
            conditions.append(
                EmailScan.id == int(search)
            )

        if any(
            term in search.lower()
            for term in [
                "public",
                "visitor",
                "anon",
                "guest",
                "unassigned",
            ]
        ):
            conditions.append(
                EmailScan.user_id.is_(None)
            )

        query = (
            query
            .outerjoin(User)
            .filter(or_(*conditions))
        )

    if verdict in VERDICTS:
        query = query.filter(
            EmailScan.verdict == verdict
        )

    scans = (
        query
        .order_by(
            EmailScan.scan_time.desc()
        )
        .all()
    )

    if category:
        scans = [
            scan
            for scan in scans
            if category
            in scan.risk_categories_list
        ]

    all_scans = (
        _scan_scope_query()
        .all()
    )

    categories = sorted(
        {
            item
            for scan in all_scans
            for item in scan.risk_categories_list
        }
    )

    filters = {
        "q": search,
        "verdict": verdict,
        "category": category,
    }

    return scans, categories, filters


def _report_payload(scan):
    email_data = _scan_email_data(
        scan
    )

    analysis = _scan_analysis(
        scan,
        email_data,
    )

    return {
        "scan_id": scan.id,
        "scanned_at": scan.scan_time.isoformat(),
        "email": email_data,
        "analysis": analysis,
    }


@scanner_bp.route(
    "/upload",
    methods=["GET", "POST"],
)
@limiter.limit("10 per minute")
def upload():
    if request.method == "GET":
        return render_template(
            "upload.html"
        )

    uploaded_file = request.files.get(
        "email_file"
    )

    if (
        not uploaded_file
        or not uploaded_file.filename
    ):
        return (
            render_template(
                "upload.html",
                error=(
                    "Choose an .eml file to scan."
                ),
            ),
            400,
        )

    raw_filename = uploaded_file.filename

    if not is_allowed_email(
        raw_filename
    ):
        return (
            render_template(
                "upload.html",
                error=(
                    "Only .eml email files are accepted."
                ),
            ),
            400,
        )

    original_name = secure_filename(
        raw_filename
    )

    if (
        not original_name
        or not is_allowed_email(
            original_name
        )
    ):
        original_name = (
            "uploaded_email.eml"
        )

    upload_dir = os.path.abspath(
        current_app.config[
            "UPLOAD_FOLDER"
        ]
    )

    os.makedirs(
        upload_dir,
        exist_ok=True,
    )

    unique_name = (
        f"{uuid.uuid4().hex}_"
        f"{original_name}"
    )

    file_path = os.path.abspath(
        os.path.join(
            upload_dir,
            unique_name,
        )
    )

    if (
        os.path.commonpath(
            (
                upload_dir,
                file_path,
            )
        )
        != upload_dir
    ):
        return (
            render_template(
                "upload.html",
                error=(
                    "Invalid file upload path."
                ),
            ),
            400,
        )

    parsed_email = None

    try:
        uploaded_file.save(
            file_path
        )

        # =========================================================
        # CANONICAL EMAIL PIPELINE
        #
        # Raw .eml
        #   -> services.email_parser
        #   -> services.threat_analysis
        #   -> compatibility adapter
        #
        # No scanner.phishing_detector dependency remains here.
        # =========================================================
        canonical_analysis = (
            _analyze_uploaded_file(
                file_path
            )
        )

        # EmailAnalysisService currently returns the canonical
        # analysis result but also exposes the parsed fields in the
        # same result shape. Build the email representation from it.
        #
        # If the service result contains a nested parsed_email,
        # use it. Otherwise reconstruct the parser representation
        # from the returned fields.
        parsed_email = (
            canonical_analysis.get(
                "parsed_email"
            )
            if isinstance(
                canonical_analysis,
                dict,
            )
            else None
        )

        if not isinstance(
            parsed_email,
            dict,
        ):
            parsed_email = {
                "message_id": canonical_analysis.get(
                    "message_id"
                ),
                "from": canonical_analysis.get(
                    "from"
                ),
                "from_address": canonical_analysis.get(
                    "from_address"
                ),
                "from_name": canonical_analysis.get(
                    "from_name"
                ),
                "to": canonical_analysis.get(
                    "to",
                    [],
                ),
                "cc": canonical_analysis.get(
                    "cc",
                    [],
                ),
                "bcc": canonical_analysis.get(
                    "bcc",
                    [],
                ),
                "reply_to": canonical_analysis.get(
                    "reply_to"
                ),
                "return_path": canonical_analysis.get(
                    "return_path"
                ),
                "subject": canonical_analysis.get(
                    "subject"
                ),
                "date": canonical_analysis.get(
                    "date"
                ),
                "received": canonical_analysis.get(
                    "received",
                    [],
                ),
                "headers": canonical_analysis.get(
                    "headers",
                    {},
                ),
                "auth_results": canonical_analysis.get(
                    "auth_results",
                    "",
                ),
                "text_body": canonical_analysis.get(
                    "text_body",
                    "",
                ),
                "html_body": canonical_analysis.get(
                    "html_body",
                    "",
                ),
                "urls": canonical_analysis.get(
                    "urls",
                    [],
                ),
                "attachments": canonical_analysis.get(
                    "attachments",
                    [],
                ),
                "iocs": canonical_analysis.get(
                    "iocs",
                    {},
                ),
            }

        # Normalize the canonical result.
        email_data = _build_upload_email_data(
            parsed_email
        )

        reputation_data = (
            _lookup_public_context(
                email_data
            )
        )

        analysis = (
            _canonical_analysis_to_legacy(
                parsed_email,
                canonical_analysis,
                reputation_data=reputation_data,
                timeline_data=_build_timeline(
                    email_data
                ),
            )
        )

    except Exception as error:
        current_app.logger.warning(
            "Could not scan uploaded email: %s",
            error,
            exc_info=True,
        )

        return (
            render_template(
                "upload.html",
                error=(
                    "The selected file could not "
                    "be read as an email."
                ),
            ),
            400,
        )

    finally:
        if os.path.exists(
            file_path
        ):
            try:
                os.remove(
                    file_path
                )
            except OSError:
                current_app.logger.warning(
                    "Could not remove temporary upload: %s",
                    file_path,
                )

    headers = dict(
        email_data.get(
            "headers",
            {},
        )
    )

    headers["from_address"] = (
        email_data.get(
            "from_address",
            "",
        )
    )

    headers["from_name"] = (
        email_data.get(
            "from_name",
            "",
        )
    )

    headers["content"] = {
        "has_html": email_data.get(
            "has_html",
            False,
        ),
        "has_plain_text": email_data.get(
            "has_plain_text",
            False,
        ),
    }

    # Preserve the original Authentication-Results header while
    # also ensuring the PDF/report compatibility schema is available.
    auth_header = (
        email_data.get(
            "auth_results"
        )
        or headers.get(
            "Authentication-Results"
        )
        or headers.get(
            "authentication-results"
        )
    )

    if auth_header:
        headers[
            "Authentication-Results"
        ] = auth_header

    risk_score = int(
        max(
            0,
            min(
                100,
                analysis.get(
                    "score",
                    analysis.get(
                        "risk_score",
                        0,
                    ),
                ),
            ),
        )
    )

    verdict = analysis.get(
        "verdict",
        "Low Risk",
    )

    if verdict not in VERDICTS:
        if risk_score >= 50:
            verdict = "High Risk"
        elif risk_score >= 20:
            verdict = "Medium Risk"
        else:
            verdict = "Low Risk"

    findings = analysis.get(
        "findings",
        [],
    )

    if not isinstance(
        findings,
        list,
    ):
        findings = [
            str(findings)
        ]

    categories = analysis.get(
        "categories",
        [],
    )

    if not isinstance(
        categories,
        list,
    ):
        categories = [
            str(categories)
        ]

    attachments = email_data.get(
        "attachments",
        [],
    )

    # Explicit compatibility guarantee for existing UI/tests.
    compatibility_categories = (
        _build_compatibility_categories(
            email_data,
            analysis,
        )
    )

    for category in compatibility_categories:
        if category not in categories:
            categories.append(
                category
            )

    analysis["score"] = risk_score
    analysis["risk_score"] = risk_score
    analysis["verdict"] = verdict
    analysis["findings"] = findings
    analysis["categories"] = categories
    analysis["risk_categories"] = categories

    # Ensure PDF/report consumers receive a dictionary rather than
    # a raw Authentication-Results string.
    analysis["auth_results"] = (
        _parse_auth_results(
            analysis.get(
                "auth_results"
            )
        )
    )

    analysis["authentication"] = (
        analysis.get(
            "authentication"
        )
        or analysis["auth_results"]
    )

    reputation_data = analysis.get(
        "reputation_data",
        {},
    )

    _current_user = getattr(g, "current_user", None)
    _guest_token = (
        None if _current_user
        else secrets.token_urlsafe(32)
    )

    scan = EmailScan(
        user_id=(
            _current_user.id
            if _current_user
            else None
        ),
        guest_token=_guest_token,
        sender=(
            ", ".join(email_data.get("from"))
            if isinstance(email_data.get("from"), list)
            else (email_data.get("from") or "")
        ),
        receiver=(
            ", ".join(email_data.get("to"))
            if isinstance(email_data.get("to"), list)
            else (email_data.get("to") or "")
        ),
        subject=email_data.get(
            "subject",
            "",
        ),
        email_date=email_data.get(
            "date",
            "",
        ),
        reply_to=email_data.get(
            "reply_to",
            "",
        ),
        email_body=(
            email_data.get(
                "body"
            )
            or email_data.get(
                "text_body"
            )
            or ""
        ),
        risk_score=risk_score,
        verdict=verdict,
        findings=json.dumps(
            findings
        ),
        urls=json.dumps(
            email_data.get(
                "urls",
                [],
            )
        ),
        attachments=json.dumps(
            attachments
        ),
        headers=json.dumps(
            headers
        ),
        iocs=json.dumps(
            email_data.get(
                "iocs",
                {},
            )
        ),
        risk_categories=json.dumps(
            categories
        ),
        reputation_data=json.dumps(
            reputation_data
        ),
    )

    db.session.add(
        scan
    )

    db.session.flush()

    record_event(
        "scan_created",
        target_type="scan",
        target_id=scan.id,
        detail=(
            f"Scanned email: "
            f"{scan.subject}"
        ),
        actor_name=(
            "Public visitor"
            if not getattr(
                g,
                "current_user",
                None,
            )
            else ""
        ),
    )

    db.session.commit()

    # Bind guest token to session so the guest can retrieve their result
    if _guest_token:
        tokens = session.get("guest_scan_tokens", [])
        tokens.append(_guest_token)
        session["guest_scan_tokens"] = tokens

    return render_template(
        "scan_result.html",
        email_data=email_data,
        analysis=analysis,
        scan=scan,
        is_public_result=(
            not getattr(
                g,
                "current_user",
                None,
            )
        ),
        linked_cases=[],
    )


@scanner_bp.route("/history")
@login_required
def history():
    scans, categories, filters = (
        _history_filters()
    )

    return render_template(
        "history.html",
        scans=scans,
        categories=categories,
        filters=filters,
        verdicts=VERDICTS,
        can_download=True,
        can_delete=True,
    )


@scanner_bp.route(
    "/history/export.csv"
)
@login_required
def export_history_csv():
    scans, _categories, _filters = (
        _history_filters()
    )

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow(
        [
            "Scan ID",
            "Scanned at",
            "Submitted by",
            "Sender",
            "Recipient",
            "Subject",
            "Score",
            "Verdict",
            "Categories",
            "URLs",
        ]
    )

    for scan in scans:
        row = [
            scan.id,
            scan.scan_time.isoformat(),
            (
                scan.user.username
                if scan.user
                else "Public visitor"
            ),
            scan.sender,
            scan.receiver,
            scan.subject,
            scan.risk_score,
            scan.verdict,
            "; ".join(
                scan.risk_categories_list
            ),
            "; ".join(
                scan.urls_list
            ),
        ]

        writer.writerow(
            [
                _safe_csv_cell(
                    value
                )
                for value in row
            ]
        )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; "
                "filename=guardly-scan-history.csv"
            )
        },
    )


@scanner_bp.route(
    "/scans/<int:scan_id>"
)
@login_required
def view_scan(scan_id):
    scan = _accessible_scan_or_404(
        scan_id
    )

    email_data = _scan_email_data(
        scan
    )

    analysis = _scan_analysis(
        scan,
        email_data,
    )

    linked_cases = (
        InvestigationCase.query
        .join(CaseScan)
        .filter(
            CaseScan.scan_id == scan.id,
            or_(
                InvestigationCase.created_by_id
                == g.current_user.id,
                InvestigationCase.assigned_to_id
                == g.current_user.id,
            ),
        )
        .order_by(
            InvestigationCase.updated_at.desc()
        )
        .all()
    )

    return render_template(
        "scan_result.html",
        email_data=email_data,
        analysis=analysis,
        scan=scan,
        is_public_result=False,
        linked_cases=linked_cases,
    )


@scanner_bp.route(
    "/scans/<int:scan_id>/export.json"
)
@login_required
def export_scan_json(scan_id):
    return jsonify(
        _report_payload(
            _accessible_scan_or_404(
                scan_id
            )
        )
    )


@scanner_bp.route(
    "/scans/<int:scan_id>/report.pdf"
)
@login_required
def download_admin_pdf_report(
    scan_id
):
    from services.pdf_report_generator import (
        generate_pdf_scan_report,
    )

    scan = _accessible_scan_or_404(
        scan_id
    )

    payload = _report_payload(
        scan
    )

    # PDF compatibility normalization.
    payload["analysis"][
        "auth_results"
    ] = _parse_auth_results(
        payload["analysis"].get(
            "auth_results"
        )
    )

    pdf_bytes = (
        generate_pdf_scan_report(
            payload["email"],
            payload["analysis"],
            scan.id,
        )
    )

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; "
                f"filename=guardly_report_scan_{scan.id}.pdf"
            )
        },
    )


@scanner_bp.route(
    "/scan/<int:scan_id>/pdf"
)
@login_required
def download_pdf_report(
    scan_id
):
    from services.pdf_report_generator import (
        generate_pdf_scan_report,
    )

    scan = _accessible_scan_or_404(
        scan_id
    )

    payload = _report_payload(
        scan
    )

    # The PDF generator expects auth_results to be a dictionary.
    payload["analysis"][
        "auth_results"
    ] = _parse_auth_results(
        payload["analysis"].get(
            "auth_results"
        )
    )

    pdf_bytes = (
        generate_pdf_scan_report(
            payload["email"],
            payload["analysis"],
            scan.id,
        )
    )

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; "
                f"filename=guardly_report_scan_{scan.id}.pdf"
            )
        },
    )


@scanner_bp.route(
    "/scans/<int:scan_id>/delete",
    methods=["POST"],
)
@login_required
def delete_scan(scan_id):
    scan = _accessible_scan_or_404(
        scan_id
    )

    record_event(
        "scan_deleted",
        target_type="scan",
        target_id=scan.id,
        detail=(
            f"Deleted email scan: "
            f"{scan.subject}"
        ),
    )

    CaseIndicator.query.filter_by(
        source_scan_id=scan.id,
        source="scan",
    ).delete()

    db.session.delete(
        scan
    )

    db.session.commit()

    flash(
        "Scan deleted.",
        "success",
    )

    return redirect(
        url_for(
            "scanner.history"
        )
    )


# ================================================================
# STANDALONE URL SCANNER
#
# Kept unchanged from the existing route implementation.
# ================================================================

_calculate_domain_entropy = (
    calculate_domain_entropy
)


@scanner_bp.route(
    "/scan/url",
    methods=["GET", "POST"],
)
@limiter.limit(
    "10 per minute"
)
def scan_url():
    target_url = request.values.get(
        "url",
        "",
    ).strip()

    if not target_url:
        return redirect(
            url_for(
                "scanner.upload"
            )
        )

    if (
        not target_url.startswith(
            "http://"
        )
        and not target_url.startswith(
            "https://"
        )
    ):
        target_url = (
            "http://"
            + target_url
        )

    parsed = urllib.parse.urlparse(
        target_url
    )

    domain = (
        parsed.netloc
        or parsed.path
    )

    # Compute URL Cryptographic Hashes
    url_bytes = target_url.encode(
        "utf-8"
    )

    md5_hash = hashlib.md5(
        url_bytes
    ).hexdigest()

    sha1_hash = hashlib.sha1(
        url_bytes
    ).hexdigest()

    sha256_hash = hashlib.sha256(
        url_bytes
    ).hexdigest()

    # Real HTTP reachability and response telemetry check
    # via safe_http_get (IP-pinned & SSRF-validated)
    http_status = (
        "Unreachable / Timed Out"
    )

    server_banner = "Unknown"
    content_type = "Unknown"
    response_ms = 0
    redirect_destination = None
    redirect_raw_hops = []
    final_url = target_url
    target_ip = None

    try:
        start_time = time.time()

        (
            status_code,
            body,
            final_url,
            server_banner,
            content_type,
            pinned_ip,
            redirect_raw_hops,
        ) = safe_http_get(
            target_url,
            timeout=2.5,
            max_redirects=10,
        )

        response_ms = round(
            (
                time.time()
                - start_time
            )
            * 1000
        )

        target_ip = pinned_ip

        if status_code > 0:
            http_status = (
                f"{status_code} Response"
            )
        else:
            http_status = (
                server_banner
            )

        if final_url != target_url:
            redirect_destination = (
                final_url
            )

    except ValueError as err:
        http_status = (
            f"Blocked: {err}"
        )

    except Exception:
        http_status = (
            "Offline / Connection Refused"
        )

    # Enterprise Redirect Chain Telemetry & Risk Scoring
    redirect_analysis = (
        analyze_redirect_chain(
            target_url,
            final_url,
            redirect_raw_hops,
        )
    )

    # Brand Impersonation & Typosquatting Analysis
    # Domain-scoped across chain
    target_lower = target_url.lower()

    domain_host = (
        domain
        .lower()
        .split(":")[0]
    )

    final_parsed = (
        urllib.parse.urlparse(
            final_url
        )
    )

    final_domain = (
        final_parsed.netloc
        or final_parsed.path
    )

    final_domain_host = (
        final_domain
        .lower()
        .split(":")[0]
    )

    detected_brand_impersonation = (
        check_brand_impersonation(
            domain_host
        )
        or check_brand_impersonation(
            final_domain_host
        )
    )

    if not detected_brand_impersonation:
        for hop in redirect_analysis[
            "hops"
        ]:
            if hop.get(
                "brand_impersonation"
            ):
                detected_brand_impersonation = (
                    hop[
                        "brand_impersonation"
                    ]
                )
                break

    # Security Heuristics Assessment
    is_ip = is_ip_literal(
        domain
    )

    domain_entropy = (
        calculate_domain_entropy(
            domain_host
        )
    )

    has_high_risk_tld = (
        any(
            domain_host.endswith(tld)
            for tld in HIGH_RISK_TLDS
        )
        or any(
            final_domain_host.endswith(
                tld
            )
            for tld in HIGH_RISK_TLDS
        )
        or redirect_analysis[
            "has_high_risk_tld"
        ]
    )

    has_redirect_anomaly = (
        redirect_analysis[
            "risk_score"
        ]
        >= 30
        or redirect_analysis[
            "has_loop"
        ]
        or redirect_analysis[
            "has_https_downgrade"
        ]
    )

    local_heuristic_rules = [
        {
            "name": (
                "IP-Based Host Detector"
            ),
            "result": (
                "Suspicious"
                if (
                    is_ip
                    or redirect_analysis[
                        "has_ip_destination"
                    ]
                )
                else "Passed"
            ),
            "icon": (
                "bi-shield-x text-warning"
                if (
                    is_ip
                    or redirect_analysis[
                        "has_ip_destination"
                    ]
                )
                else "bi-shield-check text-success"
            ),
        },
        {
            "name": (
                "Brand Impersonation Check"
            ),
            "result": (
                "Suspicious"
                if detected_brand_impersonation
                else "Passed"
            ),
            "icon": (
                "bi-shield-x text-warning"
                if detected_brand_impersonation
                else "bi-shield-check text-success"
            ),
        },
        {
            "name": (
                "High-Risk TLD Rule"
            ),
            "result": (
                "Suspicious"
                if has_high_risk_tld
                else "Passed"
            ),
            "icon": (
                "bi-shield-x text-warning"
                if has_high_risk_tld
                else "bi-shield-check text-success"
            ),
        },
        {
            "name": (
                "Domain Entropy Evaluator"
            ),
            "result": (
                "Suspicious"
                if domain_entropy > 4.2
                else "Passed"
            ),
            "icon": (
                "bi-shield-x text-warning"
                if domain_entropy > 4.2
                else "bi-shield-check text-success"
            ),
        },
        {
            "name": (
                "Redirect Chain Analyzer"
            ),
            "result": (
                "Suspicious"
                if has_redirect_anomaly
                else (
                    "Notice"
                    if redirect_analysis[
                        "has_redirects"
                    ]
                    else "Passed"
                )
            ),
            "icon": (
                "bi-shield-x text-warning"
                if has_redirect_anomaly
                else (
                    "bi-info-circle text-info"
                    if redirect_analysis[
                        "has_redirects"
                    ]
                    else "bi-shield-check text-success"
                )
            ),
        },
        {
            "name": (
                "HTTP Live Reachability"
            ),
            "result": (
                "Passed"
                if (
                    "200"
                    in http_status
                    or "30"
                    in http_status
                )
                else "Notice"
            ),
            "icon": (
                "bi-shield-check text-success"
                if (
                    "200"
                    in http_status
                    or "30"
                    in http_status
                )
                else "bi-info-circle text-info"
            ),
        },
        {
            "name": (
                "SSL / TLS Scheme Check"
            ),
            "result": (
                "Passed"
                if (
                    parsed.scheme
                    == "https"
                    and not redirect_analysis[
                        "has_https_downgrade"
                    ]
                )
                else "Notice"
            ),
            "icon": (
                "bi-shield-check text-success"
                if (
                    parsed.scheme
                    == "https"
                    and not redirect_analysis[
                        "has_https_downgrade"
                    ]
                )
                else "bi-info-circle text-warning"
            ),
        },
    ]

    suspicious_rules_count = sum(
        1
        for v in local_heuristic_rules
        if v["result"]
        == "Suspicious"
    )

    verdict = (
        "High Risk"
        if suspicious_rules_count >= 2
        else (
            "Medium Risk"
            if suspicious_rules_count == 1
            else "Low Risk"
        )
    )

    risk_score = (
        85
        if verdict == "High Risk"
        else (
            45
            if verdict == "Medium Risk"
            else 5
        )
    )

    # IP Geolocation extraction for URL host
    # using pinned_ip
    if not target_ip:
        try:
            (
                _,
                _,
                target_ip,
            ) = validate_url_ssrf(
                target_url
            )
        except Exception:
            target_ip = None

    ip_location = (
        get_ip_location(
            target_ip
        )
        if target_ip
        else None
    )

    analysis_data = {
        "target_url": target_url,
        "domain": domain,
        "final_url": final_url,
        "final_domain": final_domain,
        "scheme": (
            parsed.scheme
            or "http"
        ),
        "path": (
            parsed.path
            or "/"
        ),
        "is_ip": is_ip,
        "ip_location": ip_location,
        "domain_entropy": domain_entropy,
        "has_high_risk_tld": (
            has_high_risk_tld
        ),
        "brand_impersonation": (
            detected_brand_impersonation
        ),
        "http_status": http_status,
        "server_banner": server_banner,
        "content_type": content_type,
        "response_ms": response_ms,
        "redirect_destination": (
            redirect_destination
        ),
        "redirect_analysis": (
            redirect_analysis
        ),
        "md5_hash": md5_hash,
        "sha1_hash": sha1_hash,
        "sha256_hash": sha256_hash,
        "verdict": verdict,
        "risk_score": risk_score,
        "malicious_count": (
            suspicious_rules_count
        ),
        "total_vendors": len(
            local_heuristic_rules
        ),
        "vendors": local_heuristic_rules,
    }

    if request.args.get(
        "format"
    ) == "json":
        return jsonify(
            analysis_data
        )

    return render_template(
        "url_result.html",
        analysis=analysis_data,
    )


# ================================================================
# STANDALONE IOC SCANNER
#
# Kept independent from the email-analysis migration.
# ================================================================

@scanner_bp.route(
    "/scan/ioc",
    methods=["GET", "POST"],
)
def scan_ioc():
    query = (
        request.values.get(
            "q",
            "",
        ).strip()
        or request.values.get(
            "query",
            "",
        ).strip()
    )

    if not query:
        return redirect(
            url_for(
                "scanner.upload"
            )
        )

    # Compute IOC Cryptographic Hashes
    q_bytes = query.encode(
        "utf-8"
    )

    md5_hash = hashlib.md5(
        q_bytes
    ).hexdigest()

    sha1_hash = hashlib.sha1(
        q_bytes
    ).hexdigest()

    sha256_hash = hashlib.sha256(
        q_bytes
    ).hexdigest()

    # Determine IOC type
    if re.match(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        query,
    ):
        ioc_type = (
            "IPv4 Address"
        )

        is_private_ip = (
            is_ip_private_or_internal(
                query
            )
        )

    elif (
        len(query)
        in (32, 64)
        and re.match(
            r"^[a-fA-F0-9]+$",
            query,
        )
    ):
        ioc_type = (
            "Cryptographic Hash ("
            + (
                "MD5"
                if len(query) == 32
                else "SHA-256"
            )
            + ")"
        )

        is_private_ip = False

    else:
        ioc_type = (
            "Domain / Hostname"
        )

        is_private_ip = False

    # IP Geolocation extraction for IOC search
    target_ip = None

    if re.match(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        query,
    ):
        target_ip = query

    elif (
        "."
        in query
        and not query.endswith(
            ".eml"
        )
    ):
        try:
            target_ip = (
                socket.gethostbyname(
                    query
                )
            )
        except Exception:
            target_ip = None

    ip_location = (
        get_ip_location(
            target_ip
        )
        if target_ip
        else None
    )

    domain_entropy = (
        _calculate_domain_entropy(
            query
        )
    )

    # Query related scans in database
    pattern = f"%{query}%"

    matching_scans = (
        _scan_scope_query()
        .filter(
            or_(
                EmailScan.urls.ilike(
                    pattern
                ),
                EmailScan.iocs.ilike(
                    pattern
                ),
                EmailScan.sender.ilike(
                    pattern
                ),
                EmailScan.subject.ilike(
                    pattern
                ),
            )
        )
        .limit(10)
        .all()
    )

    analysis_data = {
        "query": query,
        "ioc_type": ioc_type,
        "is_private_ip": is_private_ip,
        "ip_location": ip_location,
        "domain_entropy": domain_entropy,
        "md5_hash": md5_hash,
        "sha1_hash": sha1_hash,
        "sha256_hash": sha256_hash,
        "matching_scans": matching_scans,
        "matches_count": len(
            matching_scans
        ),
        "reputation_score": (
            85
            if matching_scans
            else 0
        ),
        "verdict": (
            "Threat Record Found"
            if matching_scans
            else "Clean / No Threats Recorded"
        ),
    }

    if request.args.get(
        "format"
    ) == "json":
        return jsonify(
            {
                "query": query,
                "ioc_type": ioc_type,
                "domain_entropy": domain_entropy,
                "hashes": {
                    "md5": md5_hash,
                    "sha1": sha1_hash,
                    "sha256": sha256_hash,
                },
                "matches_count": len(
                    matching_scans
                ),
                "reputation_score": (
                    analysis_data[
                        "reputation_score"
                    ]
                ),
                "verdict": (
                    analysis_data[
                        "verdict"
                    ]
                ),
            }
        )

    return render_template(
        "ioc_result.html",
        analysis=analysis_data,
    )


@scanner_bp.route(
    "/api/v1/geolocation/health"
)
@scanner_bp.route(
    "/admin/geolocation/health"
)
@login_required
@roles_required(
    User.ROLE_ADMIN,
    User.ROLE_ANALYST,
)
def geolocation_health():
    """
    Health check diagnostic API endpoint for
    IP Geolocation Subsystem.
    """
    from services.geolocation import (
        get_geolocation_service,
    )

    geo_svc = (
        get_geolocation_service(
            current_app.config
        )
    )

    return jsonify(
        geo_svc.health_check()
    )


@scanner_bp.route(
    "/scan/<int:scan_id>/yara"
)
@login_required
def download_yara_rule(scan_id):
    scan = _accessible_scan_or_404(
        scan_id
    )

    payload = _report_payload(
        scan
    )

    yara_code = generate_yara_rule(
        payload["email"],
        payload["analysis"],
    )

    return Response(
        yara_code,
        mimetype="text/plain",
        headers={
            "Content-Disposition": (
                "attachment; "
                f"filename=guardly_rule_scan_{scan.id}.yar"
            )
        },
    )


@scanner_bp.route(
    "/scan/<int:scan_id>/sigma"
)
@login_required
def download_sigma_rule(scan_id):
    scan = _accessible_scan_or_404(
        scan_id
    )

    payload = _report_payload(
        scan
    )

    sigma_code = generate_sigma_rule(
        payload["email"],
        payload["analysis"],
    )

    return Response(
        sigma_code,
        mimetype="text/yaml",
        headers={
            "Content-Disposition": (
                "attachment; "
                f"filename=guardly_sigma_scan_{scan.id}.yml"
            )
        },
    )


@scanner_bp.route("/result/<guest_token>")
def view_guest_scan(guest_token):
    scan = EmailScan.query.filter_by(guest_token=guest_token, user_id=None).first()
    if not scan:
        abort(404)

    email_data = _scan_email_data(scan)
    analysis = _scan_analysis(scan, email_data)

    return render_template(
        "scan_result.html",
        email_data=email_data,
        analysis=analysis,
        scan=scan,
        is_public_result=True,
        linked_cases=[],
    )


@scanner_bp.route("/result/<guest_token>/pdf")
def download_guest_pdf_report(guest_token):
    from services.pdf_report_generator import generate_pdf_scan_report

    scan = EmailScan.query.filter_by(guest_token=guest_token, user_id=None).first()
    if not scan:
        abort(404)

    payload = _report_payload(scan)
    payload["analysis"]["auth_results"] = _parse_auth_results(
        payload["analysis"].get("auth_results")
    )

    pdf_bytes = generate_pdf_scan_report(
        payload["email"],
        payload["analysis"],
        scan.id,
    )

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; "
                f"filename=guardly_guest_report_{guest_token[:8]}.pdf"
            )
        },
    )