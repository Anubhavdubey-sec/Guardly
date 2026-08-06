import csv
import io
import json
import os
import re
import uuid

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
    url_for,
)
from sqlalchemy import or_
from werkzeug.utils import secure_filename

from models.scan import EmailScan
from models.user import User, db
from routes.auth import login_required, roles_required
from scanner.email_parser import parse_email
from scanner.phishing_detector import analyze_email
from scanner.url_heuristics import (
    HIGH_RISK_TLDS,
    KNOWN_IMPERSONATED_BRANDS,
    assess_url,
    calculate_domain_entropy,
    check_brand_impersonation,
    is_ip_literal,
)
from services.audit import record_event
from services.limiter import limiter
from services.report_generator import build_scan_report
from services.public_lookup import PublicLookupClient, enrich_analysis_with_public_context, get_ip_location
from services.ssrf import is_ip_private_or_internal, safe_http_get, validate_url_ssrf


scanner_bp = Blueprint("scanner", __name__)
ALLOWED_EXTENSIONS = {".eml"}
VERDICTS = ("Low Risk", "Medium Risk", "High Risk")


def is_allowed_email(filename):
    return os.path.splitext(filename.lower())[1] in ALLOWED_EXTENSIONS


def _scan_email_data(scan):
    headers = scan.headers_data
    content = headers.get("content", {})
    email_ips = scan.iocs_data.get("ip_addresses", [])
    ip_locations = [get_ip_location(ip) for ip in email_ips if get_ip_location(ip)]

    return {
        "from": scan.sender or "Unknown sender",
        "from_address": headers.get("from_address", ""),
        "from_name": headers.get("from_name", ""),
        "to": scan.receiver or "Unknown recipient",
        "subject": scan.subject or "(no subject)",
        "date": scan.email_date or "Unknown date",
        "reply_to": scan.reply_to or "",
        "body": scan.email_body or "",
        "urls": scan.urls_list,
        "attachments": scan.attachments_list,
        "headers": headers,
        "has_html": content.get("has_html", False),
        "has_plain_text": content.get("has_plain_text", False),
        "iocs": scan.iocs_data,
        "ip_locations": ip_locations,
    }


def _scan_analysis(scan, email_data):
    current_analysis = analyze_email(email_data)
    reputation_data = scan.reputation_data_json or {
        "provider": "Public RDAP and IP network context",
        "message": "This older scan does not include public registration or IP context.",
        "lookups": [],
    }

    timeline_data = email_data.get("delivery_timeline")
    if not timeline_data:
        from scanner.timeline import TimelineAnalysis, calculate_delivery_delays, generate_delivery_summary, parse_received_headers
        received_headers = []
        if isinstance(email_data.get("headers"), dict):
            raw_rec = email_data["headers"].get("Received") or email_data["headers"].get("received") or []
            if isinstance(raw_rec, str):
                received_headers = [raw_rec]
            elif isinstance(raw_rec, list):
                received_headers = raw_rec
        parsed_hops = parse_received_headers(received_headers)
        if parsed_hops:
            chronological_hops = list(reversed(parsed_hops))
            for idx, hop in enumerate(chronological_hops, start=1):
                hop.hop_number = idx
            hops_with_delays = calculate_delivery_delays(chronological_hops)
            summary = generate_delivery_summary(hops_with_delays)
            timeline_data = TimelineAnalysis(
                hops=hops_with_delays,
                summary=summary,
                has_timeline=True,
                summary_message=f"Reconstructed {len(hops_with_delays)} mail server relay hops.",
            ).to_dict()
        else:
            timeline_data = TimelineAnalysis(has_timeline=False, summary_message="No delivery path available.").to_dict()

    return {
        "score": scan.risk_score,
        "verdict": scan.verdict,
        "findings": scan.findings_list,
        "categories": scan.risk_categories_list,
        "url_assessments": current_analysis["url_assessments"],
        "auth_results": current_analysis["auth_results"],
        "reputation_data": reputation_data,
        "delivery_timeline": timeline_data,
    }


def _scan_scope_query():
    return EmailScan.query


def _accessible_scan_or_404(scan_id):
    scan = _scan_scope_query().filter_by(id=scan_id).first()
    if not scan:
        abort(404)
    return scan


def _history_filters():
    search = request.args.get("q", "").strip()
    verdict = request.args.get("verdict", "").strip()
    category = request.args.get("category", "").strip()
    query = _scan_scope_query()

    if search:
        pattern = f"%{search}%"
        conditions = [
            EmailScan.subject.ilike(pattern),
            EmailScan.sender.ilike(pattern),
            EmailScan.receiver.ilike(pattern),
            EmailScan.reply_to.ilike(pattern),
            EmailScan.urls.ilike(pattern),
            EmailScan.iocs.ilike(pattern),
            User.username.ilike(pattern),
            User.email.ilike(pattern),
        ]
        if search.isdigit():
            conditions.append(EmailScan.id == int(search))
        if any(term in search.lower() for term in ["public", "visitor", "anon", "guest", "unassigned"]):
            conditions.append(EmailScan.user_id.is_(None))

        query = query.outerjoin(User).filter(or_(*conditions))
    if verdict in VERDICTS:
        query = query.filter(EmailScan.verdict == verdict)

    scans = query.order_by(EmailScan.scan_time.desc()).all()
    if category:
        scans = [scan for scan in scans if category in scan.risk_categories_list]

    all_scans = _scan_scope_query().all()
    categories = sorted({item for scan in all_scans for item in scan.risk_categories_list})
    filters = {"q": search, "verdict": verdict, "category": category}
    return scans, categories, filters


def _report_payload(scan):
    email_data = _scan_email_data(scan)
    analysis = _scan_analysis(scan, email_data)
    return {
        "scan_id": scan.id,
        "scanned_at": scan.scan_time.isoformat(),
        "email": email_data,
        "analysis": analysis,
    }


@scanner_bp.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return render_template("upload.html")

    uploaded_file = request.files.get("email_file")
    if not uploaded_file or not uploaded_file.filename:
        return render_template("upload.html", error="Choose an .eml file to scan."), 400

    original_name = secure_filename(uploaded_file.filename)
    if not original_name or not is_allowed_email(original_name):
        return render_template("upload.html", error="Only .eml email files are accepted."), 400

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    file_path = os.path.join(upload_dir, unique_name)

    try:
        uploaded_file.save(file_path)
        email_data = parse_email(file_path)
        analysis = analyze_email(email_data)
        if current_app.config["PUBLIC_LOOKUPS_ENABLED"]:
            try:
                public_lookup = PublicLookupClient(
                    current_app.config["PUBLIC_LOOKUP_TIMEOUT_SECONDS"],
                    current_app.config["PUBLIC_LOOKUP_MAX_LOOKUPS"],
                )
                reputation_data = public_lookup.lookup_context(
                    email_data["iocs"]["domains"],
                    email_data["iocs"]["ip_addresses"],
                )
            except Exception as error:
                current_app.logger.warning("Public reputation lookup failed: %s", error)
                reputation_data = {
                    "provider": "Public RDAP and IP network context",
                    "message": "Public context was unavailable. Local checks were still completed.",
                    "lookups": [],
                }
        else:
            reputation_data = {
                "provider": "Public RDAP and IP network context",
                "message": "Public context lookups are disabled. Local checks were completed.",
                "lookups": [],
            }
        analysis = enrich_analysis_with_public_context(analysis, reputation_data)
    except Exception as error:
        current_app.logger.warning("Could not scan uploaded email: %s", error)
        return render_template("upload.html", error="The selected file could not be read as an email."), 400
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    headers = dict(email_data["headers"])
    headers["from_address"] = email_data["from_address"]
    headers["from_name"] = email_data["from_name"]
    headers["content"] = {
        "has_html": email_data["has_html"],
        "has_plain_text": email_data["has_plain_text"],
    }
    scan = EmailScan(
        user_id=g.current_user.id if getattr(g, "current_user", None) else None,
        sender=email_data["from"],
        receiver=email_data["to"],
        subject=email_data["subject"],
        email_date=email_data["date"],
        reply_to=email_data["reply_to"],
        email_body=email_data["body"],
        risk_score=analysis["score"],
        verdict=analysis["verdict"],
        findings=json.dumps(analysis["findings"]),
        urls=json.dumps(email_data["urls"]),
        attachments=json.dumps(email_data["attachments"]),
        headers=json.dumps(headers),
        iocs=json.dumps(email_data["iocs"]),
        risk_categories=json.dumps(analysis["categories"]),
        reputation_data=json.dumps(analysis["reputation_data"]),
    )
    db.session.add(scan)
    db.session.flush()
    record_event(
        "scan_created",
        target_type="scan",
        target_id=scan.id,
        detail=f"Scanned email: {scan.subject}",
        actor_name="Public visitor" if not getattr(g, "current_user", None) else "",
    )
    db.session.commit()

    return render_template(
        "scan_result.html",
        email_data=email_data,
        analysis=analysis,
        scan=scan,
        is_public_result=not getattr(g, "current_user", None),
    )


@scanner_bp.route("/history")
@login_required
@roles_required(User.ROLE_ADMIN, User.ROLE_ANALYST)
def history():
    scans, categories, filters = _history_filters()
    return render_template(
        "history.html",
        scans=scans,
        categories=categories,
        filters=filters,
        verdicts=VERDICTS,
        can_download=g.current_user.role == User.ROLE_ADMIN,
        can_delete=g.current_user.role == User.ROLE_ADMIN,
    )


@scanner_bp.route("/history/export.csv")
@login_required
@roles_required(User.ROLE_ADMIN)
def export_history_csv():
    scans, _categories, _filters = _history_filters()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Scanned at", "Submitted by", "Sender", "Recipient", "Subject", "Score", "Verdict", "Categories", "URLs"])
    for scan in scans:
        writer.writerow([
            scan.id,
            scan.scan_time.isoformat(),
            scan.user.username if scan.user else "Public visitor",
            scan.sender,
            scan.receiver,
            scan.subject,
            scan.risk_score,
            scan.verdict,
            "; ".join(scan.risk_categories_list),
            "; ".join(scan.urls_list),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=guardly-scan-history.csv"},
    )


@scanner_bp.route("/scans/<int:scan_id>")
@login_required
@roles_required(User.ROLE_ADMIN, User.ROLE_ANALYST)
def view_scan(scan_id):
    scan = _accessible_scan_or_404(scan_id)
    email_data = _scan_email_data(scan)
    analysis = _scan_analysis(scan, email_data)
    return render_template("scan_result.html", email_data=email_data, analysis=analysis, scan=scan, is_public_result=False)


@scanner_bp.route("/scans/<int:scan_id>/export.json")
@login_required
@roles_required(User.ROLE_ADMIN)
def export_scan_json(scan_id):
    return jsonify(_report_payload(_accessible_scan_or_404(scan_id)))


@scanner_bp.route("/scans/<int:scan_id>/report.pdf")
@login_required
@roles_required(User.ROLE_ADMIN)
def download_pdf_report(scan_id):
    scan = _accessible_scan_or_404(scan_id)
    email_data = _scan_email_data(scan)
    analysis = _scan_analysis(scan, email_data)
    report = build_scan_report(scan, email_data, analysis)
    return send_file(
        report,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"guardly-scan-{scan.id}.pdf",
    )


@scanner_bp.route('/scan/<int:scan_id>/pdf', methods=['GET'])
def download_pdf(scan_id):
    scan = EmailScan.query.get_or_404(scan_id)
    pdf_bytes = generate_pdf_report(scan)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"guardly-scan-{scan.id}.pdf",
    )


@scanner_bp.route("/scans/<int:scan_id>/delete", methods=["POST"])
@login_required
@roles_required(User.ROLE_ADMIN)
def delete_scan(scan_id):
    scan = _accessible_scan_or_404(scan_id)
    record_event("scan_deleted", target_type="scan", target_id=scan.id, detail=f"Deleted email scan: {scan.subject}")
    db.session.delete(scan)
    db.session.commit()
    flash("Scan deleted.", "success")
    return redirect(url_for("scanner.history"))


import hashlib
import time
import urllib.parse
import urllib.request
import ssl

_calculate_domain_entropy = calculate_domain_entropy


@scanner_bp.route("/scan/url", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def scan_url():
    target_url = request.values.get("url", "").strip()
    if not target_url:
        return redirect(url_for("scanner.upload"))

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc or parsed.path

    # Compute URL Cryptographic Hashes
    url_bytes = target_url.encode("utf-8")
    md5_hash = hashlib.md5(url_bytes).hexdigest()
    sha1_hash = hashlib.sha1(url_bytes).hexdigest()
    sha256_hash = hashlib.sha256(url_bytes).hexdigest()

    # Real HTTP reachability and response telemetry check via safe_http_get (IP-pinned & SSRF-validated)
    http_status = "Unreachable / Timed Out"
    server_banner = "Unknown"
    content_type = "Unknown"
    response_ms = 0
    redirect_destination = None

    target_ip = None
    try:
        start_time = time.time()
        status_code, body, final_url, server_banner, content_type, pinned_ip = safe_http_get(target_url, timeout=2.5)
        response_ms = round((time.time() - start_time) * 1000)
        target_ip = pinned_ip
        if status_code > 0:
            http_status = f"{status_code} Response"
        else:
            http_status = server_banner
        
        if final_url != target_url:
            redirect_destination = final_url
    except ValueError as err:
        http_status = f"Blocked: {err}"
    except Exception as err:
        http_status = "Offline / Connection Refused"

    # Brand Impersonation & Typosquatting Analysis (Domain-scoped via url_heuristics)
    target_lower = target_url.lower()
    domain_host = domain.lower().split(":")[0]
    detected_brand_impersonation = check_brand_impersonation(domain_host)

    # Security Heuristics Assessment
    is_ip = is_ip_literal(domain)
    domain_entropy = calculate_domain_entropy(domain_host)
    has_high_risk_tld = any(domain_host.endswith(tld) for tld in HIGH_RISK_TLDS)
    is_suspicious = is_ip or bool(detected_brand_impersonation) or has_high_risk_tld or any(kw in target_lower for kw in ("login", "verify", "secure", "bank", "account", "paypal", "phish"))

    local_heuristic_rules = [
        {"name": "IP-Based Host Detector", "result": "Suspicious" if is_ip else "Passed", "icon": "bi-shield-x text-warning" if is_ip else "bi-shield-check text-success"},
        {"name": "Brand Impersonation Check", "result": "Suspicious" if detected_brand_impersonation else "Passed", "icon": "bi-shield-x text-warning" if detected_brand_impersonation else "bi-shield-check text-success"},
        {"name": "High-Risk TLD Rule", "result": "Suspicious" if has_high_risk_tld else "Passed", "icon": "bi-shield-x text-warning" if has_high_risk_tld else "bi-shield-check text-success"},
        {"name": "Domain Entropy Evaluator", "result": "Suspicious" if domain_entropy > 4.2 else "Passed", "icon": "bi-shield-x text-warning" if domain_entropy > 4.2 else "bi-shield-check text-success"},
        {"name": "HTTP Live Reachability", "result": "Passed" if "200" in http_status or "30" in http_status else "Notice", "icon": "bi-shield-check text-success" if "200" in http_status or "30" in http_status else "bi-info-circle text-info"},
        {"name": "SSL / TLS Scheme Check", "result": "Passed" if parsed.scheme == "https" else "Notice", "icon": "bi-shield-check text-success" if parsed.scheme == "https" else "bi-info-circle text-warning"},
    ]

    suspicious_rules_count = sum(1 for v in local_heuristic_rules if v["result"] == "Suspicious")
    verdict = "High Risk" if suspicious_rules_count >= 2 else ("Medium Risk" if suspicious_rules_count == 1 else "Low Risk")
    risk_score = 85 if verdict == "High Risk" else (45 if verdict == "Medium Risk" else 5)

    # IP Geolocation extraction for URL host using pinned_ip (no secondary unpinned DNS lookup)
    if not target_ip:
        _, _, target_ip = validate_url_ssrf(target_url)

    ip_location = get_ip_location(target_ip) if target_ip else None

    analysis_data = {
        "target_url": target_url,
        "domain": domain,
        "scheme": parsed.scheme or "http",
        "path": parsed.path or "/",
        "is_ip": is_ip,
        "ip_location": ip_location,
        "domain_entropy": domain_entropy,
        "has_high_risk_tld": has_high_risk_tld,
        "brand_impersonation": detected_brand_impersonation,
        "http_status": http_status,
        "server_banner": server_banner,
        "content_type": content_type,
        "response_ms": response_ms,
        "redirect_destination": redirect_destination,
        "md5_hash": md5_hash,
        "sha1_hash": sha1_hash,
        "sha256_hash": sha256_hash,
        "verdict": verdict,
        "risk_score": risk_score,
        "malicious_count": suspicious_rules_count,
        "total_vendors": len(local_heuristic_rules),
        "vendors": local_heuristic_rules,
    }

    if request.args.get("format") == "json":
        return jsonify(analysis_data)

    return render_template("url_result.html", analysis=analysis_data)


@scanner_bp.route("/scan/ioc", methods=["GET", "POST"])
def scan_ioc():
    query = request.values.get("q", "").strip() or request.values.get("query", "").strip()
    if not query:
        return redirect(url_for("scanner.upload"))

    # Compute IOC Cryptographic Hashes
    q_bytes = query.encode("utf-8")
    md5_hash = hashlib.md5(q_bytes).hexdigest()
    sha1_hash = hashlib.sha1(q_bytes).hexdigest()
    sha256_hash = hashlib.sha256(q_bytes).hexdigest()

    # Determine IOC type
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
        ioc_type = "IPv4 Address"
        is_private_ip = is_ip_private_or_internal(query)
    elif len(query) in (32, 64) and re.match(r"^[a-fA-F0-9]+$", query):
        ioc_type = "Cryptographic Hash (" + ("MD5" if len(query) == 32 else "SHA-256") + ")"
        is_private_ip = False
    else:
        ioc_type = "Domain / Hostname"
        is_private_ip = False

    # IP Geolocation extraction for IOC search
    target_ip = None
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
        target_ip = query
    elif "." in query and not query.endswith(".eml"):
        try:
            target_ip = socket.gethostbyname(query)
        except Exception:
            target_ip = None

    ip_location = get_ip_location(target_ip) if target_ip else None
    domain_entropy = _calculate_domain_entropy(query)

    # Query related scans in database
    pattern = f"%{query}%"
    matching_scans = EmailScan.query.filter(
        or_(
            EmailScan.urls.ilike(pattern),
            EmailScan.iocs.ilike(pattern),
            EmailScan.sender.ilike(pattern),
            EmailScan.subject.ilike(pattern),
        )
    ).limit(10).all()

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
        "matches_count": len(matching_scans),
        "reputation_score": 85 if matching_scans else 0,
        "verdict": "Threat Record Found" if matching_scans else "Clean / No Threats Recorded",
    }

    if request.args.get("format") == "json":
        return jsonify({
            "query": query,
            "ioc_type": ioc_type,
            "domain_entropy": domain_entropy,
            "hashes": {"md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash},
            "matches_count": len(matching_scans),
            "reputation_score": analysis_data["reputation_score"],
            "verdict": analysis_data["verdict"],
        })

    return render_template("ioc_result.html", analysis=analysis_data)


@scanner_bp.route("/api/v1/geolocation/health")
@scanner_bp.route("/admin/geolocation/health")
def geolocation_health():
    """
    Health check diagnostic API endpoint for IP Geolocation Subsystem.
    Exposes MaxMind City/ASN database status, build epochs, cache stats, and fallback status.
    """
    from services.geolocation import get_geolocation_service
    geo_svc = get_geolocation_service(current_app.config)
    return jsonify(geo_svc.health_check())

