"""Investigation-case workflow routes for staff analysts."""

import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import and_, or_

from models.investigation_case import CaseIndicator, CaseNote, CaseScan, InvestigationCase
from models.scan import EmailScan
from models.user import User, db
from routes.auth import login_required, roles_required
from services.audit import record_event


cases_bp = Blueprint("cases", __name__, url_prefix="/cases")
STAFF_ROLES = (User.ROLE_ADMIN, User.ROLE_USER)
DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    re.IGNORECASE,
)


def _case_scope_query():
    """Cases are visible to their creator and assignee."""
    user = g.current_user
    return InvestigationCase.query.filter(
        or_(
            InvestigationCase.created_by_id == user.id,
            InvestigationCase.assigned_to_id == user.id,
        ),
    )


def _accessible_case_or_404(case_id):
    case = _case_scope_query().filter_by(id=case_id).first()
    if not case:
        abort(404)
    return case


def _accessible_scan_query():
    user = g.current_user
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
        ),
    )


def _accessible_scan_or_404(scan_id):
    scan = _accessible_scan_query().filter_by(id=scan_id).first()
    if not scan:
        abort(404)
    return scan


def _staff_members():
    staff_members = User.query.filter(
        User.is_active.is_(True),
        User.role.in_(STAFF_ROLES),
    ).order_by(User.username.asc()).all()
    if g.current_user.role != User.ROLE_ADMIN:
        return [member for member in staff_members if member.id == g.current_user.id]
    return staff_members


def _parse_tags(raw_tags):
    tags = []
    raw_tags = raw_tags or ""
    for tag in raw_tags.split(","):
        normalized = tag.strip().lower()
        if not normalized or normalized in tags:
            continue
        if len(normalized) > 40:
            raise ValueError("Tags must be 40 characters or fewer.")
        tags.append(normalized)

    if len(tags) > 10:
        raise ValueError("Add no more than 10 tags to a case.")
    return tags


def _assignee_from_form(case=None):
    raw_assignee = request.form.get("assigned_to_id", "").strip()
    if not raw_assignee:
        if (
            case
            and g.current_user.role != User.ROLE_ADMIN
            and case.assigned_to_id == g.current_user.id
            and case.created_by_id != g.current_user.id
        ):
            raise ValueError("Only an administrator can unassign a case assigned to you.")
        return None

    try:
        assignee_id = int(raw_assignee)
    except ValueError:
        raise ValueError("Select a valid assignee.")

    assignee = User.query.filter(
        User.id == assignee_id,
        User.tenant_id == g.current_user.tenant_id,
        User.is_active.is_(True),
        User.role.in_(STAFF_ROLES),
    ).first()
    if not assignee:
        raise ValueError("Select an active staff member from this tenant.")

    if g.current_user.role != User.ROLE_ADMIN and assignee.id != g.current_user.id:
        raise ValueError("Analysts can assign cases only to themselves.")
    return assignee.id


def _apply_case_fields(case, include_title=False):
    if include_title:
        title = request.form.get("title", "").strip()
        if not title:
            raise ValueError("A case title is required.")
        if len(title) > 180:
            raise ValueError("Case titles must be 180 characters or fewer.")
        case.title = title

    status = request.form.get("status", case.status)
    if status not in InvestigationCase.STATUSES:
        raise ValueError("Select a valid case status.")
    if case.status == "Closed" and status == "Closed":
        raise ValueError("Reopen the closed case before changing its details.")

    verdict_override = request.form.get("verdict_override", "").strip()
    if verdict_override not in InvestigationCase.VERDICT_OVERRIDES:
        raise ValueError("Select a valid verdict override.")

    case.status = status
    case.assigned_to_id = _assignee_from_form(case)
    case.tags = json.dumps(_parse_tags(request.form.get("tags", "")))
    case.verdict_override = verdict_override or None


def _touch_case(case):
    """Keep case ordering and freshness accurate for evidence and note changes."""
    case.updated_at = datetime.now(timezone.utc)


def _ensure_case_mutable(case):
    if case.status == "Closed":
        raise ValueError("Reopen this case before changing evidence, indicators, or notes.")


def _validated_note(raw_note):
    note = (raw_note or "").strip()
    if len(note) > 8000:
        raise ValueError("Analyst notes must be 8,000 characters or fewer.")
    return note


def _add_case_note(case, raw_note):
    note = _validated_note(raw_note)
    if not note:
        return False
    db.session.add(CaseNote(case_id=case.id, author_id=g.current_user.id, body=note))
    _touch_case(case)
    return True


def _normalize_indicator(indicator_type, raw_value):
    value = (raw_value or "").strip()
    if not value or len(value) > 512:
        raise ValueError("Indicator values must be between 1 and 512 characters.")

    if indicator_type == "domain":
        value = value.rstrip(".").lower()
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("Enter a valid domain name.") from error
        if not DOMAIN_PATTERN.fullmatch(value):
            raise ValueError("Enter a fully qualified domain name.")
        return value

    if indicator_type == "ip_address":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("Enter a valid IPv4 or IPv6 address.") from error

    if indicator_type == "url":
        try:
            parts = urlsplit(value)
            port = parts.port
        except ValueError as error:
            raise ValueError("Enter a valid HTTP or HTTPS URL.") from error
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("Enter a valid HTTP or HTTPS URL without credentials.")
        hostname = parts.hostname.rstrip(".").lower()
        host_display = f"[{hostname}]" if ":" in hostname else hostname
        netloc = host_display + (f":{port}" if port else "")
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))

    if indicator_type == "hash":
        normalized = value.lower()
        if not re.fullmatch(r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})", normalized):
            raise ValueError("Enter an MD5, SHA-1, SHA-256, or SHA-512 hash.")
        return normalized

    return value


def _derived_indicators(scan):
    """Return the IOC types and values retained by a scan, bounded for case storage."""
    values = []
    iocs = scan.iocs_data if isinstance(scan.iocs_data, dict) else {}
    for indicator_type, key in (("domain", "domains"), ("ip_address", "ip_addresses")):
        for value in iocs.get(key, []) if isinstance(iocs.get(key, []), list) else []:
            values.append((indicator_type, value))
    for value in scan.urls_list:
        values.append(("url", value))

    unique_values = []
    seen = set()
    for indicator_type, value in values:
        try:
            normalized = _normalize_indicator(indicator_type, str(value or ""))
        except ValueError:
            continue
        identity = (indicator_type, normalized.casefold())
        if not normalized or len(normalized) > 512 or identity in seen:
            continue
        seen.add(identity)
        unique_values.append((indicator_type, normalized))
    return unique_values


def _link_scan(case, scan):
    existing = CaseScan.query.filter_by(case_id=case.id, scan_id=scan.id).first()
    if existing:
        return False

    db.session.add(CaseScan(case_id=case.id, scan_id=scan.id, added_by_id=g.current_user.id))
    for indicator_type, value in _derived_indicators(scan):
        already_linked = CaseIndicator.query.filter_by(
            case_id=case.id,
            source_scan_id=scan.id,
            indicator_type=indicator_type,
            value=value,
        ).first()
        if not already_linked:
            db.session.add(CaseIndicator(
                case_id=case.id,
                source_scan_id=scan.id,
                indicator_type=indicator_type,
                value=value,
                source="scan",
            ))
    _touch_case(case)
    return True


@cases_bp.route("")
@cases_bp.route("/")
@login_required
@roles_required(*STAFF_ROLES)
def list_cases():
    status = request.args.get("status", "").strip()
    search = request.args.get("q", "").strip()
    query = _case_scope_query()
    if status in InvestigationCase.STATUSES:
        query = query.filter(InvestigationCase.status == status)
    if search:
        safe_search = search.replace("\\", r"\\").replace("%", r"\%").replace("_", r"\_")
        pattern = f"%{safe_search}%"
        query = query.filter(
            or_(
                InvestigationCase.title.ilike(pattern, escape="\\"),
                InvestigationCase.tags.ilike(pattern, escape="\\"),
            )
        )

    cases = query.order_by(InvestigationCase.updated_at.desc()).all()
    return render_template(
        "cases.html",
        cases=cases,
        statuses=InvestigationCase.STATUSES,
        filters={"status": status, "q": search},
    )


@cases_bp.route("/new", methods=["GET", "POST"])
@login_required
@roles_required(*STAFF_ROLES)
def create_case():
    preselected_scan_id = request.values.get("scan_id", type=int)
    available_scans = _accessible_scan_query().order_by(EmailScan.scan_time.desc()).limit(100).all()

    if request.method == "POST":
        try:
            case = InvestigationCase(
                tenant_id=g.current_user.tenant_id,
                created_by_id=g.current_user.id,
            )
            _apply_case_fields(case, include_title=True)
            db.session.add(case)
            db.session.flush()

            _add_case_note(case, request.form.get("initial_note", request.form.get("analyst_notes", "")))

            for raw_scan_id in request.form.getlist("scan_ids"):
                try:
                    scan_id = int(raw_scan_id)
                except ValueError:
                    raise ValueError("A selected scan was invalid.")
                _link_scan(case, _accessible_scan_or_404(scan_id))

            record_event(
                "case_created",
                target_type="case",
                target_id=case.id,
                detail=f"Created case: {case.title}",
            )
            db.session.commit()
            flash("Investigation case created.", "success")
            return redirect(url_for("cases.view_case", case_id=case.id))
        except ValueError as error:
            db.session.rollback()
            flash(str(error), "danger")

    if preselected_scan_id and not any(scan.id == preselected_scan_id for scan in available_scans):
        abort(404)
    return render_template(
        "case_form.html",
        case=None,
        statuses=InvestigationCase.STATUSES,
        verdict_overrides=InvestigationCase.VERDICT_OVERRIDES,
        staff_members=_staff_members(),
        available_scans=available_scans,
        selected_scan_ids={preselected_scan_id} if preselected_scan_id else set(),
    )


@cases_bp.route("/<int:case_id>")
@login_required
@roles_required(*STAFF_ROLES)
def view_case(case_id):
    case = _accessible_case_or_404(case_id)
    linked_scan_ids = [link.scan_id for link in case.scan_links]
    available_scans = _accessible_scan_query().filter(~EmailScan.id.in_(linked_scan_ids)).order_by(EmailScan.scan_time.desc()).limit(100).all()
    return render_template(
        "case_detail.html",
        case=case,
        statuses=InvestigationCase.STATUSES,
        verdict_overrides=InvestigationCase.VERDICT_OVERRIDES,
        staff_members=_staff_members(),
        available_scans=available_scans,
        can_unassign=(
            g.current_user.role == User.ROLE_ADMIN
            or case.created_by_id == g.current_user.id
            or case.assigned_to_id != g.current_user.id
        ),
    )


@cases_bp.route("/<int:case_id>/update", methods=["POST"])
@login_required
@roles_required(*STAFF_ROLES)
def update_case(case_id):
    case = _accessible_case_or_404(case_id)
    try:
        _apply_case_fields(case, include_title=True)
        record_event("case_updated", target_type="case", target_id=case.id, detail=f"Updated case: {case.title}")
        db.session.commit()
        flash("Case details updated.", "success")
    except ValueError as error:
        db.session.rollback()
        flash(str(error), "danger")
    return redirect(url_for("cases.view_case", case_id=case.id))


@cases_bp.route("/<int:case_id>/scans", methods=["POST"])
@login_required
@roles_required(*STAFF_ROLES)
def add_case_scan(case_id):
    case = _accessible_case_or_404(case_id)
    try:
        _ensure_case_mutable(case)
    except ValueError as error:
        flash(str(error), "warning")
        return redirect(url_for("cases.view_case", case_id=case.id))
    scan_id = request.form.get("scan_id", type=int)
    if not scan_id:
        flash("Select a scan to link.", "danger")
        return redirect(url_for("cases.view_case", case_id=case.id))

    scan = _accessible_scan_or_404(scan_id)
    if _link_scan(case, scan):
        record_event("case_scan_linked", target_type="case", target_id=case.id, detail=f"Linked scan #{scan.id} to case.")
        db.session.commit()
        flash(f"Scan #{scan.id} linked to this case.", "success")
    else:
        flash("That scan is already linked to this case.", "warning")
    return redirect(url_for("cases.view_case", case_id=case.id))


@cases_bp.route("/<int:case_id>/scans/<int:scan_id>/unlink", methods=["POST"])
@login_required
@roles_required(*STAFF_ROLES)
def unlink_case_scan(case_id, scan_id):
    case = _accessible_case_or_404(case_id)
    try:
        _ensure_case_mutable(case)
    except ValueError as error:
        flash(str(error), "warning")
        return redirect(url_for("cases.view_case", case_id=case.id))
    link = CaseScan.query.filter_by(case_id=case.id, scan_id=scan_id).first()
    if not link:
        abort(404)

    CaseIndicator.query.filter_by(case_id=case.id, source_scan_id=scan_id, source="scan").delete()
    db.session.delete(link)
    _touch_case(case)
    record_event("case_scan_unlinked", target_type="case", target_id=case.id, detail=f"Unlinked scan #{scan_id} from case.")
    db.session.commit()
    flash(f"Scan #{scan_id} unlinked from this case.", "success")
    return redirect(url_for("cases.view_case", case_id=case.id))


@cases_bp.route("/<int:case_id>/indicators", methods=["POST"])
@login_required
@roles_required(*STAFF_ROLES)
def add_case_indicator(case_id):
    case = _accessible_case_or_404(case_id)
    try:
        _ensure_case_mutable(case)
    except ValueError as error:
        flash(str(error), "warning")
        return redirect(url_for("cases.view_case", case_id=case.id))
    indicator_type = request.form.get("indicator_type", "").strip()
    if indicator_type not in CaseIndicator.INDICATOR_TYPES:
        flash("Select a valid indicator type.", "danger")
    else:
        try:
            value = _normalize_indicator(indicator_type, request.form.get("value", ""))
            if CaseIndicator.query.filter_by(case_id=case.id, indicator_type=indicator_type, value=value).first():
                flash("That indicator is already linked to this case.", "warning")
            else:
                db.session.add(CaseIndicator(
                    case_id=case.id,
                    indicator_type=indicator_type,
                    value=value,
                    source="analyst",
                ))
                _touch_case(case)
                record_event("case_indicator_added", target_type="case", target_id=case.id, detail=f"Added {indicator_type} indicator to case.")
                db.session.commit()
                flash("Indicator linked to this case.", "success")
        except ValueError as error:
            flash(str(error), "danger")
    return redirect(url_for("cases.view_case", case_id=case.id))


@cases_bp.route("/<int:case_id>/indicators/<int:indicator_id>/remove", methods=["POST"])
@login_required
@roles_required(*STAFF_ROLES)
def remove_case_indicator(case_id, indicator_id):
    case = _accessible_case_or_404(case_id)
    try:
        _ensure_case_mutable(case)
    except ValueError as error:
        flash(str(error), "warning")
        return redirect(url_for("cases.view_case", case_id=case.id))
    indicator = CaseIndicator.query.filter_by(id=indicator_id, case_id=case.id).first()
    if not indicator:
        abort(404)
    if indicator.source != "analyst":
        flash("Indicators derived from a scan are removed when that scan is unlinked.", "warning")
        return redirect(url_for("cases.view_case", case_id=case.id))

    db.session.delete(indicator)
    _touch_case(case)
    record_event("case_indicator_removed", target_type="case", target_id=case.id, detail="Removed analyst-added indicator from case.")
    db.session.commit()
    flash("Indicator removed.", "success")
    return redirect(url_for("cases.view_case", case_id=case.id))


@cases_bp.route("/<int:case_id>/notes", methods=["POST"])
@login_required
@roles_required(*STAFF_ROLES)
def add_case_note(case_id):
    case = _accessible_case_or_404(case_id)
    try:
        _ensure_case_mutable(case)
        if not _add_case_note(case, request.form.get("body", "")):
            raise ValueError("Enter an analyst note before saving.")
        record_event("case_note_added", target_type="case", target_id=case.id, detail="Added an analyst note to case.")
        db.session.commit()
        flash("Analyst note added to the case timeline.", "success")
    except ValueError as error:
        db.session.rollback()
        flash(str(error), "danger")
    return redirect(url_for("cases.view_case", case_id=case.id))
