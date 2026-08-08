"""
SOC Threat Graph Blueprint for Guardly
Exposes interactive visualization workspace and JSON APIs for DFIR campaign correlation.
"""

from flask import Blueprint, jsonify, render_template, request
from models.user import User
from routes.auth import login_required, roles_required
from services.graph_builder import build_threat_graph_data

graph_bp = Blueprint("graph", __name__)


@graph_bp.route("/threat-graph")
@login_required
@roles_required(User.ROLE_ADMIN, User.ROLE_ANALYST)
def view_threat_graph():
    """
    Renders the SOC Visual Threat Graph & Campaign Canvas workspace.
    """
    scan_id = request.args.get("scan_id", type=int)
    return render_template("threat_graph.html", target_scan_id=scan_id)


@graph_bp.route("/api/v1/threat-graph/data")
@login_required
@roles_required(User.ROLE_ADMIN, User.ROLE_ANALYST)
def threat_graph_api():
    """
    JSON API returning graph nodes and edges for network canvas.
    """
    scan_id = request.args.get("scan_id", type=int)
    graph_data = build_threat_graph_data(scan_id=scan_id)
    return jsonify(graph_data)
