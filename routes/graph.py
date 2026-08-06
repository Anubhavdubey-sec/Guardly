"""
SOC Threat Graph Blueprint for Guardly
Exposes interactive visualization workspace and JSON APIs for DFIR campaign correlation.
"""

from flask import Blueprint, jsonify, render_template, request
from routes.auth import login_required
from services.graph_builder import build_threat_graph_data

graph_bp = Blueprint("graph", __name__)


@graph_bp.route("/threat-graph")
def view_threat_graph():
    """
    Renders the SOC Visual Threat Graph & Campaign Canvas workspace.
    """
    scan_id = request.args.get("scan_id", type=int)
    return render_template("threat_graph.html", target_scan_id=scan_id)


@graph_bp.route("/api/v1/threat-graph/data")
def threat_graph_api():
    """
    JSON API returning graph nodes and edges for network canvas.
    """
    scan_id = request.args.get("scan_id", type=int)
    graph_data = build_threat_graph_data(scan_id=scan_id)
    return jsonify(graph_data)
