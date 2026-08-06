"""
SOC Threat Graph & Visual Campaign Correlation Engine for Guardly
Constructs node-edge network graphs connecting emails, senders, IP addresses,
malicious URLs, target recipients, and threat verdicts across scan history.
"""

from typing import Any, Dict, List, Optional
from models.scan import EmailScan
from models.user import User


def build_threat_graph_data(scan_id: Optional[int] = None, max_nodes: int = 200) -> Dict[str, Any]:
    """
    Queries EmailScan records and constructs a network graph (Nodes and Edges)
    for visual DFIR threat investigation and campaign correlation.
    """
    query = EmailScan.query.order_by(EmailScan.scan_time.desc())
    if scan_id:
        query = query.filter(EmailScan.id == scan_id)
    else:
        query = query.limit(50)

    scans = query.all()

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id: str, label: str, group: str, risk: str, extra: Dict[str, Any] = None):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "group": group,
                "risk": risk,
                "info": extra or {},
            })

    def add_edge(source: str, target: str, label: str):
        edge_key = f"{source}->{target}:{label}"
        if edge_key not in seen_edges and source in seen_nodes and target in seen_nodes:
            seen_edges.add(edge_key)
            edges.append({
                "from": source,
                "to": target,
                "label": label,
            })

    for scan in scans:
        verdict = scan.verdict or "Low Risk"
        email_node_id = f"email_{scan.id}"
        subj_label = (scan.subject[:25] + "...") if scan.subject and len(scan.subject) > 25 else (scan.subject or f"Email #{scan.id}")

        add_node(
            node_id=email_node_id,
            label=f"📧 {subj_label}",
            group="email",
            risk=verdict,
            extra={
                "scan_id": scan.id,
                "subject": scan.subject,
                "sender": scan.sender,
                "score": scan.risk_score,
                "verdict": verdict,
                "date": scan.scan_time.strftime("%Y-%m-%d %H:%M") if scan.scan_time else "",
            }
        )

        # Sender Domain Node
        if scan.sender:
            sender_str = str(scan.sender).strip()
            domain = sender_str.split("@")[-1] if "@" in sender_str else sender_str
            sender_node_id = f"domain_{domain.lower()}"
            add_node(
                node_id=sender_node_id,
                label=f"🌐 {domain}",
                group="domain",
                risk=verdict if verdict in ["High Risk", "Medium Risk"] else "Low Risk",
                extra={"domain": domain, "sender_email": sender_str}
            )
            add_edge(email_node_id, sender_node_id, "SENT_BY")

        # Recipient Node
        recipient_val = getattr(scan, "receiver", getattr(scan, "recipient", None))
        if recipient_val:
            recip_node_id = f"recip_{str(recipient_val).lower()}"
            add_node(
                node_id=recip_node_id,
                label=f"👤 {recipient_val}",
                group="recipient",
                risk="Safe",
                extra={"recipient": recipient_val}
            )
            add_edge(email_node_id, recip_node_id, "TARGETS")

        # Extract URLs from scan.urls JSON payload
        urls = []
        if scan.urls:
            try:
                import json
                urls = json.loads(scan.urls) if isinstance(scan.urls, str) else scan.urls
            except Exception:
                urls = []

        for u in urls[:3]:
            u_clean = str(u).replace("http://", "").replace("https://", "").split("/")[0]
            url_node_id = f"url_{u_clean.lower()}"
            add_node(
                node_id=url_node_id,
                label=f"🔗 {u_clean[:20]}",
                group="url",
                risk="High Risk" if verdict == "High Risk" else "Medium Risk",
                extra={"url": str(u)}
            )
            add_edge(email_node_id, url_node_id, "CONTAINS_LINK")

    return {
        "nodes": nodes[:max_nodes],
        "edges": edges,
        "summary": {
            "total_emails": len(scans),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "high_risk_nodes": len([n for n in nodes if n["risk"] == "High Risk"]),
        }
    }
