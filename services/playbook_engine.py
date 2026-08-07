"""
Automated SOC Incident Response Playbook Engine for Guardly
Evaluates email threat indicators, authentication status, and risk categories to execute
automated DFIR response playbooks (Quarantine, Credential Revocation, Firewall Blocklists, BEC Alert).
"""

from typing import Any, Dict, List


def execute_soc_playbooks(email_data: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes automated Incident Response playbooks based on email threat findings.
    Returns:
    - active_playbooks: List of executed playbooks with status and recommendations
    - recommended_actions: Actionable SOC mitigation steps
    - blocklist_iocs: Extracted IP, domain, and URL IOC blocklist
    """
    score = analysis.get("score", 0)
    verdict = analysis.get("verdict", "Low Risk")
    findings = analysis.get("findings", [])
    categories = analysis.get("categories", [])
    auth_results = analysis.get("auth_results", {})

    sender_domain = email_data.get("sender_domain") or ""
    urls = email_data.get("urls", [])
    iocs = email_data.get("iocs", {})

    playbooks: List[Dict[str, Any]] = []
    actions: List[str] = []

    # Playbook 1: High-Risk Phishing & Malware Quarantine Playbook
    if score >= 50 or verdict == "High Risk":
        playbooks.append({
            "playbook_id": "PB-101",
            "name": "High-Risk Threat Quarantine & Mailbox Containment",
            "status": "TRIGGERED",
            "severity": "CRITICAL",
            "summary": "Message score exceeded High-Risk threshold (50/100). Automated containment recommended.",
            "steps": [
                "Issue administrative mailbox purge command (M365 / Exchange Search-Mailbox).",
                "Quarantine all inbound messages sharing identical subject line or sender domain.",
                "Revoke active OAuth tokens for target recipient mailboxes.",
            ]
        })
        actions.append("Purge & Quarantine message across all organization mailboxes.")
        actions.append("Revoke user sessions on Identity Provider (Entra ID / Okta).")

    # Playbook 2: Credential Harvesting & Brand Impersonation Mitigation
    has_cred_lure = any("Credential" in c or "Password" in c or "URL" in c for c in categories)
    if has_cred_lure or "Display Name Email Spoofing" in str(findings):
        playbooks.append({
            "playbook_id": "PB-102",
            "name": "Credential Theft & Identity Defense Playbook",
            "status": "TRIGGERED",
            "severity": "HIGH",
            "summary": "Credential harvesting lure or brand impersonation detected.",
            "steps": [
                "Force immediate self-service password reset for recipient.",
                "Enroll recipient in Mandatory Phishing Awareness Retraining.",
                "Block malicious URL targets on Secure Web Gateway (SWG) and DNS Sinkhole.",
            ]
        })
        actions.append("Enforce password reset for targeted email user.")
        actions.append("Add malicious URLs to Secure Web Gateway / Proxy blocklist.")

    # Playbook 3: Business Email Compromise (BEC) & Invoice Fraud Response
    has_bec = any("Invoice" in c or "BEC" in c or "Financial" in c for c in categories)
    if has_bec:
        playbooks.append({
            "playbook_id": "PB-103",
            "name": "BEC & Accounts Payable Fraud Investigation",
            "status": "TRIGGERED",
            "severity": "HIGH",
            "summary": "Wire transfer or financial payment instructions detected in email body.",
            "steps": [
                "Alert Accounts Payable & Finance DFIR leads of potential wire fraud attempt.",
                "Place hold on any pending outbound ACH / Bank transfers matching bank details.",
                "Contact sender via out-of-band phone verification to validate invoice authenticity.",
            ]
        })
        actions.append("Notify Finance / Accounts Payable incident response team.")
        actions.append("Perform out-of-band phone confirmation for payment instruction changes.")

    # Default Low-Risk Monitoring Playbook
    if not playbooks:
        playbooks.append({
            "playbook_id": "PB-100",
            "name": "Standard SOC Routine Monitoring",
            "status": "ACTIVE",
            "severity": "LOW",
            "summary": "No critical threat anomalies triggered. Message logged for routine telemetry audit.",
            "steps": [
                "Retain email telemetry in SOC SIEM data lake for 90 days.",
                "No immediate containment actions required.",
            ]
        })
        actions.append("Log event telemetry to SIEM data lake.")

    # Build Blocklist IOCs
    blocklist_domains = list(set([d for d in iocs.get("domains", []) if d != sender_domain]))
    blocklist_ips = list(set(iocs.get("ip_addresses", [])))

    return {
        "active_playbooks": playbooks,
        "recommended_actions": list(dict.fromkeys(actions)),
        "blocklist": {
            "domains": blocklist_domains[:10],
            "ips": blocklist_ips[:10],
            "urls": urls[:10],
        }
    }
