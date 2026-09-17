"""
Enterprise DFIR Email Header Analysis Engine for Guardly
Integrates Authentication Analysis, Sender Identity Verification, Received Routing Chain Analysis,
Message-ID & Date Validation, Mail Client Fingerprinting, and Header Anomaly Scoring.
Produces explainable DFIR investigation findings and a weighted Header Security Score (0-100).
"""

from typing import Any, Dict, List

from services.auth_results import analyze_email_authentication
from services.header_validator import fingerprint_mail_client, validate_message_id_and_headers
from services.received_parser import parse_received_chain
from services.sender_analysis import analyze_sender_identity


def analyze_email_headers(headers_dict: Dict[str, Any], raw_email_msg: Any = None) -> Dict[str, Any]:
    """
    Performs comprehensive DFIR forensic analysis of raw RFC 5322 email headers.
    Returns:
    - header_security_score (0-100)
    - sub_scores: auth_score, sender_trust_score, infrastructure_trust_score, integrity_score
    - authentication: protocols (SPF, DKIM, DMARC, ARC)
    - sender_identity: From, Reply-To, Return-Path, Display Name analysis
    - routing_chain: Hop-by-hop Received header timeline
    - mail_client: Fingerprinted Mail User Agent / client software
    - message_id_analysis: Message-ID RFC syntax & domain alignment
    - findings: List of explainable findings (Finding, Severity, Explanation, Evidence, Recommendation)
    - technical_summary: High-level forensic summary string
    """
    headers = headers_dict or {}

    # Extract primary sender domain for alignment checks
    from_header = str(headers.get("From", "") or headers.get("from", ""))
    from_addr = from_header.split("<")[-1].replace(">", "").strip() if "<" in from_header else from_header.strip()
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    # 1. Authentication Analysis
    auth_analysis = analyze_email_authentication(headers, from_domain=from_domain)

    # 2. Sender Identity Analysis
    sender_analysis = analyze_sender_identity(headers)

    # 3. Received Header Routing Chain Analysis
    received_analysis = parse_received_chain(headers)

    # 4. Message-ID & Header Integrity Validation
    validator_analysis = validate_message_id_and_headers(headers, from_domain=from_domain)

    # 5. Mail Client Fingerprinting
    mail_client = fingerprint_mail_client(headers)

    # 6. Consolidate Explainable Findings
    all_findings: List[Dict[str, Any]] = []

    # Authentication Findings
    for proto_name, proto_info in auth_analysis["protocols"].items():
        if proto_name == "raw":
            continue
        status = proto_info.get("status", "NONE")
        if status in ("FAIL", "PERMERROR", "SOFTFAIL"):
            sev = "High" if status in ("FAIL", "PERMERROR") else "Medium"
            all_findings.append({
                "finding": f"{proto_name.upper()} Authentication Failure ({status})",
                "severity": sev,
                "explanation": f"The email failed {proto_name.upper()} validation with status {status}. Reason: {proto_info.get('reason', '')}",
                "evidence": f"Protocol: {proto_name.upper()}\nStatus: {status}\nDomain: {proto_info.get('domain', 'N/A')}",
                "recommendation": f"Verify whether the sender domain's {proto_name.upper()} record includes the sending MTA.",
            })

    # Sender Identity Findings
    all_findings.extend(sender_analysis.get("anomalies", []))

    # Routing Chain Findings
    all_findings.extend(received_analysis.get("anomalies", []))

    # Message-ID & Integrity Findings
    all_findings.extend(validator_analysis.get("anomalies", []))

    # Sort findings by severity (Critical > High > Medium > Low > Info)
    severity_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    all_findings.sort(key=lambda f: severity_weights.get(f.get("severity", "Info"), 0), reverse=True)

    # 7. Calculate Overall Weighted Header Security Score (0-100)
    # Higher score = More Secure / Trustworthy (100 = Clean, 0 = High Risk / Spoofed)
    auth_score = auth_analysis["auth_score"]
    sender_trust_score = sender_analysis["sender_trust_score"]
    infra_trust_score = received_analysis["infrastructure_trust_score"]
    integrity_score = validator_analysis["integrity_score"]

    header_security_score = int(
        (auth_score * 0.35) +
        (sender_trust_score * 0.35) +
        (infra_trust_score * 0.15) +
        (integrity_score * 0.15)
    )
    header_security_score = max(0, min(100, header_security_score))

    # Determine Header Verdict
    if header_security_score < 40:
        verdict = "High Risk / Spoofed"
    elif header_security_score < 75:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    # Technical Summary Generation
    tech_summary = (
        f"Header Analysis Verdict: {verdict} (Score: {header_security_score}/100). "
        f"Auth Status: SPF={auth_analysis['protocols']['spf']['status']}, "
        f"DKIM={auth_analysis['protocols']['dkim']['status']}, "
        f"DMARC={auth_analysis['protocols']['dmarc']['status']}. "
        f"Mail Client: {mail_client['client_name']}. "
        f"Traversed {received_analysis['hop_count']} hop(s) over {received_analysis['total_transit_seconds']}s."
    )

    return {
        "header_security_score": header_security_score,
        "verdict": verdict,
        "sub_scores": {
            "auth_score": auth_score,
            "sender_trust_score": sender_trust_score,
            "infrastructure_trust_score": infra_trust_score,
            "integrity_score": integrity_score,
        },
        "authentication": auth_analysis["protocols"],
        "sender_identity": {
            "from_name": sender_analysis["from_name"],
            "from_address": sender_analysis["from_address"],
            "from_domain": sender_analysis["from_domain"],
            "reply_to_address": sender_analysis["reply_to_address"],
            "return_path_address": sender_analysis["return_path_address"],
            "reply_to_mismatch": sender_analysis["reply_to_mismatch"],
            "return_path_mismatch": sender_analysis["return_path_mismatch"],
            "display_name_spoofing": sender_analysis["display_name_spoofing"],
        },
        "routing_chain": {
            "hop_count": received_analysis["hop_count"],
            "total_transit_seconds": received_analysis["total_transit_seconds"],
            "hops": received_analysis["hops"],
        },
        "mail_client": mail_client,
        "message_id": validator_analysis["message_id"],
        "findings": all_findings,
        "technical_summary": tech_summary,
    }
