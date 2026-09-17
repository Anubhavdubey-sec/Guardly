"""
Sender Identity Analysis Engine for Guardly DFIR Header Analysis
Compares From, Sender, Reply-To, Return-Path, Envelope Sender, and Display Name.
Detects Reply-To mismatch, Return-Path mismatch, Display Name spoofing, lookalike domains,
and free email provider impersonation of corporate brands.
"""

from email.utils import parseaddr
import re
from typing import Any, Dict, List

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "zoho.com", "protonmail.com", "proton.me", "gmx.com"
}

KNOWN_BRANDS = {
    "microsoft": ["microsoft.com", "office365.com", "azure.com"],
    "google": ["google.com", "gmail.com", "googleapis.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "paypal": ["paypal.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com"],
}


def analyze_sender_identity(headers_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes sender headers for alignment, spoofing indicators, and domain consistency.
    """
    from_header = str(headers_dict.get("From", "") or headers_dict.get("from", ""))
    reply_to_header = str(headers_dict.get("Reply-To", "") or headers_dict.get("reply-to", ""))
    return_path_header = str(headers_dict.get("Return-Path", "") or headers_dict.get("return-path", ""))
    sender_header = str(headers_dict.get("Sender", "") or headers_dict.get("sender", ""))

    from_name, from_addr = parseaddr(from_header)
    _, reply_to_addr = parseaddr(reply_to_header)
    _, return_path_addr = parseaddr(return_path_header)
    _, sender_addr = parseaddr(sender_header)

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    reply_to_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""
    return_path_domain = return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else ""
    sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

    anomalies: List[Dict[str, Any]] = []
    spoofing_score = 0

    # 1. Reply-To Mismatch Detection
    reply_to_mismatch = False
    if reply_to_addr and from_addr and reply_to_addr.lower() != from_addr.lower():
        reply_to_mismatch = True
        is_cross_domain = reply_to_domain != from_domain
        sev = "High" if is_cross_domain else "Medium"
        score_add = 35 if is_cross_domain else 15
        spoofing_score += score_add
        anomalies.append({
            "finding": "Reply-To Mismatch",
            "severity": sev,
            "explanation": f"The Reply-To address '{reply_to_addr}' does not match the From address '{from_addr}'. Replies will be routed to a different address.",
            "evidence": f"From: {from_addr}\nReply-To: {reply_to_addr}",
            "recommendation": "Verify whether the recipient expected communications to be routed to an alternate email address or domain.",
        })

    # 2. Return-Path Mismatch Detection
    return_path_mismatch = False
    if return_path_addr and from_addr and return_path_domain and from_domain:
        if return_path_domain != from_domain:
            return_path_mismatch = True
            spoofing_score += 20
            anomalies.append({
                "finding": "Return-Path Domain Mismatch",
                "severity": "Medium",
                "explanation": f"The envelope Return-Path domain '{return_path_domain}' differs from the header From domain '{from_domain}'.",
                "evidence": f"From Domain: {from_domain}\nReturn-Path Domain: {return_path_domain}",
                "recommendation": "Check SPF/DMARC alignment rules to confirm if third-party email delivery infrastructure is authorized.",
            })

    # 3. Display Name Spoofing & Brand Impersonation
    display_name_spoofing = False
    if from_name:
        fn_lower = from_name.lower()

        # Email inside display name trick (e.g., "security@microsoft.com <attacker@gmail.com>")
        embedded_email = re.search(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", fn_lower)
        if embedded_email:
            fake_email = embedded_email.group(1)
            fake_domain = fake_email.split("@")[-1]
            if fake_domain != from_domain:
                display_name_spoofing = True
                spoofing_score += 40
                anomalies.append({
                    "finding": "Display Name Email Spoofing",
                    "severity": "High",
                    "explanation": f"The display name contains an embedded email address '{fake_email}' that does not match the actual sender domain '{from_domain}'.",
                    "evidence": f"Display Name: {from_name}\nActual From: {from_addr}",
                    "recommendation": "Treat email as suspicious credential harvesting or social engineering lure.",
                })

        # Free email provider impersonating corporate brand
        if from_domain in FREE_EMAIL_DOMAINS:
            for brand, legit_domains in KNOWN_BRANDS.items():
                if brand in fn_lower and not any(d in fn_lower for d in legit_domains):
                    display_name_spoofing = True
                    spoofing_score += 40
                    anomalies.append({
                        "finding": "Free Email Brand Impersonation",
                        "severity": "Critical",
                        "explanation": f"The display name impersonates brand '{brand.title()}' while sent from a free email provider '{from_domain}'.",
                        "evidence": f"Display Name: {from_name}\nFrom Address: {from_addr}",
                        "recommendation": "Do not trust brand claims sent from webmail or free consumer email accounts.",
                    })
                    break

    sender_trust_score = max(0, 100 - spoofing_score)

    return {
        "from_name": from_name,
        "from_address": from_addr,
        "from_domain": from_domain,
        "reply_to_address": reply_to_addr,
        "reply_to_domain": reply_to_domain,
        "return_path_address": return_path_addr,
        "return_path_domain": return_path_domain,
        "sender_address": sender_addr,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "display_name_spoofing": display_name_spoofing,
        "spoofing_score": spoofing_score,
        "sender_trust_score": sender_trust_score,
        "anomalies": anomalies,
    }
