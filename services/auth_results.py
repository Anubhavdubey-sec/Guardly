"""
Authentication Results Parser & Analyzer for Guardly
Parses Authentication-Results, ARC-Authentication-Results, Received-SPF, DKIM-Signature, and DMARC headers.
Produces standardized RFC-compliant protocol evaluation (SPF, DKIM, DMARC, ARC).
"""

import re
from typing import Any, Dict, List, Optional


def parse_authentication_results_header(auth_header: str) -> Dict[str, Any]:
    """
    Parses an RFC 7601 Authentication-Results header string.
    Example:
    mx.google.com; dkim=pass header.i=@gmail.com; spf=pass (google.com: domain of user@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=user@gmail.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gmail.com
    """
    results = {
        "spf": {"status": "NONE", "reason": "No SPF authentication header found.", "domain": "", "alignment": "UNKNOWN", "risk": 0},
        "dkim": {"status": "NONE", "reason": "No DKIM signature validated.", "domain": "", "alignment": "UNKNOWN", "risk": 0},
        "dmarc": {"status": "NONE", "reason": "No DMARC policy result found.", "domain": "", "alignment": "UNKNOWN", "policy": "", "risk": 0},
        "arc": {"status": "NONE", "reason": "No ARC authentication chain present.", "domain": "", "alignment": "UNKNOWN", "risk": 0},
        "raw": auth_header or "",
    }

    if not auth_header:
        return results

    text = auth_header.lower()

    # Parse SPF
    spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b(?:\s+\(([^)]+)\))?", text)
    if spf_match:
        status = spf_match.group(1).upper()
        reason = spf_match.group(2) or f"SPF evaluated as {status}"
        domain_match = re.search(r"domain\s+of\s+([^\s;]+)|smtp\.mailfrom=([^\s;]+)", text)
        domain = domain_match.group(1) or domain_match.group(2) if domain_match else ""
        risk = 0 if status == "PASS" else (25 if status in ("FAIL", "PERMERROR") else 10)
        results["spf"] = {
            "status": status,
            "reason": reason,
            "domain": domain,
            "alignment": "PASS" if status == "PASS" else "FAIL",
            "risk": risk,
        }

    # Parse DKIM
    dkim_match = re.search(r"\bdkim=(pass|fail|neutral|none|permerror|temperror)\b(?:\s+header\.i=([^\s;]+))?", text)
    if dkim_match:
        status = dkim_match.group(1).upper()
        domain = dkim_match.group(2) or ""
        risk = 0 if status == "PASS" else (25 if status in ("FAIL", "PERMERROR") else 10)
        results["dkim"] = {
            "status": status,
            "reason": f"DKIM signature verification returned {status}",
            "domain": domain,
            "alignment": "PASS" if status == "PASS" else "FAIL",
            "risk": risk,
        }

    # Parse DMARC
    dmarc_match = re.search(r"\bdmarc=(pass|fail|bestguesspass|none|permerror|temperror)\b(?:\s+\(([^)]+)\))?", text)
    if dmarc_match:
        status = dmarc_match.group(1).upper()
        if status == "BESTGUESSPASS":
            status = "PASS"
        reason = dmarc_match.group(2) or f"DMARC evaluated as {status}"
        domain_match = re.search(r"header\.from=([^\s;]+)", text)
        domain = domain_match.group(1) if domain_match else ""
        policy_match = re.search(r"p=([a-z]+)", text)
        policy = policy_match.group(1).upper() if policy_match else "NONE"
        risk = 0 if status == "PASS" else (30 if status in ("FAIL", "PERMERROR") else 15)
        results["dmarc"] = {
            "status": status,
            "reason": reason,
            "domain": domain,
            "policy": policy,
            "alignment": "PASS" if status == "PASS" else "FAIL",
            "risk": risk,
        }

    # Parse ARC
    arc_match = re.search(r"\barc=(pass|fail|none)\b", text)
    if arc_match:
        status = arc_match.group(1).upper()
        results["arc"] = {
            "status": status,
            "reason": f"ARC evaluation returned {status}",
            "domain": "",
            "alignment": "PASS" if status == "PASS" else "FAIL",
            "risk": 0 if status == "PASS" else 15,
        }

    return results


def analyze_email_authentication(headers_dict: Dict[str, Any], from_domain: str = "") -> Dict[str, Any]:
    """
    Analyzes authentication mechanisms across all RFC email headers:
    Authentication-Results, Received-SPF, DKIM-Signature, DMARC-Filter, ARC-Authentication-Results.
    """
    auth_header = headers_dict.get("Authentication-Results", "") or headers_dict.get("authentication-results", "")
    if isinstance(auth_header, list):
        auth_header = " ; ".join(str(h) for h in auth_header)

    parsed = parse_authentication_results_header(str(auth_header))

    # Backup Received-SPF header check if SPF status is still NONE
    if parsed["spf"]["status"] == "NONE":
        rec_spf = headers_dict.get("Received-SPF", "") or headers_dict.get("received-spf", "")
        if isinstance(rec_spf, list):
            rec_spf = " ".join(str(s) for s in rec_spf)
        rec_spf_str = str(rec_spf).lower()
        if rec_spf_str:
            spf_m = re.search(r"\b(pass|fail|softfail|neutral|none|permerror|temperror)\b", rec_spf_str)
            if spf_m:
                status = spf_m.group(1).upper()
                parsed["spf"] = {
                    "status": status,
                    "reason": f"Received-SPF header evaluated as {status}",
                    "domain": from_domain,
                    "alignment": "PASS" if status == "PASS" else "FAIL",
                    "risk": 0 if status == "PASS" else (25 if status in ("FAIL", "PERMERROR") else 10),
                }

    # Backup DKIM-Signature header check
    dkim_sig = headers_dict.get("DKIM-Signature", "") or headers_dict.get("dkim-signature", "")
    if dkim_sig and parsed["dkim"]["status"] == "NONE":
        d_match = re.search(r"\bd=([a-zA-Z0-9.-]+)", str(dkim_sig))
        domain = d_match.group(1) if d_match else ""
        parsed["dkim"] = {
            "status": "PASS",
            "reason": f"DKIM-Signature present for domain {domain}",
            "domain": domain,
            "alignment": "PASS" if domain and from_domain and domain.lower() in from_domain.lower() else "NEUTRAL",
            "risk": 0,
        }

    # Backup ARC check
    arc_seal = headers_dict.get("ARC-Seal", "") or headers_dict.get("ARC-Authentication-Results", "")
    if arc_seal and parsed["arc"]["status"] == "NONE":
        parsed["arc"] = {
            "status": "PASS",
            "reason": "ARC seal signature present in headers.",
            "domain": "",
            "alignment": "PASS",
            "risk": 0,
        }

    total_auth_risk = parsed["spf"]["risk"] + parsed["dkim"]["risk"] + parsed["dmarc"]["risk"] + parsed["arc"]["risk"]
    auth_score = max(0, 100 - total_auth_risk)

    return {
        "protocols": parsed,
        "auth_score": auth_score,
        "is_authenticated": parsed["spf"]["status"] == "PASS" or parsed["dkim"]["status"] == "PASS",
    }
