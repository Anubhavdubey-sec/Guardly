"""
NLP & AI Social Engineering Lure Detector for Guardly
Performs NLP semantic & sentiment scoring to detect executive impersonation (CEO fraud),
coercive urgency pressure, financial routing manipulation, and out-of-band secrecy lures.
"""

import re
from typing import Any, Dict, List

AUTHORITY_KEYWORDS = [
    "ceo", "chief executive", "cfo", "chief financial", "president", "director",
    "executive", "board member", "hr director", "payroll manager", "legal counsel",
    "managing director", "vice president", "treasurer"
]

URGENCY_KEYWORDS = [
    "immediately", "act now", "urgent", "within 1 hour", "within 24 hours",
    "today only", "do not delay", "final notice", "immediate response required",
    "before end of day", "time sensitive", "last warning"
]

FINANCIAL_LURE_KEYWORDS = [
    "wire transfer", "bank details", "update direct deposit", "payroll account",
    "gift card", "apple gift card", "steam card", "overdue invoice",
    "change bank account", "payment instructions", "routing number", "process payment"
]

SECRECY_LURE_KEYWORDS = [
    "keep this confidential", "do not discuss", "i am in a meeting",
    "text me on my mobile", "do not call my desk", "handle this discreetly",
    "busy in a conference", "reply via email only"
]


def analyze_social_engineering_nlp(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Performs NLP semantic & psychological manipulation analysis on email subject and body text.
    """
    subject = str(email_data.get("subject", "") or "").lower()
    body = str(email_data.get("body", "") or "").lower()
    full_text = f"{subject} {body}"

    if not full_text.strip():
        return {
            "social_engineering_score": 0,
            "threat_level": "Minimal",
            "tactics": [],
            "findings": [],
            "scores": {"authority": 0, "urgency": 0, "financial": 0, "secrecy": 0},
        }

    # 1. Authority / Executive Impersonation Analysis
    auth_matches = [k for k in AUTHORITY_KEYWORDS if k in full_text]
    authority_score = min(100, len(auth_matches) * 30)

    # 2. Coercive Urgency & Pressure Analysis
    urgency_matches = [k for k in URGENCY_KEYWORDS if k in full_text]
    urgency_score = min(100, len(urgency_matches) * 25)

    # 3. Financial & Payment Routing Manipulation Analysis
    financial_matches = [k for k in FINANCIAL_LURE_KEYWORDS if k in full_text]
    financial_score = min(100, len(financial_matches) * 35)

    # 4. Out-of-Band Secrecy Lure Analysis
    secrecy_matches = [k for k in SECRECY_LURE_KEYWORDS if k in full_text]
    secrecy_score = min(100, len(secrecy_matches) * 35)

    # Consolidated Social Engineering Confidence Score (0-100)
    se_score = int(
        (authority_score * 0.30) +
        (urgency_score * 0.25) +
        (financial_score * 0.30) +
        (secrecy_score * 0.15)
    )
    se_score = min(100, se_score)

    tactics: List[str] = []
    findings: List[Dict[str, Any]] = []

    if authority_score > 0:
        tactics.append("Executive & Authority Impersonation")
        findings.append({
            "finding": "NLP Signal: Executive & Authority Impersonation",
            "severity": "High" if authority_score >= 60 else "Medium",
            "explanation": f"The email text incorporates authority claims or executive titles ({', '.join(auth_matches[:3])}).",
            "evidence": f"Matched terms: {', '.join(auth_matches)}",
            "recommendation": "Verify sender identity out-of-band before executing requests from executives.",
        })

    if urgency_score > 0:
        tactics.append("Coercive Urgency Pressure")
        findings.append({
            "finding": "NLP Signal: Coercive Urgency Pressure",
            "severity": "Medium",
            "explanation": f"The email uses coercive time-pressure language ({', '.join(urgency_matches[:3])}).",
            "evidence": f"Matched terms: {', '.join(urgency_matches)}",
            "recommendation": "Urgency is a key psychological manipulation tactic; pause and verify legitimacy.",
        })

    if financial_score > 0:
        tactics.append("Financial Payment Routing Lure")
        findings.append({
            "finding": "NLP Signal: Financial Payment & Bank Routing Manipulation",
            "severity": "Critical" if financial_score >= 60 else "High",
            "explanation": f"The email contains financial lures, gift card requests, or bank routing change instructions ({', '.join(financial_matches[:3])}).",
            "evidence": f"Matched terms: {', '.join(financial_matches)}",
            "recommendation": "Enforce secondary phone verification before executing any financial transaction.",
        })

    if secrecy_score > 0:
        tactics.append("Out-of-Band Secrecy Lure")
        findings.append({
            "finding": "NLP Signal: Out-of-Band Secrecy Demand",
            "severity": "High",
            "explanation": f"The email instructs the recipient to maintain secrecy or bypass standard communication channels ({', '.join(secrecy_matches[:3])}).",
            "evidence": f"Matched terms: {', '.join(secrecy_matches)}",
            "recommendation": "Legitimate enterprise procedures do not require bypassing corporate communication channels.",
        })

    if se_score >= 70:
        threat_level = "Critical"
    elif se_score >= 45:
        threat_level = "High"
    elif se_score >= 20:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    return {
        "social_engineering_score": se_score,
        "threat_level": threat_level,
        "tactics": list(dict.fromkeys(tactics)),
        "findings": findings,
        "scores": {
            "authority": authority_score,
            "urgency": urgency_score,
            "financial": financial_score,
            "secrecy": secrecy_score,
        },
    }
