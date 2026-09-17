"""
URL Shortener & Abused TLD Classifier Engine for Guardly
Detects popular URL shorteners (bit.ly, tinyurl.com, t.co, goo.gl, etc.) and
frequently abused / suspicious TLDs (.zip, .mov, .top, .xyz, .click, .work, .live, etc.).
"""

from typing import Any, Dict

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "cutt.ly", "rb.gy", "is.gd", "rebrand.ly", "tiny.cc", "shorturl.at",
    "bl.ink", "v.gd"
}

SUSPICIOUS_TLDS = {
    ".zip": "Abused binary archive TLD (high phishing risk)",
    ".mov": "Abused video file format TLD",
    ".top": "High-volume spam/phishing TLD",
    ".xyz": "High-volume low-cost domain registry",
    ".click": "Phishing lure TLD",
    ".work": "Generic cheap domain registry",
    ".live": "Common credential harvesting TLD",
    ".gq": "Free domain TLD frequently abused in spam",
    ".cf": "Free domain TLD frequently abused in spam",
    ".ml": "Free domain TLD frequently abused in spam",
    ".tk": "Free domain TLD frequently abused in spam",
    ".rest": "Generic cheap domain registry",
    ".country": "Generic cheap domain registry",
    ".loan": "Financial phishing lure TLD",
    ".win": "Prize/lottery lure TLD",
    ".party": "Generic cheap domain registry",
    ".review": "Feedback/lure TLD",
}


def analyze_tld_and_shortener(hostname: str, root_domain: str) -> Dict[str, Any]:
    """
    Analyzes TLD risk and checks if domain belongs to a known URL shortener service.
    """
    if not hostname:
        return {"is_shortener": False, "is_suspicious_tld": False, "tld": "", "tld_reason": "", "risk": 0}

    host_lower = hostname.lower()
    root_lower = root_domain.lower() if root_domain else host_lower

    is_shortener = host_lower in KNOWN_SHORTENERS or root_lower in KNOWN_SHORTENERS

    # Extract TLD
    tld = ""
    is_suspicious_tld = False
    tld_reason = ""

    for s_tld, reason in SUSPICIOUS_TLDS.items():
        if host_lower.endswith(s_tld):
            tld = s_tld
            is_suspicious_tld = True
            tld_reason = reason
            break

    risk = 0
    if is_shortener:
        risk += 15
    if is_suspicious_tld:
        risk += 20

    return {
        "is_shortener": is_shortener,
        "is_suspicious_tld": is_suspicious_tld,
        "tld": tld,
        "tld_reason": tld_reason,
        "risk": risk,
    }
