"""
Homograph & Lookalike Domain Detection Engine for Guardly
Detects visual similarity, character substitutions (0 -> o, 1 -> l/i, m -> rn, etc.),
and brand impersonation (micr0soft.com, paypaI.com, arnazon.com, g00gle.com, office365-login.com).
"""

import re
from typing import Any, Dict, List, Optional

HOMOGRAPH_SUBSTITUTIONS = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "rn": "m",
    "vv": "w",
}

TARGET_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "chase",
    "bankofamerica",
    "wellsfargo",
    "docusign",
    "office365",
    "facebook",
    "linkedin",
]

LEGIT_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "azure.com"],
    "google": ["google.com", "gmail.com", "googleapis.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
    "docusign": ["docusign.com"],
    "office365": ["office365.com", "office.com"],
    "facebook": ["facebook.com"],
    "linkedin": ["linkedin.com"],
}


def normalize_homograph_domain(domain_str: str) -> str:
    """
    Translates common character substitutions (0->o, 1->i, rn->m, paypai->paypal) for similarity matching.
    """
    res = domain_str.lower().replace("rn", "m").replace("vv", "w")
    for src, dst in HOMOGRAPH_SUBSTITUTIONS.items():
        res = res.replace(src.lower(), dst)
    if "paypai" in res:
        res = res.replace("paypai", "paypal")
    if "g00gle" in res or "g0gle" in res:
        res = res.replace("g00gle", "google").replace("g0gle", "google")
    if "arnazon" in res:
        res = res.replace("arnazon", "amazon")
    return res


def analyze_homograph_and_brand_impersonation(hostname: str) -> Dict[str, Any]:
    """
    Analyzes hostname for homograph lookalikes, character substitution, and brand impersonation.
    """
    if not hostname:
        return {"is_homograph": False, "impersonated_brand": None, "brand_score": 0, "anomalies": []}

    host_lower = hostname.lower()
    normalized_host = normalize_homograph_domain(host_lower)

    is_homograph = False
    impersonated_brand = None
    brand_score = 0
    anomalies: List[Dict[str, Any]] = []

    # Check for target brand presence or substitution
    for brand in TARGET_BRANDS:
        legit_list = LEGIT_BRAND_DOMAINS.get(brand, [])
        if host_lower in legit_list:
            continue  # Truly legitimate domain

        # 1. Direct Substring Match with Hyphenation or Keywords (e.g. office365-login.com, apple-security.com)
        if brand in host_lower or brand in normalized_host:
            is_homograph = True
            impersonated_brand = brand.title()
            brand_score = 40
            anomalies.append({
                "finding": f"Brand Impersonation Target: {impersonated_brand}",
                "severity": "Critical",
                "explanation": f"The domain '{hostname}' contains brand keyword '{brand}' but is not an official {brand} domain.",
                "evidence": f"Hostname: {hostname}\nTarget Brand: {impersonated_brand}",
                "recommendation": "Do not enter credentials or sign in on this domain.",
            })
            break

        # 2. Character Substitution Match (e.g. micr0soft.com, paypaI.com, arnazon.com, g00gle.com)
        pattern = re.compile(rf"\b[a-z0-9-]*{re.escape(brand)}[a-z0-9-]*\b")
        if pattern.search(normalized_host):
            is_homograph = True
            impersonated_brand = brand.title()
            brand_score = 40
            anomalies.append({
                "finding": f"Homograph / Lookalike Domain: {impersonated_brand}",
                "severity": "Critical",
                "explanation": f"The domain '{hostname}' uses character substitution or visual trickery to impersonate {impersonated_brand}.",
                "evidence": f"Original: {hostname}\nNormalized: {normalized_host}\nTarget: {impersonated_brand}",
                "recommendation": "High indicator of targeted phishing or credential harvesting attack.",
            })
            break

    return {
        "is_homograph": is_homograph,
        "impersonated_brand": impersonated_brand,
        "normalized_host": normalized_host,
        "brand_score": brand_score,
        "anomalies": anomalies,
    }
