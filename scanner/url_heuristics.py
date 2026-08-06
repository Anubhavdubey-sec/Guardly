"""
Guardly URL Heuristics & Security Assessment Module
Shared between standalone URL scanner (routes/scanner.py) and email threat scanner (scanner/phishing_detector.py).
"""

import ipaddress
import math
import re
import urllib.parse
from typing import List, Optional


def is_ip_literal(host_str: str) -> bool:
    """
    Validate if a given hostname or domain string is a raw IP literal (IPv4 or IPv6),
    properly validating octet ranges and handling ports/brackets.
    """
    if not host_str or not isinstance(host_str, str):
        return False
    host_clean = host_str.strip()
    if host_clean.startswith("[") and "]" in host_clean:
        host_clean = host_clean[1:host_clean.index("]")]
    elif ":" in host_clean and host_clean.count(":") == 1:
        host_clean = host_clean.split(":")[0]
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        return False

KNOWN_IMPERSONATED_BRANDS: List[str] = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "bankofamerica",
    "chase",
    "wellsfargo",
    "facebook",
]

HIGH_RISK_TLDS: List[str] = [
    ".zip",
    ".top",
    ".xyz",
    ".cc",
    ".tk",
    ".club",
    ".work",
    ".click",
    ".buzz",
]

SUSPICIOUS_PATH_KEYWORDS: List[str] = [
    "login",
    "verify",
    "secure",
    "bank",
    "account",
    "signin",
    "track",
    "phish",
]


def calculate_domain_entropy(domain_str: str) -> float:
    """Calculate Shannon entropy of a domain string."""
    if not domain_str:
        return 0.0
    clean_domain = domain_str.split(":")[0].lower()
    if not clean_domain:
        return 0.0
    prob = [float(clean_domain.count(c)) / len(clean_domain) for c in set(clean_domain)]
    return round(-sum([p * math.log(p) / math.log(2) for p in prob]), 2)


def check_brand_impersonation(domain: str) -> Optional[str]:
    """
    Check if domain host impersonates a known brand.
    Returns capitalized brand name if impersonating, else None.
    """
    if not domain:
        return None
    domain_host = domain.lower().split(":")[0]
    for brand in KNOWN_IMPERSONATED_BRANDS:
        if brand in domain_host:
            is_legit = (
                domain_host == f"{brand}.com"
                or domain_host.endswith(f".{brand}.com")
                or domain_host == f"{brand}.org"
                or domain_host.endswith(f".{brand}.org")
                or domain_host == f"{brand}.net"
                or domain_host.endswith(f".{brand}.net")
            )
            if not is_legit:
                return brand.capitalize()
    return None


def assess_url(url: str) -> List[str]:
    """
    Assess URL against heuristic security rules:
    - IP-based host
    - Brand impersonation
    - High-risk TLD
    - High domain entropy (> 4.2)
    - Suspicious path/query keywords

    Returns a list of human-readable reason strings (empty list if clean).
    """
    if not url or not isinstance(url, str):
        return []

    target_url = url.strip()
    if not target_url:
        return []

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    domain_host = (parsed.netloc or parsed.path).lower().split(":")[0]
    path_and_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()

    reasons: List[str] = []

    # 1. IP-based host
    is_ip = is_ip_literal(parsed.netloc or parsed.path)
    if is_ip:
        reasons.append("URL uses an IP address instead of a domain name.")

    # 2. Brand impersonation
    brand = check_brand_impersonation(domain_host)
    if brand:
        reasons.append(f"Appears to impersonate {brand}.")

    # 3. High-risk TLD
    matched_tld = next((tld for tld in HIGH_RISK_TLDS if domain_host.endswith(tld)), None)
    if matched_tld:
        reasons.append(f"Uses a high-risk top-level domain ({matched_tld}).")

    # 4. Domain entropy (> 4.2)
    entropy = calculate_domain_entropy(domain_host)
    if entropy > 4.2:
        reasons.append(
            f"Domain name has unusually high entropy ({entropy}), suggesting a random or generated domain."
        )

    # 5. Suspicious path/query keywords
    matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_and_query]
    if matched_keywords:
        kw_str = ", ".join(f"'{k}'" for k in matched_keywords)
        reasons.append(f"URL path contains suspicious keywords ({kw_str}).")

    return reasons
