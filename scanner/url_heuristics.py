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

KNOWN_SHORTENERS: List[str] = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rb.gy",
    "shorturl.at",
    "cutt.ly",
    "tiny.cc",
    "rebrand.ly",
    "bl.ink",
    "v.gd",
]


def is_shortener(domain_str: str) -> bool:
    """Check if domain belongs to a known URL shortener service."""
    if not domain_str:
        return False
    d = domain_str.lower().split(":")[0]
    return any(d == s or d.endswith("." + s) for s in KNOWN_SHORTENERS)


def analyze_redirect_chain(
    original_url: str, final_url: str, raw_hops: List[dict]
) -> dict:
    """
    Performs enterprise redirect chain analysis:
    - Tracks per-hop telemetry (source/destination URLs & domains, HTTP status code, pinned IP)
    - Detects redirect loops, cross-domain shifts, scheme upgrades/downgrades, URL shorteners, IP destinations, and high-risk TLDs
    - Computes dedicated redirect risk score
    """
    hops = []
    flags = []
    visited_urls = set()
    visited_domains = set()

    clean_orig = original_url if original_url.startswith(("http://", "https://")) else "http://" + original_url
    orig_parsed = urllib.parse.urlparse(clean_orig)
    orig_domain = (orig_parsed.netloc or orig_parsed.path).lower().split(":")[0]
    visited_urls.add(clean_orig.lower())
    visited_domains.add(orig_domain)

    has_loop = False
    has_cross_domain = False
    has_https_upgrade = False
    has_https_downgrade = False
    has_shortened_url = False
    has_ip_destination = False
    has_high_risk_tld = False
    redirect_risk = 0

    for h in raw_hops:
        src_url = h.get("source_url", "")
        dest_url = h.get("destination_url", "")
        if not src_url or not dest_url:
            continue

        src_parsed = urllib.parse.urlparse(src_url if src_url.startswith(("http://", "https://")) else "http://" + src_url)
        dest_parsed = urllib.parse.urlparse(dest_url if dest_url.startswith(("http://", "https://")) else "http://" + dest_url)
        src_dom = (src_parsed.netloc or src_parsed.path).lower().split(":")[0]
        dest_dom = (dest_parsed.netloc or dest_parsed.path).lower().split(":")[0]

        is_cross = (src_dom != dest_dom)
        is_up = (src_parsed.scheme == "http" and dest_parsed.scheme == "https")
        is_down = (src_parsed.scheme == "https" and dest_parsed.scheme == "http")
        is_short = is_shortener(src_dom) or is_shortener(dest_dom)
        is_ip = is_ip_literal(dest_dom)
        is_hr_tld = any(dest_dom.endswith(tld) for tld in HIGH_RISK_TLDS)
        brand_dest = check_brand_impersonation(dest_dom)

        if dest_url.lower() in visited_urls or dest_dom in visited_domains:
            has_loop = True
        visited_urls.add(dest_url.lower())
        visited_domains.add(dest_dom)

        if is_cross:
            has_cross_domain = True
        if is_up:
            has_https_upgrade = True
        if is_down:
            has_https_downgrade = True
        if is_short:
            has_shortened_url = True
        if is_ip:
            has_ip_destination = True
        if is_hr_tld:
            has_high_risk_tld = True

        hops.append({
            "hop_number": h.get("hop_number", len(hops) + 1),
            "status_code": h.get("status_code", 302),
            "source_url": src_url,
            "destination_url": dest_url,
            "source_domain": src_dom,
            "destination_domain": dest_dom,
            "pinned_ip": h.get("pinned_ip"),
            "is_cross_domain": is_cross,
            "is_https_upgrade": is_up,
            "is_https_downgrade": is_down,
            "is_shortened_url": is_short,
            "is_ip_destination": is_ip,
            "is_high_risk_tld": is_hr_tld,
            "brand_impersonation": brand_dest,
        })

    if has_loop:
        redirect_risk += 40
        flags.append("Redirect loop detected in chain.")
    if has_https_downgrade:
        redirect_risk += 35
        flags.append("HTTPS to insecure HTTP downgrade detected.")
    if has_ip_destination:
        redirect_risk += 30
        flags.append("Redirects to a raw IP address.")
    if has_high_risk_tld:
        redirect_risk += 25
        flags.append("Redirects to a high-risk top-level domain.")
    if has_shortened_url:
        redirect_risk += 15
        flags.append("URL shortener service used in chain.")
    if has_cross_domain:
        redirect_risk += 10
        flags.append("Cross-domain redirect detected.")
    if len(hops) > 3:
        redirect_risk += 15
        flags.append(f"High redirect hop count ({len(hops)} hops).")

    return {
        "has_redirects": len(hops) > 0,
        "total_hops": len(hops),
        "original_url": original_url,
        "final_url": final_url,
        "hops": hops,
        "has_loop": has_loop,
        "has_cross_domain": has_cross_domain,
        "has_https_upgrade": has_https_upgrade,
        "has_https_downgrade": has_https_downgrade,
        "has_shortened_url": has_shortened_url,
        "has_ip_destination": has_ip_destination,
        "has_high_risk_tld": has_high_risk_tld,
        "risk_score": min(100, redirect_risk),
        "flags": flags,
    }


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
    "signin",
    "bank",
    "phish",
    "secure-login",
    "password-reset",
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
    Check if domain host impersonates a known brand using tokenized label comparison.
    Returns capitalized brand name if impersonating, else None.
    """
    if not domain:
        return None
    domain_host = domain.lower().split(":")[0]
    tokens = re.split(r"[^a-z0-9]", domain_host)
    for brand in KNOWN_IMPERSONATED_BRANDS:
        if brand in tokens:
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

    # 5. Suspicious path/query keywords (requires 2+ keywords or co-occurrence with domain anomaly)
    matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_and_query]
    has_domain_anomaly = is_ip or bool(brand) or bool(matched_tld) or (entropy > 4.2)
    if len(matched_keywords) >= 2 or (matched_keywords and has_domain_anomaly):
        kw_str = ", ".join(f"'{k}'" for k in matched_keywords)
        reasons.append(f"URL path contains suspicious keywords ({kw_str}).")

    return reasons
