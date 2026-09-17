"""
Redirect Chain Analysis Subsystem for Guardly
Performs per-hop manual HTTP redirect tracking, loop detection, cross-domain shifts,
HTTPS downgrades/upgrades, and SSRF IP pinning verification.
"""

from typing import Any, Dict, List
import urllib.parse

from services.ssrf import safe_http_get


def analyze_url_redirect_chain(url_string: str, max_hops: int = 10) -> Dict[str, Any]:
    """
    Manually follows redirects (up to max_hops), recording every hop's source, destination,
    HTTP status, and SSRF pinned IP. Evaluates anomalies and computes redirect risk score.
    """
    if not url_string:
        return {"hops": [], "redirect_count": 0, "final_url": "", "risk_score": 0, "anomalies": []}

    try:
        status_code, body, final_url, banner, content_type, pinned_ip, raw_hops = safe_http_get(
            url_string, max_redirects=max_hops
        )
    except Exception:
        status_code, body, final_url, banner, content_type, pinned_ip, raw_hops = 0, "", url_string, "", "", "", []

    hops: List[Dict[str, Any]] = []
    seen_urls = set()
    has_loop = False
    cross_domain_count = 0
    https_downgrades = 0

    prev_domain = ""

    for idx, hop_item in enumerate(raw_hops, start=1):
        src = hop_item.get("source_url", "")
        dst = hop_item.get("destination_url", "")
        st = hop_item.get("status_code", 302)
        pip = hop_item.get("pinned_ip", "")

        if src in seen_urls:
            has_loop = True
        seen_urls.add(src)

        src_parsed = urllib.parse.urlparse(src)
        dst_parsed = urllib.parse.urlparse(dst)

        src_domain = src_parsed.netloc.split(":")[0].lower()
        dst_domain = dst_parsed.netloc.split(":")[0].lower()

        is_cross_domain = False
        if prev_domain and src_domain and prev_domain != src_domain:
            is_cross_domain = True
            cross_domain_count += 1
        prev_domain = dst_domain

        # Scheme downgrade check (HTTPS -> HTTP)
        if src_parsed.scheme == "https" and dst_parsed.scheme == "http":
            https_downgrades += 1

        hops.append({
            "hop_number": idx,
            "status_code": st,
            "source_url": src,
            "destination_url": dst,
            "pinned_ip": pip,
            "is_cross_domain": is_cross_domain,
        })

    anomalies: List[Dict[str, Any]] = []
    risk_score = 0

    if has_loop:
        risk_score += 35
        anomalies.append({
            "finding": "Infinite Redirect Loop Detected",
            "severity": "High",
            "explanation": "The URL redirects back to an earlier URL in the chain, causing an infinite loop.",
            "evidence": f"Total Hops: {len(hops)}",
            "recommendation": "High indicator of evasion or broken redirect infrastructure.",
        })

    if cross_domain_count > 0:
        risk_score += 25
        anomalies.append({
            "finding": f"Cross-Domain Redirect Detected ({cross_domain_count} shift(s))",
            "severity": "High" if cross_domain_count > 1 else "Medium",
            "explanation": f"The URL redirects across {cross_domain_count} distinct domain boundaries.",
            "evidence": f"Cross-Domain Hops: {cross_domain_count}",
            "recommendation": "Verify whether the target domain is owned by the original entity.",
        })

    if https_downgrades > 0:
        risk_score += 30
        anomalies.append({
            "finding": "HTTPS to HTTP Security Downgrade",
            "severity": "High",
            "explanation": "The redirect chain downgrades from an encrypted HTTPS connection to unencrypted HTTP.",
            "evidence": f"Downgrades: {https_downgrades}",
            "recommendation": "Potential Man-in-the-Middle (MitM) or credential sniffing risk.",
        })

    if len(hops) >= 3:
        risk_score += 20
        anomalies.append({
            "finding": f"Excessive Redirect Hops ({len(hops)} hops)",
            "severity": "Medium",
            "explanation": f"The URL traversed {len(hops)} intermediate redirect hops.",
            "evidence": f"Total Hops: {len(hops)}",
            "recommendation": "Multiple redirect hops are commonly used to bypass security scanners.",
        })

    return {
        "original_url": url_string,
        "final_url": final_url or url_string,
        "redirect_count": len(hops),
        "hops": hops,
        "has_loop": has_loop,
        "cross_domain_count": cross_domain_count,
        "https_downgrades": https_downgrades,
        "risk_score": min(100, risk_score),
        "anomalies": anomalies,
    }
