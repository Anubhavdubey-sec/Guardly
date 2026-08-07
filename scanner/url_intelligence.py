"""
Enterprise URL Threat Intelligence Engine for Guardly
Integrates URL Parsing, Entropy Analysis, Punycode Detection, Homograph Lookalike Matching,
Abused TLD Classification, URL Shorteners, Redirect Intelligence, and Login Page Detection.
Produces explainable DFIR URL findings and a weighted URL Risk Score (0-100).
"""

from typing import Any, Dict, List

from services.entropy import analyze_url_entropy_and_params
from services.homograph import analyze_homograph_and_brand_impersonation
from services.punycode import analyze_punycode_domain
from services.redirect_analyzer import analyze_url_redirect_chain
from services.tld_analysis import analyze_tld_and_shortener
from services.url_parser import parse_and_normalize_url

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".msi", ".js", ".jar", ".zip", ".rar", ".7z", ".iso", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".docm", ".xlsm"}


def inspect_url_threat_intelligence(url_string: str) -> Dict[str, Any]:
    """
    Performs full enterprise threat intelligence inspection on a URL string.
    Returns:
    - url_risk_score (0-100)
    - risk_level (Safe, Low, Medium, High, Critical)
    - parsed_url: Normalized components, IP classification, credentials
    - entropy_analysis: Shannon Entropy, Base64 query payloads
    - punycode_analysis: IDN / xn-- decoding
    - homograph_analysis: Lookalike domain matching & brand impersonation
    - tld_shortener_analysis: Shortener & suspicious TLD checks
    - redirect_analysis: Manual redirect chain telemetry
    - executable_download: File extension detection
    - findings: List of explainable findings (Finding, Severity, Explanation, Evidence, Recommendation)
    - summary: Human-readable threat summary
    """
    if not url_string:
        return {"url_risk_score": 0, "risk_level": "Safe", "findings": [], "summary": "Empty URL."}

    # 1. URL Parsing & Normalization
    parsed = parse_and_normalize_url(url_string)

    # 2. Entropy & Query Analysis
    entropy_res = analyze_url_entropy_and_params(parsed)

    # 3. Punycode Analysis
    punycode_res = analyze_punycode_domain(parsed["hostname"])

    # 4. Homograph & Brand Impersonation Analysis
    homograph_res = analyze_homograph_and_brand_impersonation(parsed["hostname"])

    # 5. TLD & Shortener Analysis
    tld_res = analyze_tld_and_shortener(parsed["hostname"], parsed["root_domain"])

    # 6. Redirect Intelligence
    redirect_res = analyze_url_redirect_chain(url_string)

    # 7. Executable / File Download Detection
    path_lower = parsed["path"].lower()
    is_executable_download = any(path_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)
    matched_ext = next((ext for ext in EXECUTABLE_EXTENSIONS if path_lower.endswith(ext)), "")

    # Consolidate Findings & Risk Score
    findings: List[Dict[str, Any]] = []
    risk_score = 0

    # Embedded Credentials Check
    if parsed["has_credentials"]:
        risk_score += 50
        findings.append({
            "finding": "Embedded Credentials in URL",
            "severity": "Critical",
            "explanation": "The URL contains inline user credentials (username:password@domain), a common credential theft technique.",
            "evidence": f"URL: {url_string}",
            "recommendation": "Do not open this URL or submit sensitive data.",
        })

    # Numeric / Raw IP URL Check
    if parsed["numeric_ip_type"]:
        risk_score += 35
        findings.append({
            "finding": f"Obfuscated {parsed['numeric_ip_type']} Target",
            "severity": "High",
            "explanation": f"The URL uses a {parsed['numeric_ip_type']} ('{parsed['hostname']}' -> '{parsed['decoded_numeric_ip']}') to obscure its destination.",
            "evidence": f"Original Host: {parsed['hostname']}\nDecoded IP: {parsed['decoded_numeric_ip']}",
            "recommendation": "Avoid visiting numeric IP hosts directly.",
        })
    elif parsed["ip_classification"]["is_ip"]:
        risk_score += 30
        findings.append({
            "finding": "Raw IP Address URL Target",
            "severity": "High",
            "explanation": f"The URL targets a raw IP address ('{parsed['hostname']}') instead of a registered domain name.",
            "evidence": f"IP Target: {parsed['hostname']}",
            "recommendation": "Legitimate enterprise web applications typically use domain names with valid SSL certificates.",
        })

    # Homograph & Brand Impersonation Findings
    findings.extend(homograph_res["anomalies"])
    risk_score += homograph_res["brand_score"]

    # Punycode Findings
    if punycode_res["is_punycode"]:
        risk_score += punycode_res["risk"]
        findings.append({
            "finding": "Punycode (IDN) Encoded Domain Target",
            "severity": "High",
            "explanation": f"The domain uses Punycode encoding ('{punycode_res['original_hostname']}' -> '{punycode_res['decoded_unicode']}') to mimic ASCII brand names.",
            "evidence": f"Punycode: {punycode_res['original_hostname']}\nUnicode: {punycode_res['decoded_unicode']}",
            "recommendation": "Check character sets carefully for visual substitution attacks.",
        })

    # Suspicious TLD & Shorteners
    risk_score += tld_res["risk"]
    if tld_res["is_suspicious_tld"]:
        findings.append({
            "finding": f"Suspicious Top-Level Domain ({tld_res['tld']})",
            "severity": "Medium",
            "explanation": f"The TLD '{tld_res['tld']}' is frequently abused in phishing campaigns. Reason: {tld_res['tld_reason']}",
            "evidence": f"TLD: {tld_res['tld']}",
            "recommendation": "Exercise caution before entering credentials on non-standard TLDs.",
        })
    if tld_res["is_shortener"]:
        findings.append({
            "finding": "URL Shortener Service Detected",
            "severity": "Medium",
            "explanation": f"The URL uses a shortener service ('{parsed['hostname']}') to obscure the final destination.",
            "evidence": f"Shortener Host: {parsed['hostname']}",
            "recommendation": "Inspect the expanded destination URL before clicking.",
        })

    # High Entropy / Obfuscation Findings
    if entropy_res["is_high_entropy"]:
        risk_score += 15
        findings.append({
            "finding": "High Shannon Entropy / Randomness",
            "severity": "Low",
            "explanation": f"The URL exhibits high Shannon Entropy ({entropy_res['url_entropy']} bits/char), indicating obfuscated or algorithmically generated strings.",
            "evidence": f"Entropy: {entropy_res['url_entropy']} bits/char",
            "recommendation": "Inspect query parameters for hidden payloads.",
        })

    if entropy_res["base64_payload_found"]:
        risk_score += 20
        findings.append({
            "finding": "Base64 Encoded Query Parameter Payload",
            "severity": "Medium",
            "explanation": "The URL query parameters contain Base64 encoded payload strings.",
            "evidence": f"Params: {', '.join(entropy_res['suspicious_params'])}",
            "recommendation": "Decode and analyze query parameters for hidden redirect targets or tracking tokens.",
        })

    # Executable Download Warning
    if is_executable_download:
        risk_score += 30
        findings.append({
            "finding": f"Direct Executable / Archive File Download ({matched_ext})",
            "severity": "High",
            "explanation": f"The URL targets a direct file download for file extension '{matched_ext}'.",
            "evidence": f"Path: {parsed['path']}",
            "recommendation": "Do not run or open downloaded executable files from unverified email links.",
        })

    # Redirect Chain Findings
    findings.extend(redirect_res["anomalies"])
    risk_score += redirect_res["risk_score"]

    # Final Risk Level Determination
    url_risk_score = min(100, risk_score)

    if url_risk_score >= 70:
        risk_level = "Critical"
    elif url_risk_score >= 50:
        risk_level = "High"
    elif url_risk_score >= 25:
        risk_level = "Medium"
    elif url_risk_score >= 10:
        risk_level = "Low"
    else:
        risk_level = "Safe"

    summary = (
        f"URL Threat Assessment: {risk_level} Risk (Score: {url_risk_score}/100). "
        f"Host: {parsed['hostname']}. "
        f"Redirects: {redirect_res['redirect_count']} hop(s). "
        f"Entropy: {entropy_res['url_entropy']} bits/char."
    )

    return {
        "url_risk_score": url_risk_score,
        "risk_level": risk_level,
        "parsed_url": parsed,
        "entropy_analysis": entropy_res,
        "punycode_analysis": punycode_res,
        "homograph_analysis": homograph_res,
        "tld_shortener_analysis": tld_res,
        "redirect_analysis": redirect_res,
        "is_executable_download": is_executable_download,
        "matched_executable_extension": matched_ext,
        "findings": findings,
        "summary": summary,
    }
