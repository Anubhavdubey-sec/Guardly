import re

EXECUTABLE_EXTENSIONS = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jar", ".ps1", ".msi"}
SUSPICIOUS_KEYWORDS = {"urgent", "verify", "account suspended", "password reset", "bank", "billing", "immediate action"}


def analyze_email(email_data):
    score = 0
    findings = []
    categories = []
    url_assessments = []

    # Sender analysis
    reply_to = email_data.get("reply_to", "")
    from_address = email_data.get("from_address", "")
    if reply_to and from_address and reply_to.lower() != from_address.lower():
        score += 25
        findings.append("Reply-To address does not match From address.")
        categories.append("Header anomaly")

    # Subject analysis
    subject = (email_data.get("subject") or "").lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in subject:
            score += 15
            findings.append(f"Subject contains urgent/suspicious keyword: '{kw}'.")
            categories.append("Urgent language")
            break

    # Attachments analysis
    for att in email_data.get("attachments", []):
        filename = att.get("filename", "").lower()
        if any(filename.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
            score += 35
            findings.append(f"Executable attachment detected: {att.get('filename')}.")
            categories.append("Executable attachments")

    # URLs analysis
    for url in email_data.get("urls", []):
        reasons = []
        status = "Clean"
        if re.search(r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            score += 25
            status = "Suspicious"
            reasons.append("URL uses an IP address instead of a domain name.")
            findings.append(f"Suspicious IP-based URL: {url}")
            categories.append("Suspicious URL")
        url_assessments.append({
            "url": url,
            "status": status,
            "reasons": reasons,
        })

    # Header authentication simulation
    auth_header = str(email_data.get("headers", {}).get("Authentication-Results", "")).lower()
    spf = "pass" if "spf=pass" in auth_header else ("fail" if "spf=fail" in auth_header else "not available")
    dkim = "pass" if "dkim=pass" in auth_header else ("fail" if "dkim=fail" in auth_header else "not available")
    dmarc = "pass" if "dmarc=pass" in auth_header else ("fail" if "dmarc=fail" in auth_header else "not available")

    if spf == "fail":
        score += 15
        findings.append("SPF authentication check failed.")
        categories.append("Authentication failure")
    if dmarc == "fail":
        score += 15
        findings.append("DMARC authentication check failed.")
        categories.append("Authentication failure")

    score = min(100, score)
    categories = list(dict.fromkeys(categories))

    if score >= 50:
        verdict = "High Risk"
    elif score >= 20:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "categories": categories,
        "url_assessments": url_assessments,
        "auth_results": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
    }
