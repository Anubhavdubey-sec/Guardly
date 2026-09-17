import re

from scanner.header_analyzer import analyze_email_headers
from scanner.nlp_analyzer import analyze_social_engineering_nlp
from scanner.url_heuristics import assess_url
from services.playbook_engine import execute_soc_playbooks
from services.yara_generator import generate_sigma_rule, generate_yara_rule

EXECUTABLE_EXTENSIONS = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jar", ".ps1", ".msi"}

LEETSPEAK_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
})


def normalize_for_matching(text: str) -> str:
    """
    Normalizes text for robust keyword matching:
    - Lowercases & translates leetspeak characters (0->o, 1->i, 3->e, 4->a, 5->s, 7->t, @->a, $->s)
    - Strips non-alphanumeric punctuation
    - Collapses spaced-out single letters (e.g. 'v e r i f y' -> 'verify')
    - Collapses multiple whitespace characters
    """
    text = (text or "").lower().translate(LEETSPEAK_MAP)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"(?<=\b[a-z0-9])\s+(?=[a-z0-9]\b)", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


KEYWORD_CATEGORIES = {
    "Urgency / pressure tactics": {
        "weight": 12,
        "keywords": [
            "urgent", "immediate action", "act now", "final notice",
            "response required", "within 24 hours", "your account will be closed",
            "expire today", "time sensitive", "last warning", "before it is too late",
            "failure to respond", "account will be terminated", "act immediately",
            "expires in", "limited time only"
        ],
    },
    "Credential harvesting / account security": {
        "weight": 20,
        "keywords": [
            "verify your account", "confirm your identity", "update your password",
            "unusual sign in activity", "unusual login attempt", "click here to verify",
            "reset your password", "login to continue", "security alert",
            "verify your identity", "confirm your details", "account has been locked",
            "suspicious activity detected", "unauthorized access attempt",
            "we noticed a login", "verify now to avoid suspension",
            "your session has expired", "re authenticate your account"
        ],
    },
    "Financial / billing lures": {
        "weight": 18,
        "keywords": [
            "invoice attached", "payment failed", "billing issue",
            "outstanding balance", "wire transfer", "bank account suspended",
            "update payment details", "unauthorized transaction",
            "your card has been declined", "payment could not be processed",
            "refund pending", "billing information required",
            "your subscription payment failed", "overdue invoice"
        ],
    },
    "Invoice / wire fraud (BEC)": {
        "weight": 22,
        "keywords": [
            "are you available right now", "wire the funds", "urgent payment needed",
            "change of bank details", "new payment instructions",
            "please process this payment", "confidential transaction",
            "can you handle this for me", "i need you to do something for me quickly"
        ],
    },
    "Prize / lottery / sweepstakes": {
        "weight": 15,
        "keywords": [
            "you have won", "claim your prize", "lottery winner",
            "free gift card", "congratulations you have been selected",
            "you are eligible for a reward", "claim within 24 hours",
            "selected as a winner", "cash prize awaiting"
        ],
    },
    "Tech support scams": {
        "weight": 18,
        "keywords": [
            "virus detected", "your computer is infected", "microsoft support",
            "call this number immediately", "security software expired",
            "your device has been compromised", "malware detected on your system",
            "apple support case", "windows defender alert"
        ],
    },
    "Delivery / shipping scams": {
        "weight": 12,
        "keywords": [
            "delivery failed", "package on hold", "customs fee required",
            "reschedule your delivery", "tracking number attached",
            "delivery address confirmation needed", "parcel could not be delivered",
            "shipping label attached", "pay a small fee to release your package"
        ],
    },
    "Extortion / sextortion": {
        "weight": 30,
        "keywords": [
            "i have access to your", "pay in bitcoin", "webcam recording",
            "i know your password", "i have been watching you",
            "i recorded you", "send payment within 48 hours or i will",
            "your device was hacked"
        ],
    },
    "HR / payroll fraud": {
        "weight": 22,
        "keywords": [
            "direct deposit change", "payroll update needed",
            "gift cards for employees", "update your banking information for payroll",
            "confirm your salary account", "hr department urgent request"
        ],
    },
    "Tax / government impersonation": {
        "weight": 20,
        "keywords": [
            "irs notice", "tax refund pending", "unpaid taxes",
            "government grant available", "social security number suspended",
            "legal action will be taken", "court summons attached",
            "outstanding fine", "pay immediately to avoid arrest"
        ],
    },
    "Healthcare / insurance scams": {
        "weight": 15,
        "keywords": [
            "your insurance claim", "medicare benefits update",
            "health coverage suspended", "verify your medical information",
            "prescription order confirmation"
        ],
    },
    "Subscription / renewal scams": {
        "weight": 14,
        "keywords": [
            "your subscription has been renewed", "auto renewal notice",
            "cancel your subscription", "membership will expire",
            "renewal payment could not be processed"
        ],
    },
    "Job offer / recruitment scams": {
        "weight": 15,
        "keywords": [
            "work from home opportunity", "earn money fast",
            "you have been selected for this position",
            "no experience required high pay", "send your bank details to receive salary"
        ],
    },
    "Cryptocurrency / investment scams": {
        "weight": 18,
        "keywords": [
            "guaranteed returns", "double your bitcoin", "investment opportunity",
            "crypto giveaway", "act now to claim your tokens",
            "exclusive investment offer"
        ],
    },
    "Charity / disaster relief scams": {
        "weight": 14,
        "keywords": [
            "donate now to help", "disaster relief fund",
            "urgent humanitarian appeal", "your donation is needed immediately"
        ],
    },
    "Generic phishing infrastructure phrases": {
        "weight": 0,
        "keywords": [
            "click here", "this link will expire", "action required",
            "we noticed something unusual", "verify to continue",
            "update required", "click the link below", "confirm now"
        ],
    },
}

# Derived flat set for backward compatibility
SUSPICIOUS_KEYWORDS = set(
    kw for cat in KEYWORD_CATEGORIES.values() for kw in cat["keywords"]
)


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

    # Subject & Body Keyword Analysis (Normalized matching)
    raw_subject = email_data.get("subject") or ""
    raw_body = email_data.get("body") or ""

    norm_subject = normalize_for_matching(raw_subject)
    norm_body = normalize_for_matching(raw_body)
    norm_full_text = f"{norm_subject} {norm_body}".strip()

    raw_keyword_score = 0

    for cat_name, cat_info in KEYWORD_CATEGORIES.items():
        matched_kws = []
        for kw in cat_info["keywords"]:
            norm_kw = normalize_for_matching(kw)
            if norm_kw and norm_kw in norm_full_text:
                matched_kws.append(kw)

        if matched_kws:
            raw_keyword_score += cat_info["weight"]
            kw_list_str = ", ".join(f"'{k}'" for k in matched_kws)
            findings.append(f"Message contains {cat_name.lower()} language: {kw_list_str}.")
            categories.append(cat_name)

    score += min(40, raw_keyword_score)

    # Attachments analysis
    pdf_urls_set = set(email_data.get("pdf_urls", []))
    for att in email_data.get("attachments", []):
        filename = att.get("filename", "")
        filename_lower = filename.lower()
        if any(filename_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
            score += 35
            findings.append(f"Executable attachment detected: {filename}.")
            categories.append("Executable attachments")

        pdf_scan = att.get("pdf_scan")
        if pdf_scan:
            if pdf_scan.get("error"):
                findings.append(f"PDF attachment '{filename}' could not be fully scanned: {pdf_scan['error']}.")
            if pdf_scan.get("urls"):
                pdf_urls_set.update(pdf_scan["urls"])
                score += 20
                url_count = len(pdf_scan["urls"])
                findings.append(f"PDF attachment '{filename}' contains {url_count} embedded link(s) not visible in the message body.")
                categories.append("Link hidden in attachment")

    # URLs analysis
    for url in email_data.get("urls", []):
        is_from_pdf = url in pdf_urls_set
        reasons = assess_url(url)
        if is_from_pdf:
            reasons.append("URL is embedded inside a PDF attachment rather than the message body.")

        if reasons:
            score += 25
            status = "Suspicious"
            source_label = "PDF attachment" if is_from_pdf else "message body"
            for r in reasons:
                findings.append(f"Suspicious URL detected ({source_label}: {url}): {r}")
            categories.append("Suspicious URL")
        else:
            status = "Clean"

        url_assessments.append({
            "url": url,
            "status": status,
            "reasons": reasons,
        })

    # DFIR Email Header Analysis Engine
    headers_dict = email_data.get("headers", {})
    header_dfir = analyze_email_headers(headers_dict)
    
    # Extract auth statuses for backwards compatibility
    spf = header_dfir["authentication"]["spf"]["status"].lower()
    dkim = header_dfir["authentication"]["dkim"]["status"].lower()
    dmarc = header_dfir["authentication"]["dmarc"]["status"].lower()

    if spf in ("fail", "permerror"):
        score += 25
        findings.append("SPF authentication check failed.")
        categories.append("Authentication failure")
    if dkim in ("fail", "permerror"):
        score += 25
        findings.append("DKIM authentication check failed.")
        categories.append("Authentication failure")
    if dmarc in ("fail", "permerror"):
        score += 30
        findings.append("DMARC authentication check failed.")
        categories.append("Authentication failure")

    # Record Critical/High Header DFIR Anomalies (e.g. Free Email Brand Impersonation or Display Name Spoofing)
    for dfir_finding in header_dfir.get("findings", []):
        sev = dfir_finding.get("severity")
        title = dfir_finding.get("finding")
        explanation = dfir_finding.get("explanation")
        if title in ("Display Name Email Spoofing", "Free Email Brand Impersonation"):
            score += 25
            findings.append(f"{title}: {explanation}")
            categories.append("Header anomaly")

    score = min(100, score)
    categories = list(dict.fromkeys(categories))

    if score >= 50:
        verdict = "High Risk"
    elif score >= 20:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    # NLP & AI Social Engineering Lure Detector
    nlp_analysis = analyze_social_engineering_nlp(email_data)

    res_dict = {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "categories": categories,
        "url_assessments": url_assessments,
        "auth_results": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "header_analysis": header_dfir,
        "nlp_analysis": nlp_analysis,
    }

    # Generate Automated YARA, SIEM Sigma Rules, and SOC Incident Response Playbooks
    res_dict["yara_rule"] = generate_yara_rule(email_data, res_dict)
    res_dict["sigma_rule"] = generate_sigma_rule(email_data, res_dict)
    res_dict["soc_playbook"] = execute_soc_playbooks(email_data, res_dict)

    return res_dict
