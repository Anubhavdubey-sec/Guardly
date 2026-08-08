"""
Threat Analysis Engine Orchestrator for Guardly (Phase 4 / Module 3).
Executes modular security analyzers: HeaderAnalyzer, AuthenticationAnalyzer,
SenderAnalyzer, ContentAnalyzer, URLAnalyzer, AttachmentAnalyzer, and IOCAnalyzer.
Calculates deterministic weighted threat score (0-100), severity, and recommendation decision.
"""

import os
import re
import json
import html
import unicodedata
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

# Import existing Guardly security scanners & services
from scanner.header_analyzer import analyze_email_headers
from services.auth_results import parse_authentication_results_header
from scanner.url_intelligence import inspect_url_threat_intelligence
from scanner.nlp_analyzer import analyze_social_engineering_nlp
from scanner.pdf_scanner import extract_pdf_intel
from scanner.qr_ocr_scanner import scan_attachment_for_quishing
from services.homograph import analyze_homograph_and_brand_impersonation
from services.tld_analysis import analyze_tld_and_shortener

logger = logging.getLogger("guardly.services.threat_analysis")

# Dangerous & Script File Extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".scr", ".pif", ".com", ".cpl", ".hta", ".msi", ".msp", ".jar", ".chm",
    ".vbe", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".iso", ".img", ".dll"
}

ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".cab"}

# IPv4 / IPv6 / Domain / Email / Crypto Regex Patterns
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
IPV6_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b"
)
CRYPTO_WALLETS_REGEX = re.compile(
    r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39}|0x[a-fA-F0-9]{40})\b"
)

# Known Brand Domains for Impersonation Checks
POPULAR_BRANDS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "facebook.com", "instagram.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "dhl.com", "fedex.com", "ups.com"
}


def normalize_text_content(text: str) -> str:
    """
    Normalizes text for multilingual phishing & content analysis:
    - Normalizes NFKC Unicode characters & strips zero-width spaces/joiners.
    - Decodes HTML entities (`&nbsp;`, `&#39;`).
    - Collapses multiple whitespace.
    """
    if not text:
        return ""

    # Decode HTML entities
    unescaped = html.unescape(text)

    # Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", unescaped)

    # Remove zero-width & invisible control characters (\u200b, \u200c, \u200d, \ufeff)
    cleaned = re.sub(r'[\u200b-\u200f\ufeff\u202a-\u202e]', '', normalized)

    # Lowercase & normalize spaces
    return re.sub(r'\s+', ' ', cleaned).strip()


class HeaderAnalyzer:
    """Analyzes RFC 5322 headers for hop anomalies, Return-Path mismatch, and clock skew."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        headers = parsed_email.get("headers", {})
        from_addr = parsed_email.get("from", "")
        reply_to = parsed_email.get("reply_to", "")
        return_path = parsed_email.get("return_path", "")
        received_hops = parsed_email.get("received", [])

        # Call existing header analysis module
        header_result = analyze_email_headers(headers_dict=headers)

        findings = [f.get("finding", str(f)) if isinstance(f, dict) else str(f) for f in header_result.get("findings", [])]

        # Additional Return-Path mismatch check
        if return_path and from_addr:
            from_domain = from_addr.split("@")[-1].lower().strip("> ")
            rp_domain = return_path.split("@")[-1].lower().strip("> ")
            if from_domain and rp_domain and from_domain != rp_domain:
                findings.append(f"Return-Path domain ({rp_domain}) mismatch with From domain ({from_domain})")

        return {
            "findings": findings,
            "anomaly_count": len(findings),
            "hop_count": len(received_hops),
            "header_score_penalty": min(35, len(findings) * 12),
        }


class AuthenticationAnalyzer:
    """Evaluates SPF, DKIM, DMARC, and Authentication-Results."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        auth_str = parsed_email.get("auth_results", "")
        headers = parsed_email.get("headers", {})

        if not auth_str and isinstance(headers, dict):
            auth_str = str(headers.get("Authentication-Results", ""))

        parsed_auth = parse_authentication_results_header(auth_str)

        spf = parsed_auth.get("spf", {}).get("status", "NOT_PRESENT").upper() if isinstance(parsed_auth.get("spf"), dict) else "NOT_PRESENT"
        dkim = parsed_auth.get("dkim", {}).get("status", "NOT_PRESENT").upper() if isinstance(parsed_auth.get("dkim"), dict) else "NOT_PRESENT"
        dmarc = parsed_auth.get("dmarc", {}).get("status", "NOT_PRESENT").upper() if isinstance(parsed_auth.get("dmarc"), dict) else "NOT_PRESENT"

        findings = []
        score_penalty = 0

        if spf in ("FAIL", "SOFTFAIL"):
            findings.append(f"SPF authentication status: {spf}")
            score_penalty += 20
        elif spf == "NOT_PRESENT":
            spf = "NOT_PRESENT"

        if dkim == "FAIL":
            findings.append("DKIM signature validation FAILED")
            score_penalty += 20
        elif dkim == "NOT_PRESENT":
            dkim = "NOT_PRESENT"

        if dmarc == "FAIL":
            findings.append("DMARC alignment validation FAILED")
            score_penalty += 25
        elif dmarc == "NOT_PRESENT":
            dmarc = "NOT_PRESENT"

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "auth_results_raw": auth_str,
            "findings": findings,
            "auth_score_penalty": score_penalty,
        }


class SenderAnalyzer:
    """Analyzes sender display-name impersonation, domain mismatch, lookalike domains, and homographs."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        from_raw = parsed_email.get("from", "")
        reply_to = parsed_email.get("reply_to", "")
        return_path = parsed_email.get("return_path", "")

        from_domain = ""
        display_name = ""
        if "@" in from_raw:
            parts = from_raw.split("<")
            if len(parts) > 1:
                display_name = parts[0].strip(' "')
                from_domain = parts[1].split("@")[-1].strip("> ").lower()
            else:
                from_domain = from_raw.split("@")[-1].strip("> ").lower()
        else:
            display_name = from_raw

        reply_domain = reply_to.split("@")[-1].strip("> ").lower() if "@" in reply_to else ""
        return_domain = return_path.split("@")[-1].strip("> ").lower() if "@" in return_path else ""

        findings = []
        score_penalty = 0

        # Homograph / Punycode check on sender domain
        homograph_info = analyze_homograph_and_brand_impersonation(from_domain)
        if homograph_info.get("is_homograph") or from_domain.startswith("xn--"):
            findings.append(f"Sender domain uses Punycode/IDN visual homograph: {from_domain}")
            score_penalty += 30

        # Display Name Brand Impersonation check
        disp_clean = re.sub(r"[^a-z0-9]", "", display_name.lower())
        for brand in POPULAR_BRANDS:
            brand_name = brand.split(".")[0]
            if brand_name in disp_clean and brand_name not in from_domain:
                findings.append(f"Display Name impersonation detected: '{display_name}' claims brand '{brand_name}' but domain is '{from_domain}'")
                score_penalty += 35
                break

        # Reply-To Mismatch
        if reply_domain and from_domain and reply_domain != from_domain:
            findings.append(f"Reply-To domain ({reply_domain}) does not match From domain ({from_domain})")
            score_penalty += 20

        # TLD Risk
        tld_info = analyze_tld_and_shortener(from_domain, from_domain)
        if tld_info.get("is_suspicious_tld"):
            findings.append(f"Sender domain uses suspicious TLD: {tld_info.get('tld')}")
            score_penalty += 15

        return {
            "from_domain": from_domain,
            "display_name": display_name,
            "reply_to_domain": reply_domain,
            "return_path_domain": return_domain,
            "is_homograph": homograph_info.get("is_homograph", False),
            "findings": findings,
            "sender_score_penalty": score_penalty,
        }


class ContentAnalyzer:
    """Analyzes plain text & HTML bodies for credential lures, suspension pressure, BEC, and scam lures."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        text_body = parsed_email.get("text_body", "")
        html_body = parsed_email.get("html_body", "")
        subject = parsed_email.get("subject", "")

        combined_text = normalize_text_content(f"{subject}\n{text_body}\n{html_body}")

        # Reuse Guardly AI NLP Lure Engine
        nlp_res = analyze_social_engineering_nlp(parsed_email)

        findings = []
        score = nlp_res.get("social_engineering_score", 0)

        # Multilingual & Normalized Keyword Pattern Scans
        patterns = {
            "Credential / Password Request": r"\b(?:verify|update|confirm|enter|reset)\s+(?:your\s+)?(?:password|credential|login|passcode|otp|mfa)\b",
            "Account Suspension Threat": r"\b(?:account|access|service)\s+(?:will\s+be\s+)?(?:suspended|terminated|disabled|locked|closed|blocked)\b",
            "Urgent Payment / Invoice Scam": r"\b(?:urgent|overdue|immediate|pending)\s+(?:payment|invoice|wire|transfer|remittance|gift\s*card)\b",
            "Security Alert / Fake Notification": r"\b(?:unauthorized|suspicious|unusual)\s+(?:login|activity|access|attempt|sign-in)\b",
            "Tax / Refund Scam": r"\b(?:tax|refund|rebate|claim|grant|inheritance)\s+(?:eligible|available|amount|payout)\b",
        }

        matched_tactics = nlp_res.get("tactics", [])
        for label, pat in patterns.items():
            if re.search(pat, combined_text, re.IGNORECASE):
                if label not in matched_tactics:
                    matched_tactics.append(label)
                findings.append(f"Content indicator detected: {label}")

        return {
            "social_engineering_score": score,
            "threat_level": nlp_res.get("threat_level", "Low Risk"),
            "tactics": matched_tactics,
            "findings": findings,
            "content_score_penalty": min(40, score // 2 + len(findings) * 5),
        }


class URLAnalyzer:
    """Analyzes extracted URLs using Guardly URL Intelligence Engine (Non-executing)."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str], int]:
        urls = parsed_email.get("urls", [])
        url_findings = []
        analyzed_urls = []
        total_penalty = 0

        for target_url in urls[:25]:  # Limit to 25 URLs max for performance
            # Reuse Guardly URL Intelligence engine
            intel = inspect_url_threat_intelligence(target_url)

            u_findings = [f.get("finding", str(f)) if isinstance(f, dict) else str(f) for f in intel.get("findings", [])]
            u_score = intel.get("url_risk_score", 0)

            analyzed_urls.append({
                "url": target_url,
                "score": u_score,
                "verdict": intel.get("risk_level", "Low Risk"),
                "findings": u_findings,
            })

            for f in u_findings:
                if f not in url_findings:
                    url_findings.append(f"URL [{target_url[:40]}...]: {f}")

            if u_score >= 50:
                total_penalty += 25
            elif u_score >= 25:
                total_penalty += 10

        return analyzed_urls, url_findings, min(45, total_penalty)


class AttachmentAnalyzer:
    """Safe static analysis of attachment metadata: SHA-256, dangerous extensions, double extensions, MIME mismatch."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str], int]:
        attachments = parsed_email.get("attachments", [])
        att_findings = []
        analyzed_atts = []
        total_penalty = 0

        for att in attachments:
            filename = att.get("filename", "")
            orig_filename = att.get("original_filename", filename)
            mime_type = att.get("mime_type", "")
            size_bytes = att.get("size", 0)
            sha256 = att.get("sha256", "")
            storage_path = att.get("storage_path", "")

            ext = os.path.splitext(filename)[1].lower()
            orig_ext = os.path.splitext(orig_filename)[1].lower()

            att_item = {
                "filename": filename,
                "original_filename": orig_filename,
                "mime_type": mime_type,
                "size": size_bytes,
                "sha256": sha256,
                "storage_path": storage_path,
                "findings": [],
            }

            # 1. Dangerous Extension Check
            if ext in DANGEROUS_EXTENSIONS or orig_ext in DANGEROUS_EXTENSIONS:
                msg = f"Attachment '{filename}' has executable/dangerous extension ({ext})"
                att_item["findings"].append(msg)
                att_findings.append(msg)
                total_penalty += 35

            # 2. Double Extension Check (e.g. invoice.pdf.exe)
            filename_parts = filename.split(".")
            if len(filename_parts) > 2:
                penultimate_ext = f".{filename_parts[-2].lower()}"
                if penultimate_ext in {".pdf", ".doc", ".docx", ".xls", ".png", ".jpg", ".txt"}:
                    msg = f"Attachment '{filename}' uses double extension deception ({penultimate_ext}{ext})"
                    att_item["findings"].append(msg)
                    att_findings.append(msg)
                    total_penalty += 30

            # 3. PDF Attachment Scan
            if ext == ".pdf" and storage_path and os.path.exists(storage_path):
                try:
                    with open(storage_path, "rb") as pf:
                        pdf_bytes = pf.read()
                    pdf_res = extract_pdf_intel(pdf_bytes)
                    if pdf_res.get("urls"):
                        msg = f"PDF attachment '{filename}' contains embedded URLs: {', '.join(pdf_res['urls'][:3])}"
                        att_item["findings"].append(msg)
                        att_findings.append(msg)
                        total_penalty += 15
                except Exception as pdf_err:
                    logger.debug(f"PDF scan error for {filename}: {pdf_err}")

            # 4. Image QR Code Quishing Scan
            if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"} and storage_path and os.path.exists(storage_path):
                try:
                    qr_res = scan_attachment_for_quishing(storage_path)
                    if qr_res.get("quishing_detected"):
                        msg = f"QR code embedded in image attachment '{filename}' pointing to URL: {qr_res.get('qr_url')}"
                        att_item["findings"].append(msg)
                        att_findings.append(msg)
                        total_penalty += 35
                except Exception as qr_err:
                    logger.debug(f"QR scan error for {filename}: {qr_err}")

            analyzed_atts.append(att_item)

        return analyzed_atts, att_findings, min(45, total_penalty)


class IOCAnalyzer:
    """Extracts IPv4, IPv6, Domains, URLs, Emails, SHA-256 hashes, and Crypto wallet addresses."""

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, List[str]]:
        text_body = parsed_email.get("text_body", "")
        html_body = parsed_email.get("html_body", "")
        headers = str(parsed_email.get("headers", {}))
        attachments = parsed_email.get("attachments", [])
        urls = parsed_email.get("urls", [])

        combined = f"{headers}\n{text_body}\n{html_body}"

        ips = set(IPV4_REGEX.findall(combined) + IPV6_REGEX.findall(combined))
        domains = set(DOMAIN_REGEX.findall(combined))
        emails = set(EMAIL_REGEX.findall(combined))
        cryptos = set(CRYPTO_WALLETS_REGEX.findall(combined))
        hashes = set()

        for att in attachments:
            if att.get("sha256"):
                hashes.add(att["sha256"])

        # Filter out common false positives
        clean_ips = [ip for ip in ips if not ip.startswith("127.") and ip != "0.0.0.0"]
        clean_domains = [d for d in domains if len(d) <= 253 and not d.endswith(".local")]

        return {
            "ip_addresses": sorted(list(clean_ips)),
            "domains": sorted(list(clean_domains)),
            "urls": sorted(list(set(urls))),
            "email_addresses": sorted(list(emails)),
            "hashes": sorted(list(hashes)),
            "crypto_wallets": sorted(list(cryptos)),
        }


class ThreatAnalysisEngine:
    """
    Main Threat Analysis Orchestrator for Guardly.
    Coordinates HeaderAnalyzer, AuthenticationAnalyzer, SenderAnalyzer,
    ContentAnalyzer, URLAnalyzer, AttachmentAnalyzer, and IOCAnalyzer.
    Calculates deterministic weighted score (0-100), severity, and recommendation decision.
    """

    def __init__(self):
        self.header_analyzer = HeaderAnalyzer()
        self.auth_analyzer = AuthenticationAnalyzer()
        self.sender_analyzer = SenderAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.ioc_analyzer = IOCAnalyzer()

    def analyze(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes full security analysis on a structured email object.

        Returns:
            Structured Analysis Result dictionary.
        """
        msg_id = parsed_email.get("message_id", "unknown_msg")

        # 1. Execute individual analyzers
        header_res = self.header_analyzer.analyze(parsed_email)
        auth_res = self.auth_analyzer.analyze(parsed_email)
        sender_res = self.sender_analyzer.analyze(parsed_email)
        content_res = self.content_analyzer.analyze(parsed_email)
        analyzed_urls, url_findings, url_penalty = self.url_analyzer.analyze(parsed_email)
        analyzed_atts, att_findings, att_penalty = self.attachment_analyzer.analyze(parsed_email)
        iocs = self.ioc_analyzer.analyze(parsed_email)

        # 2. Combine findings & compute deterministic risk score
        all_findings = []
        all_findings.extend(header_res.get("findings", []))
        all_findings.extend(auth_res.get("findings", []))
        all_findings.extend(sender_res.get("findings", []))
        all_findings.extend(content_res.get("findings", []))
        all_findings.extend(url_findings)
        all_findings.extend(att_findings)

        # Weighted Score Computation
        raw_score = (
            header_res.get("header_score_penalty", 0) +
            auth_res.get("auth_score_penalty", 0) +
            sender_res.get("sender_score_penalty", 0) +
            content_res.get("content_score_penalty", 0) +
            url_penalty +
            att_penalty
        )

        final_risk_score = min(100, max(0, int(raw_score)))

        # Determine Severity & Recommendation
        if final_risk_score >= 80:
            severity = "CRITICAL"
            recommendation = "QUARANTINE"
        elif final_risk_score >= 60:
            severity = "HIGH"
            recommendation = "QUARANTINE"
        elif final_risk_score >= 30:
            severity = "MEDIUM"
            recommendation = "REVIEW"
        else:
            severity = "LOW"
            recommendation = "ALLOW"

        result = {
            "message_id": msg_id,
            "risk_score": final_risk_score,
            "severity": severity,
            "recommendation": recommendation,
            "findings": all_findings,
            "authentication": {
                "spf": auth_res.get("spf"),
                "dkim": auth_res.get("dkim"),
                "dmarc": auth_res.get("dmarc"),
                "auth_results": auth_res.get("auth_results_raw"),
            },
            "sender_analysis": {
                "from_domain": sender_res.get("from_domain"),
                "display_name": sender_res.get("display_name"),
                "reply_to_domain": sender_res.get("reply_to_domain"),
                "return_path_domain": sender_res.get("return_path_domain"),
                "is_homograph": sender_res.get("is_homograph"),
            },
            "content_analysis": {
                "social_engineering_score": content_res.get("social_engineering_score"),
                "threat_level": content_res.get("threat_level"),
                "tactics": content_res.get("tactics"),
            },
            "url_analysis": analyzed_urls,
            "attachment_analysis": analyzed_atts,
            "iocs": iocs,
        }

        logger.info(
            f"Threat analysis completed for {msg_id}: Score={final_risk_score}, "
            f"Severity={severity}, Recommendation={recommendation}, Findings={len(all_findings)}"
        )
        return result
