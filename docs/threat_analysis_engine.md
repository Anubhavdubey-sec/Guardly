# Guardly Threat Analysis Engine (Phase 4 / Module 3)

## Architecture Overview

Guardly **Module 3** integrates the Module 1 SMTP Receiver and Module 2 Mail Queue & Email Parser into Guardly's core **Threat Analysis Engine** (`services/threat_analysis.py`).

```
SMTP Receiver (Module 1)
         ↓
Mail Queue & Email Parser (Module 2)
         ↓ (Status: READY_FOR_ANALYSIS)
Threat Analysis Engine (services/threat_analysis.py)
 ├── HeaderAnalyzer
 ├── AuthenticationAnalyzer
 ├── SenderAnalyzer
 ├── ContentAnalyzer
 ├── URLAnalyzer
 ├── AttachmentAnalyzer
 └── IOCAnalyzer
         ↓
Deterministic Risk Scoring & Verdict Decision (ALLOW / REVIEW / QUARANTINE)
         ↓
Persist to EmailMessage & EmailScan Tables
```

---

## Modular Security Analyzers

1. **HeaderAnalyzer**:
   - Analyzes `From`, `To`, `Reply-To`, `Return-Path`, `Message-ID`, `Date`, and `Received` routing chain.
   - Detects hop anomalies, Return-Path mismatch, missing headers, and malformed syntax.

2. **AuthenticationAnalyzer**:
   - Parses RFC 7601 `Authentication-Results` headers.
   - Evaluates SPF, DKIM, and DMARC verification status (`PASS`, `FAIL`, `SOFTFAIL`, `NEUTRAL`, `UNKNOWN`, `NOT_PRESENT`).

3. **SenderAnalyzer**:
   - Detects display-name brand impersonation (e.g. `Bank of America Support <alert@scam-bank.com>`).
   - Identifies Reply-To and Return-Path domain mismatches.
   - Evaluates IDN visual homograph lookalikes & Punycode domains (`xn--...`).
   - Assesses TLD risk profile.

4. **ContentAnalyzer**:
   - Normalizes text against zero-width characters, HTML entity encoding, and Unicode NFKC variants.
   - Reuses Guardly NLP Lure engine to identify credential harvesting, password reset requests, MFA/OTP lures, account suspension pressure, BEC, and invoice/tax scams.

5. **URLAnalyzer**:
   - Integrates Guardly's non-executing URL Intelligence Engine (`scanner/url_intelligence.py`).
   - Detects URL shorteners, Punycode, homographs, IP/Hex/Decimal URLs, high-entropy query payloads, and suspicious TLDs.
   - **Never makes automated HTTP outbound network calls**.

6. **AttachmentAnalyzer**:
   - Performs static analysis on attachment metadata.
   - Detects executable extensions (`.exe`, `.bat`, `.vbs`, `.ps1`), double extensions (`.pdf.exe`), and macro-capable formats.
   - Computes SHA-256 hash for every attachment.
   - Scans embedded URLs in PDFs (`scanner/pdf_scanner.py`) and image quishing QR codes (`scanner/qr_ocr_scanner.py`).

7. **IOCAnalyzer**:
   - Extracts and deduplicates IPv4, IPv6, Domains, URLs, Email Addresses, File Hashes, and Cryptocurrency wallet addresses across headers, body, and attachments.

---

## Deterministic Risk Scoring & Verdict Categories

Every score is explainable and calculated deterministically using weighted findings:

| Severity Level | Risk Score Range | Recommended Decision |
| :--- | :--- | :--- |
| **`LOW`** | `0 – 29` | **`ALLOW`** |
| **`MEDIUM`** | `30 – 59` | **`REVIEW`** |
| **`HIGH`** | `60 – 79` | **`QUARANTINE`** |
| **`CRITICAL`** | `80 – 100` | **`QUARANTINE`** |

---

## Structured Result Format

```json
{
    "message_id": "msg_20260808074512_x9y8z7",
    "risk_score": 85,
    "severity": "CRITICAL",
    "recommendation": "QUARANTINE",
    "findings": [
        "Return-Path domain (evil.net) mismatch with From domain (paypal-login-alert.top)",
        "SPF authentication status: FAIL",
        "DKIM signature validation FAILED",
        "Display Name impersonation detected: 'PayPal Support' claims brand 'paypal' but domain is 'paypal-login-alert.top'",
        "Content indicator detected: Credential / Password Request",
        "URL [http://192.168.1.1/login...]: Direct IP address used in URL hostname"
    ],
    "authentication": {
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
        "auth_results": "spf=fail dkim=fail dmarc=fail"
    },
    "sender_analysis": {
        "from_domain": "paypal-login-alert.top",
        "display_name": "PayPal Support",
        "reply_to_domain": "evil.net",
        "return_path_domain": "evil.net",
        "is_homograph": false
    },
    "content_analysis": {
        "social_engineering_score": 75,
        "threat_level": "High Risk",
        "tactics": ["Urgent Credential Request", "Account Suspension Threat"]
    },
    "url_analysis": [
        {
            "url": "http://192.168.1.1/login",
            "score": 60,
            "verdict": "High Risk",
            "findings": ["Direct IP address used in URL hostname"]
        }
    ],
    "attachment_analysis": [],
    "iocs": {
        "ip_addresses": ["192.168.1.1"],
        "domains": ["paypal-login-alert.top", "evil.net"],
        "urls": ["http://192.168.1.1/login"],
        "email_addresses": ["alert@paypal-login-alert.top", "target@company.com"],
        "hashes": [],
        "crypto_wallets": []
    }
}
```

---

## Security & Resource Controls

- **No Attachment Execution**: Files are analyzed purely through safe static inspection.
- **No Active Web Navigation**: URLs are inspected via static pattern parsing without making HTTP requests.
- **Path Traversal Defense**: Safe attachment storage filenames with SHA-256 prefixes.
- **Catastrophic Regex Defense**: Limited iteration bounds on URL & header evaluation loops.
- **Multilingual Unicode Normalization**: NFKC normalization & zero-width character stripping.
