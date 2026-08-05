# Guardly · Enterprise Email Security & Threat Intelligence Platform

Guardly is a high-performance, portfolio-grade Flask cybersecurity application designed for email threat inspection, link verification, indicator of compromise (IOC) extraction, and automated SOC report generation.

---

## 🛡️ Implemented Security Architecture & Protections

Guardly implements production-grade security controls following OWASP Web Security Guidelines and NIST SP 800-53 standards:

### 1. Environment & Secret Management
- **Centralized Secure Config**: Environment variables loaded via `dotenv` with standardized key names (`SECRET_KEY`, `AUTO_CREATE_SCHEMA`, `DATABASE_URL`).
- **Cryptographic Secret Storage**: Production environments generate 256-bit secrets (`secrets.token_hex(32)`).
- **Git Hardening**: `.env`, database artifacts, temporary uploads, and bytecode are ignored via `.gitignore`.

### 2. Comprehensive CSRF Protection
- **Session-Bound Tokens**: Native CSRF token generation (`services/csrf.py`) using constant-time comparison (`secrets.compare_digest`).
- **Form & Header Verification**: Enforces CSRF tokens across all `POST`, `PUT`, `PATCH`, and `DELETE` requests (`<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`).
- **Testing Mode Isolation**: CSRF verification can be selectively bypassed during unit testing (`WTF_CSRF_ENABLED = False`).

### 3. Enterprise SSRF & Private IP Protection
- **`ipaddress` Module Firewall**: Direct IP and DNS hostname resolutions are validated using Python's `ipaddress` module (`services/ssrf.py`).
- **Subnet & Range Restrictions**: Automatically blocks requests to RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), cloud metadata endpoints (`169.254.169.254`), and unroutable ranges (`0.0.0.0/8`).
- **Protocol Restriction**: Accepts strictly `http` and `https` schemes; explicitly rejects `file://`, `ftp://`, `gopher://`, `dict://`, `ldap://`, etc.
- **Safe Redirect Validation**: Step-by-step redirect validation prevents SSRF attacks through HTTP location redirects.

### 4. Vector-Sharp ReportLab PDF Generation
- **Native Binary PDF Engine**: Replaces raw text pseudo-PDFs with ReportLab `SimpleDocTemplate` vector PDF generation (`services/report_generator.py`).
- **Structured Executive Reports**: Generates formatted threat summaries, risk score meters, findings tables, extracted IOC lists, and header metadata.

### 5. Production Error Handling & Sanitized Logging
- **Safe Error Pages**: Custom handlers for `400`, `403`, `404`, `413`, and `500` return sanitized HTML/JSON responses without exposing internal Python stack traces.
- **Audit Event Logging**: Internal application events log security activities without storing sensitive passwords, secret keys, or private tokens.

### 6. Email Delivery Timeline Analysis
- **RFC 822 Header Path Reconstruction**: Reconstructs the exact chronological mail flow (`scanner/timeline.py`) from initial sender relay to recipient inbox by parsing RFC 822 `Received:` headers.
- **Inter-Hop Delay Analysis**: Computes delay intervals between consecutive relay hops, flagging timestamp anomalies, out-of-order headers, and clock skew.
- **Native IP & Relay Classification**: Uses Python's native `ipaddress` module to classify relay IPs as Public, Private, Loopback, Link-Local, Reserved, or IPv6.
- **Risk Observations**: Identifies private IP relays, duplicate relays, IPv6 usage, and missing timestamp fields as neutral DFIR observations.
- **Offline Architecture & Limitations**: Operates 100% locally with zero external API calls. Geographic context utilizes local IP lookups (`services/public_lookup.py`), displaying `"Location Unavailable"` when unresolvable locally. Missing or malformed headers default gracefully to `"Unknown"` without raising UI exceptions.

---

## 🚀 Quick Start & Deployment

### 1. Environment Setup

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configuration

Copy the configuration template:

```bash
cp .env.example .env
```

Generate a strong secret key for `.env`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Launching the Application

```bash
python app.py
```

---

## 🧪 Running Automated Tests

Run the complete automated unit and security test suite:

```bash
python -m unittest discover tests
```

---

## 📦 Packaging for Distribution

> [!CAUTION]
> **Do NOT manually zip or archive the project directory.** Manually zipping the project folder may accidentally expose sensitive local credentials (`.env`), virtual environment binaries (`.venv/`), local database files, or internal git metadata (`.git/`).

To generate a clean, secure, production-ready distribution archive containing only committed git files:

```bash
# Using Python (Cross-platform Windows / Linux / macOS)
python scripts/package_release.py

# Or using Bash
bash scripts/package_release.sh
```

The output package will be created at `dist/Guardly.zip` and verified against forbidden file inclusion rules before completion.
