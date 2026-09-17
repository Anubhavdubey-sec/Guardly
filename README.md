# Guardly · Enterprise Email Security & Threat Intelligence Platform

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![Security Audit](https://img.shields.io/badge/Security%20Audit-9.8%20%2F%2010-brightgreen.svg)](#-enterprise-security-architecture--hardening-score-9810)
[![Test Suite](https://img.shields.io/badge/Tests-168%20Passed-success.svg)](#-testing--quality-assurance)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Guardly** (formerly PhishGuard) is a production-grade, multi-stage cybersecurity platform designed for deep email threat inspection, indicator of compromise (IOC) extraction, RFC 822 hop timeline reconstruction, interactive threat graph correlation, automated policy enforcement, and SOC incident triage.

Guardly functions both as an **interactive SOC Analyst Web Application** and as an **automated Email Security Gateway (SEG) & Relay Pipeline** with post-delivery mailbox remediation for Google Workspace / Gmail.

---

## 📑 Table of Contents

- [Architectural Overview](#-architectural-overview)
- [Key Features & Capabilities](#-key-features--capabilities)
- [Enterprise Security Architecture (Score 9.8/10)](#-enterprise-security-architecture--hardening-score-9810)
- [Project Directory Structure](#-project-directory-structure)
- [Quick Start & Installation](#-quick-start--installation)
- [Configuration Reference (.env)](#-configuration-reference-env)
- [CLI Commands Reference](#-cli-commands-reference)
- [Live Integration Demo & Sample Traffic](#-live-integration-demo--sample-traffic)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [Key API Endpoints](#-key-api-endpoints)
- [Secure Packaging for Release](#-secure-packaging-for-release)
- [License](#-license)

---

## 🏛️ Architectural Overview

Guardly supports dual ingestion workflows: interactive manual upload via the SOC web console and live automated ingestion through a high-concurrency inbound SMTP receiver.

```
                          INGESTION CHANNELS
               ┌───────────────────────────────────────┐
               │ 1. SOC Web Console (.eml Upload)      │
               │ 2. SMTP Gateway Receiver (Port 2525)  │
               │ 3. Gmail API Post-Delivery Poller     │
               └──────────────────┬────────────────────┘
                                  │
                                  ▼
               ┌───────────────────────────────────────┐
               │    Mail Queue & RFC 5322 Parser       │
               │  - MIME normalization, body decoding  │
               │  - SHA-256 attachment hashing         │
               │  - Safe non-executing link extraction │
               └──────────────────┬────────────────────┘
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │               GUARDLY MULTI-LAYER THREAT ENGINE                   │
 │                                                                   │
 │  ├── RFC 822 Hop Timeline & Inter-Hop Delay Analysis              │
 │  ├── RFC 7601 Auth Analysis (SPF, DKIM, DMARC Alignment)          │
 │  ├── Display Name & Brand Spoofing / Homograph Detection          │
 │  ├── NLP Lure Detection (Urgency, MFA/OTP, BEC, Tax/Invoice)     │
 │  ├── Static Attachment Inspection (Macros, Double-Ext, Shells)    │
 │  ├── PDF Embedded Link & Script Scanner                           │
 │  ├── Quishing Detection (Image QR Code & OCR Lure Scanner)        │
 │  ├── URL Heuristics (Entropy, Suspicious TLDs, Punycode, IP-URLs) │
 │  └── Authoritative MaxMind GeoLite2 IP Geolocation & ASN Lookup   │
 └────────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
               ┌───────────────────────────────────────┐
               │   Deterministic Risk Scoring Engine   │
               │         Score: 0 - 100               │
               └──────────────────┬────────────────────┘
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       ▼                          ▼                          ▼
 0 ──────── 29              30 ──────── 64             65 ──────── 100
   [ ALLOW ]                  [ REVIEW ]          [ QUARANTINE / REJECT ]
       │                          │                          │
       ▼                          ▼                          ▼
Outbound Mail Relay     Held in SOC Analyst         Isolated in Secure Vault
 (Port 2526 / TLS)         Review Queue            (`quarantine/`) & Auto-Trash
```

---

## ✨ Key Features & Capabilities

### 1. Inbound SMTP Gateway & Async Mail Queue
- **Non-blocking SMTP Receiver**: Built on `aiosmtpd` in a dedicated background thread on port `2525`. Rejects malformed sender/recipient syntax (`550`) and oversized payloads (`552`) at envelope time.
- **Relational Mail Queue State Machine**: Tracks messages through `RECEIVED` ➔ `QUEUED` ➔ `PROCESSING` ➔ `PARSED` ➔ `READY_FOR_ANALYSIS` ➔ `READY_FOR_RELAY` / `QUARANTINED` / `REJECTED` / `REVIEW` with exponential retry backoff.
- **Atomic Mail Storage**: Incoming messages are stored atomically with UUID filenames inside `received_emails/` without relying on untrusted header strings.

### 2. Multi-Layer Threat Analysis Engine
- **Delivery Timeline & Routing Hop Analysis**: Reconstructs chronological relay progression from RFC 822 `Received:` headers. Computes hop-by-hop latency, flags clock anomalies, and identifies private/reserved relay nodes.
- **Email Authentication Verification**: Extracts and evaluates RFC 7601 `Authentication-Results` headers for SPF, DKIM, and DMARC passing, softfail, or alignment failures.
- **Brand Impersonation & Homograph Defense**: Detects display name deception (e.g. `PayPal Support <alert@evil.com>`), Return-Path vs. From discrepancies, and Punycode/IDN homoglyph spoofing.
- **NLP Lure & Social Engineering Detection**: Scans email plain text and normalized HTML for credential harvesting, password expiration alarms, MFA/OTP prompts, wire transfer requests, and BEC patterns.
- **Static Attachment & Quishing Scanner**: Computes SHA-256 hashes, flags dangerous extensions (`.exe`, `.bat`, `.ps1`, `.vbs`, double extensions), parses embedded URLs in PDFs via `pypdf`, and extracts QR codes & OCR lures from images.
- **URL Intelligence & Heuristics**: Calculates Shannon entropy on domain paths, parses IP-literal hostnames, shorteners, punycode strings, and high-risk TLDs without issuing live HTTP requests to untrusted targets.
- **Authoritative Local IP Geolocation**: Leverages offline **MaxMind GeoLite2** (`GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`) with memory caching for fast lookup of relay countries, cities, and autonomous systems.

### 3. Automated Mail Policy & Quarantine Management
- **Configurable Policy Thresholds**:
  - `0 – 29`: **ALLOW** ➔ Marked `READY_FOR_RELAY` for outbound delivery.
  - `30 – 64`: **REVIEW** ➔ Held in Analyst Review Queue.
  - `65 – 95`: **QUARANTINE** ➔ Moved to encrypted/isolated `quarantine/` vault and tracked in `mail_quarantine` table.
  - `96 – 100`: **REJECT** ➔ Blocked with rejection audit logs.
- **SOC Analyst Quarantine Workflows**: Analysts can inspect quarantined messages, analyze extracted indicators, and selectively release messages to relay with tenant-boundary checks.

### 4. Outbound Mail Relay (MTA)
- **RFC 5321 Delivery Engine**: Delivers approved emails to downstream corporate mail servers (Exchange, Postfix, Sendmail) over SMTP/STARTTLS on configurable ports (e.g. `2526`).
- **Lab Mock Mode**: Includes an integrated mock relay mode (`RELAY_MOCK_MODE=true`) for safe offline testing without an active outbound MTA.

### 5. Google Workspace / Gmail API Post-Delivery Scanner
- **Continuous Post-Delivery Remediation**: Connects to Google Workspace inboxes via official Gmail REST APIs (`users.messages.list`, `users.messages.get`, `users.messages.trash`) using Service Account credentials.
- **Automated Quarantine & Trashing**: Scans messages that bypassed perimeter defenses, evaluates threat risk, and automatically trashes high-risk phishing lures while copying raw bytes to the Guardly quarantine vault.

### 6. SOC Analyst Console, Threat Graph & Case Management
- **Interactive Threat Graph**: Powered by Cytoscape.js, visually mapping sender domains, relay hops, URLs, attachment hashes, and IOC nodes.
- **Case Management System**: Full incident triage portal to promote suspicious scans into investigation cases, assign analysts, track severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and record analyst notes.
- **Vector-Sharp PDF Reports**: Native binary PDF generation using ReportLab (`SimpleDocTemplate`) with risk meters, header breakdowns, forensic findings, and IOC lists.

---

## 🛡️ Enterprise Security Architecture & Hardening (Score 9.8/10)

Guardly follows NIST SP 800-53 and OWASP Application Security Verification Standard (ASVS) best practices:

| Category | Security Control Implemented |
| :--- | :--- |
| **Authentication & RBAC** | Role-Based Access Control (`admin`, `analyst`, `user`) with Werkzeug salted hashing, tenant isolation, session fixation defense (`session.clear()` on login), and prompt CLI onboarding. |
| **Password Policy** | Strict 12–128 character passphrase policy (`services/password_validator.py`), entropy verification, common credential blacklist, control character blocking, and live client-side strength meter (`static/js/password_strength.js`). |
| **CSRF Defense** | Session-bound cryptographic tokens validated via constant-time comparison (`secrets.compare_digest`) on all state-mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`). |
| **SSRF Firewall** | Python `ipaddress` validation (`services/ssrf.py`) blocking RFC 1918 private subnets, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), cloud metadata endpoints (`169.254.169.254`), and non-HTTP protocols. |
| **Session Hardening** | `HttpOnly=True`, `SameSite=Lax`, dynamically enforced `Secure` cookies in HTTPS, 2-hour sliding window lifetime (`PERMANENT_SESSION_LIFETIME = 7200`). |
| **Rate Limiting** | Flask-Limiter brute-force defenses (e.g. 5 attempts/minute on `/login`) with `429 Too Many Requests` responses. |
| **HTTP Headers** | Global security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, strict `Content-Security-Policy` (CSP), and `HSTS`. |
| **Upload Defense** | `secure_filename()` sanitization, mandatory `.eml` allow-list, randomized UUID storage, 10 MB payload ceiling (`MAX_CONTENT_LENGTH`), and path traversal prevention. |
| **Audit Logging** | Centralized audit telemetry (`SystemLog`, `MailAuditLog`) logging security-critical actions without recording raw passwords, tokens, or private keys. |

---

## 📂 Project Directory Structure

```
Phishing-Email-Detector/
├── app.py                      # Flask Application factory & CLI commands
├── config.py                   # Centralized application & security settings
├── requirements.txt            # Python dependencies
├── run_full_demo.py            # End-to-end multi-service integration demo
├── send_test_emails.py         # SMTP sample traffic generator
│
├── scanner/                    # Core Detection Engines
│   ├── email_parser.py         # Email header & MIME structure parser
│   ├── header_analyzer.py      # Hop routing, Return-Path & header verification
│   ├── nlp_analyzer.py         # Urgency, credential harvesting & lure NLP
│   ├── pdf_scanner.py          # PDF attachment & embedded link extractor
│   ├── phishing_detector.py    # Master heuristic scoring orchestrator
│   ├── qr_ocr_scanner.py       # Quishing QR code & OCR image analyzer
│   ├── timeline.py             # RFC 822 relay hop delivery timeline builder
│   ├── url_heuristics.py       # Link entropy & pattern heuristic rules
│   └── url_intelligence.py     # Safe non-executing URL analysis engine
│
├── services/                   # Business Logic & Pipeline Services
│   ├── audit.py                # Security audit event logging
│   ├── auth_results.py         # RFC 7601 SPF/DKIM/DMARC parser
│   ├── csrf.py                 # Cryptographic CSRF token validation
│   ├── email_parser.py         # RFC 5322 MIME & attachment extractor
│   ├── geolocation.py          # MaxMind GeoLite2 & IP geolocation service
│   ├── gmail_scanner.py        # Google Workspace REST API post-delivery scanner
│   ├── graph_builder.py        # Threat graph network topology generator
│   ├── mail_enforcement.py     # Policy enforcement & quarantine vault manager
│   ├── mail_policy.py          # Deterministic policy thresholds (ALLOW/REVIEW/QUARANTINE)
│   ├── mail_queue.py           # Async mail queue worker thread
│   ├── mail_relay.py           # Outbound SMTP relay delivery engine
│   ├── password_validator.py   # Passphrase policy & entropy evaluator
│   ├── pdf_report_generator.py # ReportLab binary PDF executive report engine
│   ├── playbook_engine.py      # Automated incident response playbooks
│   ├── smtp_receiver.py        # Inbound aiosmtpd SMTP server
│   ├── ssrf.py                 # SSRF firewall & private IP blocking
│   ├── threat_analysis.py      # Unified Phase 4 threat evaluation pipeline
│   ├── yara_generator.py       # Automated YARA rule generation from IOCs
│   └── threat_intelligence/    # Threat intel feed connectors (VT, AbuseIPDB, OTX, etc.)
│
├── models/                     # SQLAlchemy Relational Models
│   ├── email_message.py        # EmailMessage & EmailAttachment schemas
│   ├── investigation_case.py   # SOC incident investigation cases & notes
│   ├── policy.py               # MailPolicyConfig, MailQuarantine & MailAuditLog
│   ├── queue.py                # MailQueue relational job store
│   ├── relay.py                # MailRelayLog delivery records
│   ├── scan.py                 # EmailScan historical inspection logs
│   ├── system_log.py           # Audit events & security logs
│   └── user.py                 # User account, RBAC & tenant models
│
├── routes/                     # HTTP Route Blueprints
│   ├── admin.py                # Admin portal, user management & audit logs
│   ├── auth.py                 # Login, session management & password APIs
│   ├── cases.py                # Incident case management endpoints
│   ├── graph.py                # Cytoscape threat graph endpoints
│   └── scanner.py              # Email analysis, upload & report downloads
│
├── templates/                  # Jinja2 HTML5 Responsive Web Templates
├── static/                     # CSS, JS (password_strength.js), and assets
├── data/                       # Local GeoLite2-City & GeoLite2-ASN databases
├── tests/                      # 168 Unit & Security Test Suites
├── docs/                       # Architectural & module-specific documentation
└── scripts/                    # Release packaging & database maintenance utilities
```

---

## 🚀 Quick Start & Installation

### 1. Prerequisites
- **Python**: `3.10` or higher
- **Database**: SQLite (default for local development) or MySQL / PostgreSQL
- **OS**: Windows, macOS, or Linux

### 2. Environment Setup

```bash
# Clone the repository
cd Phishing-Email-Detector

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration Setup

Copy the example environment template and generate a cryptographically strong secret:

```bash
cp .env.example .env
```

Generate a production-grade 64-character secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste this string into your `.env` file for `SECRET_KEY`.

### 4. Database Initialization & Admin Setup

```bash
# Initialize database schema
python -m flask init-db

# Create an administrator account (prompts for username, email, and password)
python -m flask create-admin
```

### 5. Launch the Web Application

```bash
python app.py
```

The Guardly SOC portal will be accessible at: **`http://127.0.0.1:5000`**

Log in using the administrator credentials created in Step 4.

---

## ⚙️ Configuration Reference (.env)

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | *(Required in prod)* | Cryptographic key for session cookies and CSRF validation. |
| `DEBUG` | `false` | Enable Flask debug mode (`true` / `false`). |
| `DATABASE_URL` | `sqlite:///database/users.db` | SQLAlchemy connection URI (supports SQLite, MySQL, PostgreSQL). |
| `AUTO_CREATE_SCHEMA` | `true` | Automatically creates missing tables on application boot. |
| `WTF_CSRF_ENABLED` | `true` | Enforces CSRF validation across all modifying HTTP requests. |
| `RATELIMIT_ENABLED` | `true` | Enables brute-force request rate limiting on auth endpoints. |
| `SESSION_COOKIE_SECURE` | `false` (in dev) | Set to `true` when running over HTTPS. |
| `UPLOAD_FOLDER` | `uploads` | Directory for uploaded `.eml` files. |
| `MAX_CONTENT_LENGTH` | `10485760` (10 MB) | Maximum permitted file upload size. |
| **SMTP Gateway** | | |
| `SMTP_HOST` | `127.0.0.1` | Interface IP for the Inbound SMTP Gateway receiver. |
| `SMTP_PORT` | `2525` | Port for the Inbound SMTP Gateway receiver. |
| `MAIL_STORAGE_PATH` | `received_emails` | Directory for storing raw spooled `.eml` files. |
| `MAX_MESSAGE_SIZE` | `10485760` (10 MB) | Maximum accepted SMTP message size. |
| **Mail Relay Engine** | | |
| `RELAY_ENABLED` | `true` | Enable outbound mail relay processing. |
| `RELAY_HOST` | `127.0.0.1` | Downstream corporate MTA IP/hostname. |
| `RELAY_PORT` | `2526` | Downstream corporate MTA port. |
| `RELAY_USE_TLS` | `false` | Enable STARTTLS for outbound relay connections. |
| `RELAY_MOCK_MODE` | `true` | Simulates delivery in lab environments without a remote MTA. |
| **Policy Thresholds** | | |
| `POLICY_ALLOW_MAX` | `29` | Upper risk score bound for automatic delivery (`0 - 29`). |
| `POLICY_REVIEW_MIN` | `30` | Lower risk score bound for analyst review (`30 - 64`). |
| `POLICY_REVIEW_MAX` | `64` | Upper risk score bound for analyst review. |
| `POLICY_QUARANTINE_MIN` | `65` | Lower risk score bound for quarantine (`65 - 95`). |
| `POLICY_QUARANTINE_MAX` | `95` | Upper risk score bound for quarantine. |
| `POLICY_REJECT_MIN` | `96` | Lower risk score bound for outright rejection (`96 - 100`). |
| **Geolocation** | | |
| `GEOLOCATION_CITY_PATH`| `data/GeoLite2-City.mmdb`| Path to local MaxMind City database. |
| `GEOLOCATION_ASN_PATH` | `data/GeoLite2-ASN.mmdb` | Path to local MaxMind ASN database. |
| `GEOLOCATION_FALLBACK_ENABLED` | `true` | Falls back to online IP lookup if local `.mmdb` is absent. |
| **Gmail Post-Delivery**| | |
| `GMAIL_API_MOCK_MODE` | `true` | Safe mock mode for offline testing without Google Cloud keys. |
| `GMAIL_REMEDIATION_ACTION` | `TRASH` | Action taken on detected threats (`TRASH` or `QUARANTINE`). |
| `GMAIL_RISK_THRESHOLD`| `65` | Risk threshold triggering automated post-delivery remediation. |

---

## 💻 CLI Commands Reference

Guardly provides comprehensive Click-based CLI commands via the Flask runner:

```bash
# Database & User Management
python -m flask init-db                     # Initialize database schema & run migrations
python -m flask create-admin                 # Interactively create or promote an admin user
python -m flask reset-admin-password         # Safely reset an administrator password
python -m flask migrate-sqlite-data          # Migrate legacy SQLite database to MySQL

# Inbound Gateway & Pipeline Services
python -m flask run-smtp                     # Launch Inbound SMTP Gateway on 127.0.0.1:2525
python -m flask run-smtp --port 2525 --no-worker  # Run receiver without background queue worker
python -m flask run-mail-worker              # Run standalone mail parsing & threat worker
python -m flask run-mail-relay               # Run outbound mail relay queue worker

# Google Workspace / Gmail Post-Delivery Scanner
python -m flask scan-gmail-inbox --email user@company.com --max-results 20
```

---

## 🧪 Live Integration Demo & Sample Traffic

Guardly includes automated simulation tools to demonstrate the entire email pipeline end-to-end:

### 1. Run the Full Pipeline Integration Demo
Launches the Inbound Gateway (port 2525), Target Relay Server (port 2526), processing workers, sends 4 representative email types, and displays live telemetry:

```bash
python run_full_demo.py
```

Demo execution outcomes:
1. **Clean Project Update** ➔ Scored `0` ➔ **ALLOW** ➔ Relayed to downstream server (`250 OK`).
2. **Suspicious Urgency Lure** ➔ Scored `40` ➔ **REVIEW** ➔ Held in Analyst Review Queue.
3. **PayPal Phishing Impersonation** ➔ Scored `85` ➔ **QUARANTINE** ➔ Moved to `quarantine/` vault.
4. **Dangerous Malware Executable** ➔ Scored `100` ➔ **REJECT** ➔ Blocked with rejection audit record.

### 2. Send Custom Test Traffic
To generate test emails against a running Guardly SMTP instance:

```bash
python send_test_emails.py
```

---

## 🔬 Testing & Quality Assurance

Guardly includes a rigorous, production-grade automated unit and security test suite:

```bash
python -m unittest discover tests
```

### Test Suite Summary (168 Tests, 100% Passing)

- `test_security.py` & `test_password_validation.py`: Comprehensive OWASP security verification (CSRF token enforcement, session fixation clearing, SSRF subnet blocking, HTTP security headers, upload directory traversal, passphrase rules).
- `test_smtp_receiver.py`: Envelope address regex parsing, payload size caps, atomic spooling.
- `test_mail_queue_parser.py`: Queue state machine transitions, RFC 5322 parsing, retry limits.
- `test_threat_analysis.py`: Multi-analyzer evaluation, auth results parsing, deterministic scoring.
- `test_mail_policy_enforcement.py`: Boundary verification, vault isolation, tenant release controls.
- `test_mail_relay.py`: Outbound SMTP client, retry logic, mock delivery mode.
- `test_gmail_scanner.py`: Google Workspace API message fetching, threat evaluation, automated trashing.
- `test_geolocation.py`: MaxMind City/ASN parsing, memory caching, fallback provider isolation.
- `test_timeline.py` & `test_header_analysis.py`: RFC 822 hop timeline reconstruction, clock skew calculation.
- `test_case_management.py` & `test_threat_graph.py`: Incident case lifecycle, topology graph generation.
- `test_pdf_scanner.py` & `test_quishing_nlp.py`: PDF embedded link extraction, QR code / OCR quishing detection.

---

## 🔌 Key API Endpoints

### Public & Authentication
- `GET /` — Upload & Live Scanner interface
- `GET /login` / `POST /login` — Authenticated analyst/admin sign-in (rate-limited)
- `POST /logout` — Session teardown
- `POST /api/v1/password/validate` — Real-time password complexity & entropy validator

### Inspection & Forensic Operations
- `POST /upload` — Inspect uploaded `.eml` file
- `GET /scan/<id>` — Detailed forensic report (headers, hops, findings, IOCs)
- `GET /scan/<id>/report/pdf` — Download official ReportLab executive PDF report
- `GET /threat-graph` — Interactive Cytoscape threat graph view
- `GET /threat-graph/data/<id>` — JSON network topology (sender, hops, URLs, IOCs)

### Incident Case Management
- `GET /cases` — SOC incident case list and status filter
- `GET /cases/new?scan_id=<id>` — Promote scan into an active investigation
- `GET /cases/<id>` — Case details, threat indicators, audit history, analyst notes
- `POST /cases/<id>/notes` — Append forensic analysis notes

### Administration & Diagnostics
- `GET /admin/dashboard` — Security operations telemetry and system metrics
- `GET /admin/users` — User account management and role assignments
- `GET /admin/logs` — Security audit and authentication logs
- `GET /api/v1/geolocation/health` — MaxMind GeoLite2 database status and cache diagnostics

---

## 📦 Secure Packaging for Release

> [!CAUTION]
> **Do not manually zip the project folder.** Manual archiving risks leaking local secret files (`.env`), test databases (`users.db`), virtual environments (`.venv/`), and git history.

Use the verified packaging utility to produce a clean, production-ready release artifact:

```bash
# Cross-platform Python packager
python scripts/package_release.py

# Or via Bash
bash scripts/package_release.sh
```

The resulting verified archive is saved to `dist/Guardly.zip`.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
