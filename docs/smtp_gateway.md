# Guardly SMTP Receiver Foundation (Phase 4 / Module 1)

## Architecture Overview

Guardly's **SMTP Receiver Foundation** provides a standalone, non-blocking SMTP server endpoint capable of receiving raw RFC 5322 email messages and storing them securely on disk as `.eml` files.

```
SMTP Client / Mailer
         ↓ (Port 2525)
Guardly SMTP Receiver (aiosmtpd / asyncio thread)
         ↓
Security Checks (Address Regex, Size Limit, Path Sanitization)
         ↓
Mail Storage Engine (mail/storage.py)
         ↓ (Atomic Write)
.eml File System Store (received_emails/YYYYMMDD_<uuid>.eml)
         ↓
Future Threat Analysis Pipeline
```

---

## Configuration

All SMTP Receiver parameters are fully configurable via environment variables (`.env`) or application config (`config.py`). Production settings are never hardcoded.

| Parameter | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **SMTP Host** | `SMTP_HOST` | `127.0.0.1` | Network interface to bind the SMTP listener. |
| **SMTP Port** | `SMTP_PORT` | `2525` | Development port for receiving SMTP test traffic. |
| **Storage Path** | `MAIL_STORAGE_PATH` | `received_emails` | Relative or absolute directory for `.eml` storage. |
| **Max Message Size** | `MAX_MESSAGE_SIZE` | `10485760` (10 MB) | Maximum accepted email payload size in bytes. |

---

## Security Features

1. **Envelope Address Syntax Validation**:
   - Rejects malformed `MAIL FROM` addresses with `550 5.1.7 Invalid sender address syntax`.
   - Rejects malformed `RCPT TO` addresses with `550 5.1.1 Invalid recipient address syntax`.
2. **Fixed Message Size Limit**:
   - Enforces `MAX_MESSAGE_SIZE`. Oversized payloads are immediately rejected with `552 5.3.4 Message size exceeds fixed limit`.
3. **Path Traversal Defense**:
   - Filenames are generated using a non-predictable UUID (`YYYYMMDD_<uuid>.eml`).
   - Sender and recipient inputs are **never** used in file paths.
   - Canonical path resolution (`os.path.abspath`) verifies all file operations stay within `MAIL_STORAGE_PATH`.
4. **Non-Blocking Operation**:
   - The SMTP receiver runs asynchronously in a dedicated thread (`aiosmtpd`), ensuring zero impact or thread blocking on the Flask web application.
5. **Redacted Logging**:
   - Logs metadata (sender, recipient count, byte size, file location) without logging passwords, sensitive headers, or email bodies.

---

## Local Testing & Management

### Starting the SMTP Receiver via Flask CLI

```powershell
# In a dedicated terminal window:
.venv\Scripts\python.exe -m flask run-smtp --host 127.0.0.1 --port 2525
```

### Sending a Test Email via Python `smtplib`

```powershell
.venv\Scripts\python.exe -c "import smtplib; client = smtplib.SMTP('127.0.0.1', 2525); client.sendmail('analyst@company.com', ['test@guardly.local'], 'From: analyst@company.com\r\nTo: test@guardly.local\r\nSubject: DFIR Test Message\r\n\r\nThis is a raw SMTP test email.'); client.quit(); print('Email sent successfully!')"
```

### Verifying Received `.eml` Files

```powershell
# List stored .eml messages
Get-ChildItem -Path .\received_emails\*.eml

# Read the contents of the latest received message
Get-Content (Get-ChildItem -Path .\received_emails\*.eml | Sort-CreationTime -Descending | Select-Object -First 1).FullName
```

---

## Limitations (Phase 4 / Module 1 Scope)

- Does **not** alter public MX/DNS records.
- Does **not** perform email forwarding or outbound relay.
- Does **not** integrate with live Google Workspace / Microsoft 365 OAuth APIs yet (reserved for subsequent modules).
