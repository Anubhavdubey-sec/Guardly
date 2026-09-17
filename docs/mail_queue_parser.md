# Guardly Mail Queue & Email Parser (Phase 4 / Module 2)

## Overview & Architecture

Guardly **Module 2** builds directly on top of the Module 1 SMTP Receiver, implementing a reliable **Async Mail Queue** and **RFC 5322 Email Parser**.

```
SMTP Client
    ↓ (Port 2525)
Guardly SMTP Receiver (services/smtp_receiver.py)
    ↓
Raw .eml Storage (mail/storage.py -> received_emails/YYYYMMDD_<uuid>.eml)
    ↓
Mail Queue (models/queue.py -> mail_queue DB table)
    ↓
Queue Processing Worker (services/mail_queue.py -> MailQueueWorkerThread)
    ↓
Email Parser (services/email_parser.py)
    ↓ (Extract Headers, Plain/HTML Bodies, Non-Executing URLs, SHA-256 Attachments)
Structured Email Object (models/email_message.py -> email_messages & email_attachments DB tables)
    ↓
Status = READY_FOR_ANALYSIS
```

---

## Mail Queue State Machine

Each received raw message is tracked in the `mail_queue` relational database table:

```
RECEIVED  ──>  QUEUED  ──>  PROCESSING  ──>  PARSED  ──>  READY_FOR_ANALYSIS
                 ▲              │
                 └─ (Retry < 3) ┴──────────>  FAILED (Retry >= 3)
```

| Queue Status | Description |
| :--- | :--- |
| **`RECEIVED`** | Message captured by SMTP receiver and stored on disk. |
| **`QUEUED`** | Job enqueued and ready for worker consumption. |
| **`PROCESSING`** | Worker actively parsing RFC email headers, bodies, and attachments. |
| **`PARSED`** | Parsing complete, metadata extracted. |
| **`READY_FOR_ANALYSIS`** | Structured Email Object & Attachments saved in DB, ready for Threat Engine. |
| **`FAILED`** | Processing failed permanently after 3 retry attempts. |

---

## Email Parser Capabilities

1. **RFC Header Parsing**:
   - Parses `From`, `To`, `CC`, `BCC`, `Reply-To`, `Subject`, `Date`, `Message-ID`, `Return-Path`, `Received` (hop trace), and `Authentication-Results`.
   - Decodes RFC 2047 encoded header words (`=?utf-8?...`).

2. **Body Extraction**:
   - Decodes plain text (`text/plain`) and HTML (`text/html`) body parts safely.

3. **URL Extraction (Non-Executing)**:
   - Extracts HTTP/HTTPS links from plain text bodies and HTML attributes (`href`, `src`).
   - Deduplicates URLs while preserving discovery order.
   - **Does NOT make HTTP outbound requests or execute links**.

4. **Attachment Processing & Security Controls**:
   - Calculates **SHA-256 hash** for every attachment.
   - Saves attachment files to `extracted_attachments/` using non-executable storage filenames (`<sha256>_<sanitized_filename>`).
   - **Path Traversal Defense**: Strips path indicators (`../`, `..\`, `/`, `\`), null bytes, and non-printable control characters from filenames.
   - Enforces Maximum Attachment Size (`25 MB`) and Maximum Attachment Count (`20 attachments`).
   - **Does NOT execute attachments or open suspicious files**.

---

## Database Tables

Using Guardly's unified MySQL/SQLite database architecture:

1. **`mail_queue`**: Tracks job states, message IDs, timestamps, retries, and errors.
2. **`email_messages`**: Stores structured parsed emails, text/html bodies, URL JSON arrays, and header JSON dicts.
3. **`email_attachments`**: Stores attachment metadata, SHA-256 hashes, size in bytes, MIME types, and safe storage paths.

---

## CLI & Service Management Commands

### Start SMTP Receiver + Queue Worker
```powershell
.venv\Scripts\python.exe -m flask run-smtp --host 127.0.0.1 --port 2525 --with-worker
```

### Start Standalone Mail Worker Only
```powershell
.venv\Scripts\python.exe -m flask run-mail-worker
```

---

## Manual Verification & Testing

Send a test email with an attachment over SMTP:

```powershell
.venv\Scripts\python.exe -c "
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['Subject'] = 'Phase 4 Module 2 Verification'
msg['From'] = 'sender@domain.com'
msg['To'] = 'victim@company.com'
msg.set_content('Hello! Visit https://example.com/verify to test URL extraction.')
msg.add_attachment(b'%PDF-1.4 Fake PDF Content', maintype='application', subtype='pdf', filename='sample.pdf')

with smtplib.SMTP('127.0.0.1', 2525) as s:
    s.send_message(msg)
print('✅ Test email sent to Queue!')
"
```

Verify processed message in DB:
```powershell
.venv\Scripts\python.exe -c "
from app import app
from models.email_message import EmailMessage
with app.app_context():
    msg = EmailMessage.query.order_by(EmailMessage.id.desc()).first()
    if msg:
        print('Status:', msg.status)
        print('Subject:', msg.subject)
        print('URLs:', msg.urls_list)
        print('Attachments:', msg.attachments_list)
"
```
