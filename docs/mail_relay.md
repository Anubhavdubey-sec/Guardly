# Guardly Secure Mail Relay & Outbound Delivery Engine (Phase 4 / Module 5)

## Overview & Full Phase 4 Architecture

Guardly **Module 5** completes the end-to-end Phase 4 email pipeline by delivering clean messages in `READY_FOR_RELAY` status to the destination mail server via outbound SMTP.

```
SMTP Gateway Receiver (Module 1)
         ↓ (Port 2525)
Mail Queue & Email Parser (Module 2)
         ↓
Threat Analysis Engine (Module 3)
         ↓
Mail Policy & Enforcement Engine (Module 4)
         ↓ (Status: READY_FOR_RELAY)
Secure Mail Relay Engine (services/mail_relay.py)
 ├── Outbound Relay Queue Processor
 ├── Configurable Target SMTP Relay Host/Port
 ├── Outbound SMTP Client (STARTTLS / TLS / Auth)
 ├── State Machine Transition -> DELIVERED / FAILED
 └── Delivery Audit Log Telemetry
```

---

## Outbound Relay Configuration

The Mail Relay engine is configured via environment variables or Flask configuration:

```env
RELAY_ENABLED=true
RELAY_HOST=127.0.0.1
RELAY_PORT=2526
RELAY_USE_TLS=false
RELAY_USERNAME=
RELAY_PASSWORD=
RELAY_TIMEOUT=10
RELAY_MOCK_MODE=false
```

- **`RELAY_MOCK_MODE`**: When enabled, simulates successful SMTP delivery for lab testing without requiring an active remote SMTP server socket.

---

## State Machine Transition to `DELIVERED`

1. **Input State**: `EmailMessage.status = "READY_FOR_RELAY"`, `MailQueue.status = "READY_FOR_RELAY"`
2. **Execution**: `MailRelayEngine.relay_message(email_msg)` reads raw `.eml` bytes and connects to target SMTP relay host/port (`RELAY_HOST:RELAY_PORT`).
3. **Success Transition**:
   - `EmailMessage.status = "DELIVERED"`
   - `MailQueue.status = "DELIVERED"`
   - Creates `MailRelayLog` record with `smtp_code=250`
   - Logs `MailAuditLog` event (`action="DELIVERED"`)
4. **Failure Transition**:
   - `EmailMessage.status = "FAILED"`
   - `MailQueue.status = "FAILED"`
   - Creates `MailRelayLog` record with error details
   - Logs `MailAuditLog` event (`action="DELIVERED_FAILED"`)

---

## CLI & Service Commands

### Run Standalone Outbound Mail Relay Worker
```powershell
.venv\Scripts\python.exe -m flask run-mail-relay
```

### Run Full System Test Discovery (160 Tests)
```powershell
.venv\Scripts\python.exe -m unittest discover tests
```

---

## End-to-End LAB Pipeline Test

```powershell
# 1. Send clean email to Gateway (Port 2525)
# 2. Queue & Parser process raw .eml
# 3. Threat Engine calculates Risk Score = 10
# 4. Policy Engine evaluates ALLOW (0-29) -> Enforcement sets READY_FOR_RELAY
# 5. Mail Relay Engine connects to Destination SMTP (Port 2526)
# 6. Status updated to DELIVERED!
```
