# Guardly Gmail Workspace API Post-Delivery Scanner (Phase 5)

## Overview & Architecture

Guardly **Phase 5** introduces an automated **Post-Delivery Threat Scanner & Remediation Engine** for Google Workspace / Gmail inboxes using the official Google Gmail REST API with Domain-Wide Delegation / OAuth 2.0.

```
Google Workspace User Inbox (user@company.com)
            ↓ (Gmail REST API: users.messages.list)
1. Guardly Gmail Post-Delivery Scanner (services/gmail_scanner.py)
            ↓ (Fetches raw message RFC 5322 bytes via users.messages.get)
2. Guardly Email Parser (services/email_parser.py)
            ↓
3. Guardly Threat Analysis Engine (services/threat_analysis.py)
            ↓ (Calculates Threat Risk Score 0 - 100)
4. Post-Delivery Policy & Automated Remediation
    ├── Risk Score >= 65 (HIGH / CRITICAL PHISHING)
    │     ├── 🗑️ Calls Gmail API: users.messages.trash()
    │     ├── 📁 Moves email out of Inbox into Gmail Trash / 'Guardly-Quarantine'
    │     ├── 🔒 Copies raw email to Guardly quarantine/ vault
    │     └── 📝 Logs Audit Event (POST_DELIVERY_QUARANTINED / POST_DELIVERY_TRASHED)
    └── Risk Score < 65 (CLEAN)
          └── Records GmailPostDeliveryScan DB telemetry (action_taken="ALLOWED")
```

---

## Configuration Variables

```env
# Gmail Post-Delivery Scanner Settings
GMAIL_SERVICE_ACCOUNT_FILE=/path/to/google_service_account.json
GMAIL_DELEGATED_USER=admin@company.com
GMAIL_API_MOCK_MODE=true
GMAIL_REMEDIATION_ACTION=TRASH
GMAIL_RISK_THRESHOLD=65
```

- **`GMAIL_API_MOCK_MODE`**: Defaults to `true` for offline testing without a live Google Cloud key. Set to `false` when running against a live Google Workspace tenant.

---

## CLI Commands

### Scan Specific Google Workspace Inbox
```powershell
.venv\Scripts\python.exe -m flask scan-gmail-inbox --email user@company.com --max-results 10
```

### Run Phase 5 Test Suite (165 Tests)
```powershell
.venv\Scripts\python.exe -m unittest discover tests
```
