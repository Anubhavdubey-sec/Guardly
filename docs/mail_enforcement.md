# Guardly Mail Policy & Enforcement Engine (Phase 4 / Module 4)

## Overview & Architecture

Guardly **Module 4** implements the Mail Policy Evaluation & Enforcement layer that acts on Threat Analysis Engine (Module 3) findings to determine whether an email is allowed to proceed toward mail relay or must be held for review, quarantined, or rejected.

```
SMTP Receiver (Module 1)
         ↓
Mail Queue & Email Parser (Module 2)
         ↓
Threat Analysis Engine (Module 3)
         ↓ (Risk Score & Findings)
Policy Engine (services/mail_policy.py)
         ↓ (Decision: ALLOW / REVIEW / QUARANTINE / REJECT)
Mail Enforcement & Vault Manager (services/mail_enforcement.py)
 ├── ALLOW       -> State: READY_FOR_RELAY
 ├── REVIEW      -> State: REVIEW (Stored in Review Queue)
 ├── QUARANTINE  -> State: QUARANTINED (Stored in quarantine/ vault + mail_quarantine DB record)
 └── REJECT      -> State: REJECTED (Recorded rejection reason)
```

> [!IMPORTANT]
> **LOCAL / LAB MODE ENFORCEMENT**
> In LAB Mode, Guardly does NOT send real outbound SMTP rejections, modify production DNS/MX records, or connect to Gmail/Google Workspace. Enforcement decisions mark message state machine records and manage isolated vault files safely.

---

## Default Policy Thresholds (Inclusive Boundaries)

The Policy Engine maps deterministic risk scores (0–100) to enforcement decisions using the following default inclusive boundaries:

| Risk Score Range | Policy Decision | Next State Machine Transition | Automated Delivery Status |
| :---: | :---: | :---: | :---: |
| **`0 – 29`** | **`ALLOW`** | `READY_FOR_RELAY` | Allowed for future relay |
| **`30 – 64`** | **`REVIEW`** | `REVIEW` | Held in Analyst Review Queue (**NOT DELIVERED**) |
| **`65 – 95`** | **`QUARANTINE`** | `QUARANTINED` | Moved to `quarantine/` Vault (**NOT DELIVERED**) |
| **`96 – 100`** | **`REJECT`** | `REJECTED` | Mark Rejected with reason (**NOT DELIVERED**) |

### Boundary Verification Examples:
- `0`, `5`, `25`, `29` → `ALLOW` (`READY_FOR_RELAY`)
- `30`, `40`, `64` → `REVIEW` (`REVIEW`)
- `65`, `70`, `90`, `95` → `QUARANTINE` (`QUARANTINED`)
- `96`, `99`, `100` → `REJECT` (`REJECTED`)

---

## Configurable Thresholds & Validation

Policy thresholds are dynamically configurable via environment variables:

```env
POLICY_ALLOW_MAX=29
POLICY_REVIEW_MIN=30
POLICY_REVIEW_MAX=64
POLICY_QUARANTINE_MIN=65
POLICY_QUARANTINE_MAX=95
POLICY_REJECT_MIN=96
```

### Validation Rules:
`PolicyConfig` enforces:
1. `0 <= ALLOW_MAX < REVIEW_MIN <= REVIEW_MAX < QUARANTINE_MIN <= QUARANTINE_MAX < REJECT_MIN <= 100`
2. Gap-free contiguous sequence: `REVIEW_MIN == ALLOW_MAX + 1`, `QUARANTINE_MIN == REVIEW_MAX + 1`, `REJECT_MIN == QUARANTINE_MAX + 1`.
3. If an invalid threshold configuration is detected, `PolicyConfig` raises a `ValueError` to fail safely into `REVIEW` state rather than risking silent misdelivery.

---

## Message State Machine

```
RECEIVED  ──>  QUEUED  ──>  PROCESSING  ──>  ANALYZED  ──┬──>  ALLOW  ──>  READY_FOR_RELAY  ──>  DELIVERED
                                                          ├──>  REVIEW (Requires Admin Release)
                                                          ├──>  QUARANTINED (Requires Admin Release)
                                                          └──>  REJECTED
```

- **`QUARANTINED -> READY_FOR_RELAY`**: Can ONLY occur via explicit authorized administrator invocation of `release_message(quarantine_id, released_by_user_id, user_tenant_id)`.
- **`REVIEW -> READY_FOR_RELAY`**: Can ONLY occur via explicit authorized administrator invocation of `release_review_message(message_id, released_by_user_id, user_tenant_id)`.

---

## Isolated Quarantine Storage (`quarantine/`)

Quarantined messages are stored safely outside the standard mail processing tree in `quarantine/<quarantine_id>.eml`.

### Quarantine ID Format:
`QUAR-YYYYMMDD-xxxxxxxx` (e.g. `QUAR-20260808-430f3681`)

### `mail_quarantine` Database Fields:
- `id`, `message_id`, `tenant_id`, `quarantine_id`, `original_sender`, `recipient`, `subject`, `reason`, `risk_score`, `severity`, `raw_message_path`, `quarantine_file_path`, `status`, `created_at`, `released_at`, `released_by`.

---

## Multi-Tenant Security & RBAC Isolation

Every policy decision, quarantine record, and audit log contains a mandatory `tenant_id` column.
- Queries enforce strict tenant scoping (`WHERE tenant_id = :user_tenant_id`).
- Tenant A administrators cannot view, release, or tamper with Tenant B quarantined emails.

---

## Failure Safety & Audit Logging

- **Analysis Failure**: If threat analysis fails or raises an exception, the policy engine defaults to **`REVIEW`** (never `ALLOW`).
- **Audit Log Telemetry**: Every decision (`ALLOW`, `REVIEW`, `QUARANTINE`, `REJECT`, `RELEASE`, `FAILED`) is logged to the `mail_audit_logs` table with timestamps, actor IDs, risk scores, and decision details.

---

## CLI & Testing Commands

### Execute Policy & Enforcement Tests
```powershell
.venv\Scripts\python.exe -m unittest tests/test_mail_policy_enforcement.py
```

### Run Full System Test Discovery (156 Tests)
```powershell
.venv\Scripts\python.exe -m unittest discover tests
```
