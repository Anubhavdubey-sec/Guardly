# Guardly Authentication Upgrade Architecture & Documentation

## Overview

Guardly supports three multi-factor authentication methods for staff sign-in:
1. **Google Sign-In** (Sign in with Google via Firebase Authentication)
2. **Phone Number + SMS OTP** (Sign in with Phone via Firebase Phone Authentication)
3. **Corporate Username / Email + Password** (Preserved legacy staff login)

```
                              LOGIN SELECTION
                                     │
      ┌──────────────────────────────┼──────────────────────────────┐
      ▼                              ▼                              ▼
Google Sign-In                Phone Number OTP             Username / Password
(Firebase Auth)               (Firebase Phone)             (Guardly Native)
      │                              │                              │
Firebase ID Token              Firebase ID Token              Argon2/Bcrypt Hash
      └──────────────┬───────────────┘                              │
                     ▼                                              │
              POST /auth/firebase                                   │
                     │                                              │
           1. Token Verification                                    │
           2. Extract Verified Claims                               │
           3. Account Linking                                       │
           4. Guardly RBAC Evaluation                               │
                     │                                              │
                     └──────────────────────┬───────────────────────┘
                                            ▼
                                  Guardly Staff Session
                                            ↓
                                 Staff Analyst Dashboard
```

---

## Key Principles & Security Architecture

### 1. Identity Verification vs. Guardly RBAC
- **Firebase Authentication** handles identity ("Who is this user?").
- **Guardly Database & RBAC** handles authorization ("What is this user allowed to access?").
- **Non-Privileged Default Role**: Brand-new Firebase-authenticated users receive `role=User.ROLE_USER` by default. Firebase sign-in only proves identity; staff access (`analyst` / `admin`) requires explicit promotion by a Guardly Administrator.
- Client-supplied `tenant_id`, `role`, or `permissions` are **NEVER trusted**. Roles and tenant boundaries are strictly assigned by Guardly server database logic.

### 2. Resolved Security Finding (CWE-269 / OWASP A01:2021)
- **Issue**: Previously, new Firebase sign-ups automatically received `role=User.ROLE_ANALYST`, allowing external Google/Phone users to bypass admin approval and immediately access staff dashboards.
- **Remediation**: `services/firebase_auth.py` sets `role=User.ROLE_USER` on new user creation. Attempts by `ROLE_USER` accounts to authenticate via `/auth/firebase` return `403 Forbidden` until promoted by an Administrator via Guardly User Management.

### 3. Account Linking
When a user authenticates via Google or Phone OTP:
- If a Guardly user exists with matching verified `email` or `phone_number`, the Firebase `uid` is linked to the existing user record without creating duplicate accounts.
- Password hashes and existing staff roles (`admin` / `analyst`) are strictly preserved.

### 3. Backend Endpoint: `POST /auth/firebase`
Request Payload:
```json
{
  "id_token": "verified_firebase_id_token_string"
}
```

Response:
```json
{
  "success": true,
  "redirect_url": "/dashboard",
  "user": {
    "id": 1,
    "username": "analyst_user",
    "email": "analyst@guardly.sec",
    "role": "analyst",
    "tenant_id": "default",
    "auth_provider": "google"
  }
}
```

---

## Environment Configuration

```env
FIREBASE_PROJECT_ID=your-firebase-project-id
FIREBASE_SERVICE_ACCOUNT_KEY=/path/to/firebase-service-account.json
FIREBASE_TEST_MODE=true
```

- **`FIREBASE_TEST_MODE`**: Set to `true` during local development and automated CI testing to allow mock token verification without requiring live Google Cloud API calls.

---

## Testing Commands

### Run Authentication Test Suite
```powershell
.venv\Scripts\python.exe -m unittest tests/test_firebase_auth.py
```

### Run Full System Test Suite (177 Tests)
```powershell
.venv\Scripts\python.exe -m unittest discover tests
```
