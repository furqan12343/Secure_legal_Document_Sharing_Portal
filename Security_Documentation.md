# Security Documentation

## 1. Authentication

The system uses email/password login. Passwords are hashed with bcrypt in `backend/app/core/security.py`. Login returns a JWT access token with expiry.

## 2. Authorization

There are two layers:

1. RBAC: role checks at endpoint level.
2. ACL: document-level permissions in `DocumentAccess`.

Roles:

- `LAWYER`: creates cases, uploads, manages, shares, approves requests.
- `CLIENT`: uploads/views case documents.
- `ASSISTANT`: requests access and views/downloads approved documents.
- `ADMIN`: manages users and views logs, but cannot view legal documents.

## 3. Encryption

Files are encrypted using AES-256-GCM in `EncryptionService`.

The key is loaded from:

```text
FILE_MASTER_KEY_BASE64
```

The system does not store plaintext documents in the database.

## 4. Upload security

Before storage, uploaded files go through:

- filename sanitization
- extension validation
- MIME type sanity check
- size validation
- static malware scan
- AES encryption

## 5. Malware scanning

The prototype scanner checks for risky indicators such as:

- `MZ` executable header
- `powershell`
- `cmd.exe`
- `<script`
- `eval(`
- `base64_decode`
- `/bin/sh`

This is a prototype scanner. A real production version should use antivirus, sandboxing, and/or a trained ML model.

## 6. API security

Implemented:

- JWT bearer authentication
- role checks
- server-side Pydantic validation
- basic login rate limiting
- secure headers
- generic login error messages
- no hardcoded secrets

## 7. Secure headers

The middleware adds:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- `Cache-Control: no-store`
- `Content-Security-Policy`

Downloads also send `Content-Disposition: attachment`.

## 8. Audit logging

The system logs:

- user registration
- login success/failure
- case creation
- document upload
- document view/download
- failed document view/download
- permission requested/approved/rejected
- document sharing
- admin user actions

Logs use `previous_hash` and `entry_hash` to create a basic tamper-evident chain.

## 9. Session management

JWT tokens include:

- user ID
- role
- issued-at time
- expiry time

Prototype logout means the browser deletes the token. Production should use refresh tokens and token revocation.

## 10. Cloud security note

This project is local by default. In cloud deployment:

- use HTTPS only
- store secrets in environment variables or secret manager
- restrict database access
- use IAM roles
- do not commit `.env`
- use encrypted object storage for files

## 11. Limitations

- Static malware scanning is not a full antivirus.
- SQLite is for demo only.
- In-memory rate limiting resets on server restart.
- Local development does not enforce real HTTPS.
