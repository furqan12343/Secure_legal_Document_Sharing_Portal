# Secure Legal Document Exchange Portal

A secure web-based document exchange system designed for legal workflows between **Lawyers, Clients, Assistants, and Admins**.  
The project focuses on secure software design, secure implementation, role-based access control, encrypted document storage, malware scanning, audit logging, and security testing.

This project was developed as part of **Secure Software Design and Development — Assignment 3**, based on the secure UML design, threat modeling, and security requirements created in Assignment 2.

---

## Project Overview

The Secure Legal Document Exchange Portal allows users to upload, share, request, and manage legal documents while enforcing strict security controls.

The system supports four main roles:

- **Lawyer** — manages legal documents, shares files, approves/rejects access requests.
- **Client** — uploads case-related documents and accesses permitted documents.
- **Assistant** — requests access and views/downloads only approved documents.
- **Admin** — manages users and audit logs but cannot access legal documents.

A key security goal of this project is to ensure that sensitive legal files are protected against unauthorized access, insecure storage, malware uploads, weak authentication, and broken access control.

---

## Key Features

### Authentication and Authorization

- Secure login using JWT-based authentication.
- Passwords are hashed using bcrypt before storage.
- Role-Based Access Control for Lawyer, Client, Assistant, and Admin.
- Admin self-registration is blocked to prevent privilege escalation.
- Login rate limiting is applied to reduce brute-force attacks.

### Secure Document Handling

- Users can upload legal documents based on role permissions.
- Uploaded files are validated before processing.
- Files are scanned using a static malware scanning service.
- Safe files are encrypted before storage.
- File metadata is stored in the database.
- Documents can only be accessed through proper authorization checks.

### Document Permissions

The system uses document-level permissions:

- `VIEW` — user can view document metadata.
- `DOWNLOAD` — user can download the document.
- `MANAGE` — user can download and re-share/re-grant access.

This prevents users from accessing documents only because they are logged in. Every document request is checked against permissions.

### Sharing and Permission Workflow

- Lawyers can share documents with clients and assistants.
- Assistants can request access to restricted documents.
- Lawyers can approve or reject permission requests.
- Approved access creates document permission records.
- Rejected requests do not grant access.

### Admin Separation of Duties

Admins can:

- Create and manage users.
- View audit integrity reports.
- Manage system-level controls.

Admins cannot:

- View legal documents.
- Download legal documents.
- Receive shared legal document access.

This supports separation of duties and protects document confidentiality.

---

## Security Controls Implemented

### Password Security

Passwords are not stored in plaintext.  
The backend hashes passwords using bcrypt and stores only the password hash in the database.

### File Encryption

Uploaded documents are encrypted at rest using AES-based encryption.  
The encryption key is loaded from environment variables and is not hardcoded in the source code.

### Malware Scanning

Before files are stored, the system performs static malware scanning.

The scanner checks for:

- Dangerous file extensions.
- Suspicious script patterns.
- PowerShell and command execution indicators.
- PE/executable indicators.
- Packed or obfuscated file indicators.
- YARA-style static rule patterns.
- Suspicious API/import strings.

Unsafe files are rejected before encryption and storage.

### Input Validation

Server-side validation is applied using Pydantic schemas.  
Inputs such as email, password, role, document IDs, and sharing requests are validated before further processing.

### SQL Injection Protection

The project uses SQLAlchemy ORM instead of raw SQL string concatenation.  
This helps ensure that user input is treated as data, not executable SQL.

### XSS Protection

Unsafe frontend rendering was avoided by using safe DOM methods such as:

- `textContent`
- `createTextNode`
- `replaceChildren`

This reduces the risk of stored or reflected XSS.

### Secure Headers

The backend includes security headers such as:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `Cache-Control`

### Audit Logging

Important security events are logged, including:

- Login success/failure
- Document upload
- Document download
- Document sharing
- Permission request
- Permission approval/rejection
- Admin user actions
- Role changes

Audit logs include hash-chain integrity checking using `previous_hash` and `entry_hash` to detect tampering.

---

## OWASP Top 10 Coverage

This project addresses several OWASP Top 10 security risks:

- Broken Access Control
- Cryptographic Failures
- Injection
- Insecure Design
- Security Misconfiguration
- Identification and Authentication Failures
- Software and Data Integrity Failures
- Security Logging and Monitoring Failures

SSRF is not directly applicable because the backend does not fetch user-supplied external URLs.

---

## GRC and Security Assurance

This project is also suitable for security assurance and GRC-style validation.

Planned or performed testing includes:

- SAST testing for source code vulnerabilities.
- DAST testing for runtime web application vulnerabilities.
- OWASP-based security review.
- Manual testing for SQL injection, XSS, IDOR, access control, and information disclosure.
- Security control validation against the original design and threat model.

This connects the project with secure SDLC practices and governance, risk, and compliance activities.

---

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy ORM
- SQLite
- Pydantic
- bcrypt password hashing
- JWT authentication
- AES file encryption

### Frontend

- HTML
- CSS
- JavaScript
- React single-file frontend
- Tailwind CSS

### Database

- SQLite database
- SQLAlchemy ORM for database operations

---

## Project Structure

```text
project/
│
├── backend/
│   ├── app/
│   │   ├── routers/
│   │   ├── services/
│   │   ├── core/
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── db.py
│   │   └── main.py
│   │
│   ├── storage/
│   │   └── encrypted_files/
│   │
│   ├── scripts/
│   ├── requirements.txt
│   ├── .env.example
│   └── secure_legal_portal.db
│
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
│
└── README.md
## Setup on Windows PowerShell

Use Python 3.12.

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
copy .env.example .env
python scripts/generate_key.py
```

Copy the generated key into `.env`:

```text
FILE_MASTER_KEY_BASE64="generated-value-here"
JWT_SECRET_KEY="make-this-long-and-random"
```

Run the backend:

```powershell
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

The backend will redirect to:

```text
http://127.0.0.1:8000/frontend/index.html
```

## Optional: create demo users

After `.env` is ready, run:

```powershell
python scripts/create_demo_users.py
```

## Demo flow

1. Login as lawyer, client, assistant, or admin.
2. As lawyer/client, upload a document from the Documents page.
3. Backend validates file type/size, scans it, encrypts it, stores metadata, and logs the upload.
4. As lawyer, share a document with another user by email.
5. As assistant/client, download only documents they are allowed to access.
6. As admin, open User Management and Audit Integrity.
7. Admin cannot access documents because document routes block admin access server-side.

## API docs

```text
http://127.0.0.1:8000/docs
```

## Submission reminder

Do not submit your real `.env` file. Submit `.env.example` only.


## Final Admin-Integrated Version

This final version uses the integrated React frontend in `frontend/index.html` and the FastAPI backend in `backend/app`. The Register page includes all four roles: Lawyer, Client, Assistant, and Admin.

For exact Windows commands, open `RUN_STEPS_WINDOWS.md`.
