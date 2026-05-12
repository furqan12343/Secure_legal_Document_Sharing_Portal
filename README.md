# Secure Legal Document Exchange Portal

This version uses the uploaded **single-file React frontend** as the main UI and maps it onto the FastAPI backend implementation.

## What changed in this integrated version

- `frontend/index.html` is now the uploaded React single-file frontend.
- Backend now exposes compatibility routes used by that frontend:
  - `/auth/*`
  - `/documents/*`
  - `/sharing/*`
  - `/users/me*`
  - `/admin/*`
- Original backend routes are still available under `/api/*`.
- Content Security Policy was updated so the CDN-based React/Babel/Tailwind frontend can load.
- Login error handling in the frontend was fixed so failed login shows a message instead of breaking.
- A demo user creation script was added.

## Security features implemented

- JWT authentication
- Bcrypt password hashing
- Role-Based Access Control: `LAWYER`, `CLIENT`, `ASSISTANT`, `ADMIN`
- Admin separation of duties: admins can manage users/logs but cannot access legal documents
- Document-level ACL permissions
- Lawyer/client document upload
- File validation and filename sanitization
- Static malware scanning before storage
- AES-256-GCM encryption at rest
- SHA-256 file hash for integrity evidence
- Permission request and lawyer approval flow
- Lawyer document sharing by email
- Audit logging with hash-chain style integrity check
- Secure HTTP headers
- Server-side validation

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
