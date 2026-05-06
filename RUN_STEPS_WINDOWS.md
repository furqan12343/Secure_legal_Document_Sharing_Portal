# Windows Run Steps for Final Admin Integrated Version

This project has this layout:

```text
SSD_Assignment3_Group13_FINAL_Admin_Integrated/
├── backend/
│   ├── app/
│   ├── scripts/
│   ├── storage/
│   ├── .env.example
│   └── requirements.txt
└── frontend/
    └── index.html
```

## Run from VS Code / PowerShell

Open the main project folder in VS Code, then open **Terminal > New Terminal**.

Run:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
copy .env.example .env
python scripts/generate_key.py
notepad .env
python -m uvicorn app.main:app --reload
```

Inside `.env`, paste your generated key like this:

```env
FILE_MASTER_KEY_BASE64="PASTE_GENERATED_KEY_HERE"
JWT_SECRET_KEY="Group13SecureLegalPortalJWTSecret123456"
```

Then open:

```text
http://127.0.0.1:8000
```

## Important

The `.env` file is not included in the ZIP on purpose. Create it by running:

```powershell
copy .env.example .env
```

The Admin option is included in the Register page role dropdown. If your browser still shows the old dropdown, press **Ctrl + F5** or open the project in a fresh browser tab.

## Optional demo users

After installing requirements and creating `.env`, you may run:

```powershell
python scripts/create_demo_users.py
```

Demo passwords use:

```text
Test@1234
```
