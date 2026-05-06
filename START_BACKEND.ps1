# Start FastAPI backend for Secure Legal Document Portal
# Run this from the main project folder.

Set-Location backend

if (-Not (Test-Path ".venv")) {
    py -3.12 -m venv .venv
}

. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

if (-Not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created backend/.env. Run: python scripts/generate_key.py, then paste the key into .env before starting." -ForegroundColor Yellow
    python scripts/generate_key.py
    notepad .env
}

python -m uvicorn app.main:app --reload
