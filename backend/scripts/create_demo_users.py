"""
Create demo users for the Assignment 3 secure legal portal.
Run from backend folder after activating .venv and creating .env:

    python scripts/create_demo_users.py

Security note: these are classroom demo credentials only. Do not use them in production.
"""
from pathlib import Path
import sys

# Allow running as a script from backend/scripts.
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.core.security import hash_password  # noqa: E402
from app.db import Base, engine, SessionLocal  # noqa: E402
from app.models import User, UserRole  # noqa: E402

USERS = [
    ("Demo Lawyer", "lawyer@example.com", "Test@1234", UserRole.LAWYER.value),
    ("Demo Client", "client@example.com", "Test@1234", UserRole.CLIENT.value),
    ("Demo Assistant", "assistant@example.com", "Test@1234", UserRole.ASSISTANT.value),
    ("Demo Admin", "admin@example.com", "Test@1234", UserRole.ADMIN.value),
]


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for name, email, password, role in USERS:
            existing = db.query(User).filter(User.email == email).first()
            if existing:
                print(f"already exists: {email}")
                continue
            db.add(User(name=name, email=email, password_hash=hash_password(password), role=role, is_active=True))
            print(f"created: {email} / {password} / {role}")
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
