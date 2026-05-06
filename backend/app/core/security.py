"""
File: security.py
Purpose: Password hashing, JWT creation/validation, and token hashing.
Security: bcrypt is used for passwords; JWT contains only minimal claims and has expiry.
"""
from datetime import datetime, timedelta, timezone
import hashlib, bcrypt
from jose import jwt
from app.core.config import settings

def hash_password(password: str) -> str:
    """Hash password using bcrypt. Security: bcrypt automatically creates a random salt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password safely. Security: invalid hash returns False instead of leaking error."""
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False

def create_access_token(user_id: int, role: str) -> str:
    """Create JWT access token. Security: token has expiry and is signed with env secret."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.require_jwt_secret(), algorithm=settings.jwt_algorithm)

def decode_access_token(token: str) -> dict:
    """Decode JWT. Security: verifies signature and expiry."""
    return jwt.decode(token, settings.require_jwt_secret(), algorithms=[settings.jwt_algorithm])

def sha256_text(value: str) -> str:
    """Hash sensitive tokens before DB storage. Security: raw reset token is not stored."""
    return hashlib.sha256(value.encode()).hexdigest()
