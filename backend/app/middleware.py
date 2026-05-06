"""
File: middleware.py
Purpose: Auth dependencies, rate limiting, and secure headers.
Security: Centralizes token checks, role checks, login throttling, and browser protection headers.
"""
from collections import defaultdict, deque
from time import time
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session
from app.core.security import decode_access_token
from app.db import get_db
from app.models import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
_attempts: dict[str, deque[float]] = defaultdict(deque)

async def add_security_headers(request: Request, call_next):
    """Add secure HTTP headers. Security: reduces sniffing, clickjacking, caching, and feature abuse."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' http://127.0.0.1:8000 http://localhost:8000; img-src 'self' data: blob:"
    return response

def check_rate_limit(request: Request, action: str, limit: int = 10, window_seconds: int = 60) -> None:
    """Block repeated requests. Security: slows brute-force login attempts."""
    ip = request.client.host if request.client else "unknown"
    key, now = f"{ip}:{action}", time()
    q = _attempts[key]
    while q and q[0] < now - window_seconds:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    q.append(now)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Return authenticated user. Security: verifies JWT and blocks disabled/deleted users."""
    try:
        payload = decode_access_token(token)
        user_id = int(payload.get("sub", "0"))
    except (JWTError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return user

def require_roles(*roles: UserRole):
    """Create role dependency. Security: endpoint-level RBAC."""
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in {role.value for role in roles}:
            raise HTTPException(status_code=403, detail="You are not allowed to perform this action")
        return user
    return dependency
