"""
File: auth_service.py
Purpose: Registration, login, and password reset.
Security: Passwords are bcrypt-hashed, login errors are generic, and attempts are logged.
"""
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session
from app.core.security import create_access_token, hash_password, sha256_text, verify_password
from app.models import LoginAttempt, PasswordResetToken, User
from app.schemas import LoginRequest, RegisterRequest
from app.services.audit_log_service import AuditLogService

class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.audit = AuditLogService(db)

    def register(self, data: RegisterRequest, request: Request | None = None) -> User:
        """Register user. Security: duplicate emails rejected and password stored as hash only."""
        email = data.email.lower().strip()
        if self.db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=400, detail="Unable to register user with these details")
        user = User(name=data.name.strip(), email=email, password_hash=hash_password(data.password), role=data.role.value)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        self.audit.log_event("USER_REGISTERED", "SUCCESS", actor=user, target_type="User", target_id=user.id, request=request)
        return user

    def login(self, data: LoginRequest, request: Request | None = None) -> tuple[str, User]:
        """Login user. Security: verifies bcrypt hash, blocks inactive users, logs success/failure."""
        email = data.email.lower().strip()
        user = self.db.query(User).filter(User.email == email).first()
        success = bool(user and user.is_active and verify_password(data.password, user.password_hash))
        self.db.add(LoginAttempt(email=email, ip_address=request.client.host if request and request.client else None, success=success))
        self.db.commit()
        if not success:
            self.audit.log_event("LOGIN_FAILED", "FAILED", target_type="User", target_id=email, request=request)
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = create_access_token(user.id, user.role)
        self.audit.log_event("LOGIN_SUCCESS", "SUCCESS", actor=user, target_type="User", target_id=user.id, request=request)
        return token, user

    def create_reset_token(self, email: str, request: Request | None = None) -> str | None:
        """Create reset token. Security: stores SHA-256 of token, not the raw token."""
        user = self.db.query(User).filter(User.email == email.lower().strip()).first()
        if not user:
            return None
        raw = secrets.token_urlsafe(32)
        reset = PasswordResetToken(user_id=user.id, token_hash=sha256_text(raw), expires_at=datetime.now(timezone.utc) + timedelta(minutes=30))
        self.db.add(reset)
        self.db.commit()
        self.audit.log_event("PASSWORD_RESET_TOKEN_CREATED", "SUCCESS", actor=user, target_type="User", target_id=user.id, request=request)
        return raw

    def reset_password(self, raw_token: str, new_password: str, request: Request | None = None) -> None:
        """Reset password. Security: token must be valid, unused, and not expired."""
        token_hash = sha256_text(raw_token)
        reset = self.db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
        now = datetime.now(timezone.utc)
        if not reset or reset.used or reset.expires_at < now:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        user = self.db.get(User, reset.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        user.password_hash = hash_password(new_password)
        reset.used = True
        self.db.commit()
        self.audit.log_event("PASSWORD_RESET_COMPLETED", "SUCCESS", actor=user, target_type="User", target_id=user.id, request=request)
