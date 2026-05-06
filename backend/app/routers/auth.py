"""
File: auth.py
Purpose: Authentication endpoints.
Security: Server-side validation, bcrypt passwords, generic login errors, and rate limiting.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.db import get_db
from app.middleware import check_rate_limit
from app.schemas import LoginRequest, PasswordResetConfirm, PasswordResetRequest, RegisterRequest, TokenResponse, UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
def register(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register user. Security: password is hashed before saving."""
    return AuthService(db).register(data, request)

@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login user. Security: throttled, bcrypt-verified, and audited."""
    check_rate_limit(request, "login")
    token, user = AuthService(db).login(data, request)
    return TokenResponse(access_token=token, role=user.role, name=user.name, user_id=user.id)

@router.post("/request-password-reset")
def request_password_reset(data: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    """Create reset token. Security: token hash is stored; prototype returns token for demo only."""
    token = AuthService(db).create_reset_token(data.email, request)
    response = {"message": "If this email exists, a reset link has been created."}
    if token:
        response["demo_reset_token"] = token
    return response

@router.post("/reset-password")
def reset_password(data: PasswordResetConfirm, request: Request, db: Session = Depends(get_db)):
    """Reset password. Security: token must be unused, valid, and unexpired."""
    AuthService(db).reset_password(data.token, data.new_password, request)
    return {"message": "Password reset successful"}

@router.post("/logout")
def logout():
    """Logout hint. Security: client must delete token; production should add token revocation."""
    return {"message": "Delete the token on client side"}
