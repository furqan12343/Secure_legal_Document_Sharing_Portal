"""
File: admin.py
Purpose: Admin user-management and audit-log endpoints.
Security: All routes require ADMIN and admin cannot access legal document contents here.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.security import hash_password
from app.db import get_db
from app.middleware import require_roles
from app.models import User, UserRole
from app.schemas import AuditLogResponse, RoleUpdateRequest, StatusUpdateRequest, UserCreateRequest, UserResponse
from app.services.audit_log_service import AuditLogService

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/users", response_model=list[UserResponse])
def list_users(admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """List users. Security: admin-only endpoint."""
    return db.query(User).order_by(User.id).all()

@router.post("/users", response_model=UserResponse)
def create_user(data: UserCreateRequest, request: Request, admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """Create user. Security: password is hashed and duplicate email is rejected."""
    email = data.email.lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Unable to create user with these details")
    user = User(name=data.name.strip(), email=email, password_hash=hash_password(data.password), role=data.role.value)
    db.add(user); db.commit(); db.refresh(user)
    AuditLogService(db).log_event("USER_CREATED_BY_ADMIN", "SUCCESS", actor=admin, target_type="User", target_id=user.id, request=request)
    return user

@router.patch("/users/{user_id}/role", response_model=UserResponse)
def change_role(user_id: int, data: RoleUpdateRequest, request: Request, admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """Change role. Security: admin cannot change their own role."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=403, detail="Admin cannot change their own role")
    user.role = data.role.value
    db.commit(); db.refresh(user)
    AuditLogService(db).log_event("ROLE_CHANGED", "SUCCESS", actor=admin, target_type="User", target_id=user.id, request=request, details=f"new_role={data.role.value}")
    return user

@router.patch("/users/{user_id}/status", response_model=UserResponse)
def set_status(user_id: int, data: StatusUpdateRequest, request: Request, admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """Activate/deactivate user. Security: admin cannot disable their own account."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=403, detail="Admin cannot disable their own account")
    user.is_active = data.is_active
    db.commit(); db.refresh(user)
    AuditLogService(db).log_event("USER_STATUS_CHANGED", "SUCCESS", actor=admin, target_type="User", target_id=user.id, request=request, details=f"is_active={data.is_active}")
    return user

@router.get("/audit-logs", response_model=list[AuditLogResponse])
def audit_logs(limit: int = 100, admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """View audit logs. Security: admin-only and limited to 500 rows."""
    return AuditLogService(db).recent(min(limit, 500))
