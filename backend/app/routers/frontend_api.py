"""
File: frontend_api.py
Purpose:
Compatibility API for the single-file React frontend supplied for Assignment 3.

Security controls:
- Uses the same JWT, bcrypt, RBAC, ACL, AES encryption, malware scanning, and audit services
  as the original backend.
- Keeps admins separated from legal documents.
- Performs server-side validation even when frontend validation exists.
- Returns frontend-friendly JSON shapes without weakening backend controls.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.db import get_db
from app.middleware import check_rate_limit, get_current_user, require_roles
from app.models import (
    AuditLog,
    Case,
    Document,
    DocumentAccess,
    FileScanResult,
    PermissionRequest,
    PermissionType,
    RequestStatus,
    User,
    UserRole,
)
from app.services.audit_log_service import AuditLogService
from app.services.auth_service import AuthService
from app.services.document_service import DocumentService
from app.services.permission_service import PermissionService
from app.services.rbac_service import RBACService

router = APIRouter(tags=["Frontend Compatibility API"])


# ---------------------------------------------------------------------------
# Request models for the React frontend
# ---------------------------------------------------------------------------

class FrontendRegisterRequest(BaseModel):
    """Registration body used by the React frontend."""
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: UserRole


class FrontendLoginRequest(BaseModel):
    """Login body used by the React frontend."""
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class SharingGrantRequest(BaseModel):
    """Direct sharing request used by lawyer UI."""
    document_id: int
    grantee_email: EmailStr
    permission_type: str = Field(default="VIEW", max_length=30)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)


class SharingRequestBody(BaseModel):
    """Assistant/client permission request body."""
    document_id: int
    justification: Optional[str] = Field(default=None, max_length=500)


class SharingApproveRequest(BaseModel):
    """Approval body used by lawyer UI."""
    request_id: int
    permission_type: str = Field(default="VIEW", max_length=30)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)


class ChangePasswordRequest(BaseModel):
    """Profile password change request."""
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class AdminPasswordResetRequest(BaseModel):
    """Admin password reset request by email."""
    user_email: EmailStr


class AdminCreateUserRequest(BaseModel):
    """Admin create-user body used by the React frontend."""
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: UserRole


class AdminRoleChangeRequest(BaseModel):
    """Admin role-change body used by the React frontend."""
    user_id: int
    new_role: UserRole


# ---------------------------------------------------------------------------
# Response mapping helpers
# ---------------------------------------------------------------------------

def user_json(user: User) -> dict:
    """Return a frontend-friendly user object without password hash."""
    return {
        "id": user.id,
        "user_id": user.id,
        "full_name": user.name,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": None,
    }


def document_json(doc: Document) -> dict:
    """Return the document shape expected by the supplied React frontend."""
    owner_id = doc.case.lawyer_id if doc.case else doc.uploaded_by_id
    return {
        "id": doc.id,
        "case_id": doc.case_id,
        "owner_id": owner_id,
        "uploaded_by_id": doc.uploaded_by_id,
        "original_filename": doc.original_filename,
        "file_hash": doc.file_hash,
        "mime_type": doc.mime_type,
        "file_size": doc.file_size,
        "scan_status": doc.scan_status,
        "malware_scan_status": "CLEAN" if doc.scan_status == "SAFE" else "MALICIOUS",
        "created_at": doc.created_at.isoformat() if doc.created_at else None,
        "uploaded_at": doc.created_at.isoformat() if doc.created_at else None,
    }


def permission_request_json(req: PermissionRequest) -> dict:
    """Return the request shape used in the lawyer approval queue."""
    return {
        "id": req.id,
        "document_id": req.document_id,
        "requester_id": req.requested_by_id,
        "requested_by_id": req.requested_by_id,
        "requested_to_lawyer_id": req.requested_to_lawyer_id,
        "status": req.status,
        "justification": req.reason,
        "reason": req.reason,
        "requested_at": req.created_at.isoformat() if req.created_at else None,
        "created_at": req.created_at.isoformat() if req.created_at else None,
        "reviewed_at": req.reviewed_at.isoformat() if req.reviewed_at else None,
    }


def activity_json(log: AuditLog) -> dict:
    """Return a compact activity item used on the profile page."""
    return {
        "id": log.id,
        "action": log.action,
        "resource_id": log.target_id,
        "target_type": log.target_type,
        "ip_address": log.ip_address,
        "status": log.status,
        "timestamp": log.created_at.isoformat() if log.created_at else None,
    }


def normalize_permission(permission: str) -> str:
    """Map frontend permissions to backend ACL permissions."""
    permission = (permission or "VIEW").upper().strip()
    if permission == "SHARE":
        return PermissionType.MANAGE.value
    if permission in {PermissionType.VIEW.value, PermissionType.DOWNLOAD.value, PermissionType.MANAGE.value}:
        return permission
    raise HTTPException(status_code=400, detail="Invalid permission type")


def ensure_case_for_upload(db: Session, user: User, raw_case_id: str | None = None) -> Case:
    """
    Find or create a case for uploads from the React frontend.

    Assignment 3 demo handover rule:
    - Numeric value = existing Case ID, only if the user belongs to that case.
    - Client may type/select ANY active lawyer email. The file is handed to that lawyer.
    - Lawyer may type/select ANY active client email. The file is linked to that client.
    - Blank field = fallback demo mode using the most recently created active lawyer/client.
    - Admin and Assistant cannot upload legal documents.
    """
    if user.role not in {UserRole.LAWYER.value, UserRole.CLIENT.value}:
        raise HTTPException(status_code=403, detail="Only lawyers and clients can upload documents")

    raw = (raw_case_id or "").strip()

    if raw and raw.isdigit():
        case = db.get(Case, int(raw))
        if case and RBACService(db).can_upload_to_case(user, case):
            return case
        raise HTTPException(status_code=403, detail="Case not found or you are not assigned to this case")

    if user.role == UserRole.CLIENT.value:
        client_id = user.id
        if raw and "@" in raw:
            lawyer = (
                db.query(User)
                .filter(User.email == raw.lower(), User.role == UserRole.LAWYER.value, User.is_active == True)
                .first()
            )
            if not lawyer:
                raise HTTPException(status_code=404, detail="No active lawyer account found for that email")
        else:
            lawyer = (
                db.query(User)
                .filter(User.role == UserRole.LAWYER.value, User.is_active == True)
                .order_by(User.id.desc())
                .first()
            )
            if not lawyer:
                raise HTTPException(status_code=400, detail="No lawyer account exists yet. Create a lawyer account first.")
        lawyer_id = lawyer.id
        title = f"Client Upload - {user.email} to {lawyer.email}"

    else:  # LAWYER upload
        lawyer_id = user.id
        if raw and "@" in raw:
            client = (
                db.query(User)
                .filter(User.email == raw.lower(), User.role == UserRole.CLIENT.value, User.is_active == True)
                .first()
            )
            if not client:
                raise HTTPException(status_code=404, detail="No active client account found for that email")
        else:
            client = (
                db.query(User)
                .filter(User.role == UserRole.CLIENT.value, User.is_active == True)
                .order_by(User.id.desc())
                .first()
            )
        client_id = client.id if client else user.id
        title = f"Lawyer Upload - {user.email}"

    existing = (
        db.query(Case)
        .filter(Case.lawyer_id == lawyer_id, Case.client_id == client_id, Case.case_title == title)
        .first()
    )
    if existing:
        return existing

    case = Case(case_title=title, lawyer_id=lawyer_id, client_id=client_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    return case

# ---------------------------------------------------------------------------
# Auth endpoints: /auth/*
# ---------------------------------------------------------------------------

@router.post("/auth/register")
def frontend_register(data: FrontendRegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register from React frontend. Security: bcrypt hashing and audit are delegated to AuthService."""
    from app.schemas import RegisterRequest

    created = AuthService(db).register(
        RegisterRequest(name=data.full_name, email=data.email, password=data.password, role=data.role),
        request,
    )
    return {"message": "Registration successful", "user": user_json(created)}


@router.post("/auth/login")
def frontend_login(data: FrontendLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login from React frontend. Security: rate limit, bcrypt verification, JWT token."""
    from app.schemas import LoginRequest

    check_rate_limit(request, "login")
    token, user = AuthService(db).login(LoginRequest(email=data.email, password=data.password), request)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "name": user.name,
        "full_name": user.name,
    }


@router.post("/auth/logout")
def frontend_logout():
    """Logout endpoint. Security: client deletes JWT; production can add revocation list."""
    return {"message": "Logged out"}


# ---------------------------------------------------------------------------
# Document endpoints: /documents/*
# ---------------------------------------------------------------------------

@router.get("/documents/")
def frontend_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List visible documents. Security: DocumentService filters by RBAC/ACL and blocks admins."""
    docs = DocumentService(db).visible_documents(user)
    return {"documents": [document_json(d) for d in docs]}


@router.post("/documents/upload")
async def frontend_upload_document(
    request: Request,
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Upload from React frontend. Security: creates/uses a case, then validates, scans, encrypts, and logs."""
    case = ensure_case_for_upload(db, user, case_id)
    try:
        doc = await DocumentService(db).upload_document(user, case.id, file)
        AuditLogService(db).log_event(
            "DOCUMENT_UPLOADED",
            "SUCCESS",
            actor=user,
            target_type="Document",
            target_id=doc.id,
            request=request,
            details=description,
        )
        return {"message": "Document uploaded", "document": document_json(doc)}
    except Exception:
        db.rollback()
        try:
            AuditLogService(db).log_event(
                "DOCUMENT_UPLOAD_FAILED", "FAILED", actor=user, target_type="Document", request=request
            )
        except Exception:
            db.rollback()
        raise


@router.get("/documents/{document_id}/download")
def frontend_download_document(
    document_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download document. Security: decryption occurs only after DOWNLOAD authorization."""
    from fastapi.responses import Response

    try:
        doc, data = DocumentService(db).decrypt_for_download(user, document_id)
        AuditLogService(db).log_event(
            "DOCUMENT_DOWNLOADED", "SUCCESS", actor=user, target_type="Document", target_id=doc.id, request=request
        )
        return Response(
            content=data,
            media_type=doc.mime_type or "application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{doc.original_filename}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )
    except Exception:
        AuditLogService(db).log_event(
            "FAILED_DOCUMENT_DOWNLOAD", "FAILED", actor=user, target_type="Document", target_id=document_id, request=request
        )
        raise


@router.delete("/documents/{document_id}")
def frontend_delete_document(
    document_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a document. Security: only managing lawyer/owner can delete; audit is preserved."""
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if not RBACService(db).can_manage_document(user, doc) and doc.uploaded_by_id != user.id:
        raise HTTPException(status_code=403, detail="You cannot delete this document")

    # Delete dependent rows first to satisfy simple SQLite foreign key behavior.
    db.query(DocumentAccess).filter(DocumentAccess.document_id == document_id).delete()
    db.query(PermissionRequest).filter(PermissionRequest.document_id == document_id).delete()
    db.query(FileScanResult).filter(FileScanResult.document_id == document_id).delete()
    path = Path(doc.encrypted_file_path)
    db.delete(doc)
    db.commit()
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass
    AuditLogService(db).log_event(
        "DOCUMENT_DELETED", "SUCCESS", actor=user, target_type="Document", target_id=document_id, request=request
    )
    return {"message": "Document deleted"}


# ---------------------------------------------------------------------------
# Sharing/request endpoints: /sharing/*
# ---------------------------------------------------------------------------

@router.post("/sharing/grant")
def frontend_grant_access(
    data: SharingGrantRequest,
    request: Request,
    lawyer: User = Depends(require_roles(UserRole.LAWYER)),
    db: Session = Depends(get_db),
):
    """Share a document by recipient email. Security: delegates actual ACL checks to PermissionService."""
    target = db.query(User).filter(User.email == data.grantee_email.lower().strip()).first()
    if not target:
        raise HTTPException(status_code=404, detail="Recipient user not found")
    permission = normalize_permission(data.permission_type)
    access = PermissionService(db).share(lawyer, data.document_id, target.id, permission)
    AuditLogService(db).log_event(
        "DOCUMENT_SHARED",
        "SUCCESS",
        actor=lawyer,
        target_type="Document",
        target_id=data.document_id,
        request=request,
        details=f"target_email={target.email}, permission={permission}",
    )
    return {"message": "Document shared", "access_id": access.id}


@router.post("/sharing/request")
def frontend_request_access(
    data: SharingRequestBody,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create permission request. Security: admins blocked and duplicate pending requests blocked."""
    doc = db.get(Document, data.document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if user.role == UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Admin cannot request legal document access")
    if doc.case and doc.case.lawyer_id == user.id:
        raise HTTPException(status_code=400, detail="You already manage this document")
    pending = (
        db.query(PermissionRequest)
        .filter_by(document_id=doc.id, requested_by_id=user.id, status=RequestStatus.PENDING.value)
        .first()
    )
    if pending:
        raise HTTPException(status_code=400, detail="A pending request already exists")
    lawyer_id = doc.case.lawyer_id if doc.case else doc.uploaded_by_id
    req = PermissionRequest(
        document_id=doc.id,
        requested_by_id=user.id,
        requested_to_lawyer_id=lawyer_id,
        reason=data.justification,
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    AuditLogService(db).log_event(
        "PERMISSION_REQUESTED", "SUCCESS", actor=user, target_type="Document", target_id=data.document_id, request=request
    )
    return {"message": "Permission request submitted", "request": permission_request_json(req)}


@router.get("/sharing/pending")
def frontend_pending_requests(lawyer: User = Depends(require_roles(UserRole.LAWYER)), db: Session = Depends(get_db)):
    """List pending requests for current lawyer only."""
    reqs = [r for r in PermissionService(db).list_for_lawyer(lawyer) if r.status == RequestStatus.PENDING.value]
    return {"requests": [permission_request_json(r) for r in reqs]}


@router.post("/sharing/approve")
def frontend_approve_request(
    data: SharingApproveRequest,
    request: Request,
    lawyer: User = Depends(require_roles(UserRole.LAWYER)),
    db: Session = Depends(get_db),
):
    """Approve request. Security: only the assigned lawyer can approve."""
    # Existing service grants VIEW+DOWNLOAD. For VIEW-only, remove DOWNLOAD afterwards.
    req = PermissionService(db).approve(lawyer, data.request_id)
    requested_permission = normalize_permission(data.permission_type)
    if requested_permission == PermissionType.VIEW.value:
        db.query(DocumentAccess).filter_by(
            document_id=req.document_id,
            user_id=req.requested_by_id,
            permission_type=PermissionType.DOWNLOAD.value,
        ).delete()
        db.commit()
    elif requested_permission == PermissionType.MANAGE.value:
        PermissionService(db).grant(req.document_id, req.requested_by_id, lawyer.id, PermissionType.MANAGE.value)
        db.commit()
    AuditLogService(db).log_event(
        "PERMISSION_APPROVED",
        "SUCCESS",
        actor=lawyer,
        target_type="PermissionRequest",
        target_id=data.request_id,
        request=request,
        details=f"permission={requested_permission}",
    )
    return {"message": "Request approved", "request": permission_request_json(req)}


@router.post("/sharing/deny/{request_id}")
def frontend_deny_request(
    request_id: int,
    request: Request,
    lawyer: User = Depends(require_roles(UserRole.LAWYER)),
    db: Session = Depends(get_db),
):
    """Deny request. Security: only the assigned lawyer can deny."""
    req = PermissionService(db).reject(lawyer, request_id)
    AuditLogService(db).log_event(
        "PERMISSION_REJECTED", "SUCCESS", actor=lawyer, target_type="PermissionRequest", target_id=request_id, request=request
    )
    return {"message": "Request denied", "request": permission_request_json(req)}


# ---------------------------------------------------------------------------
@router.get("/users/lawyers")
def frontend_list_lawyers(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List active lawyers for client upload handover. Security: authenticated users only."""
    lawyers = (
        db.query(User)
        .filter(User.role == UserRole.LAWYER.value, User.is_active == True)
        .order_by(User.email)
        .all()
    )
    return {"lawyers": [
        {"id": u.id, "email": u.email, "full_name": u.name, "name": u.name, "role": u.role}
        for u in lawyers
    ]}

# Profile endpoints: /users/me*
# ---------------------------------------------------------------------------

@router.get("/users/me")
def frontend_profile(user: User = Depends(get_current_user)):
    """Return current user profile. Security: password hash is never returned."""
    return {"profile": user_json(user)}


@router.get("/users/me/activity")
def frontend_activity(limit: int = 20, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return current user's recent audit events."""
    limit = max(1, min(limit, 100))
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.actor_user_id == user.id)
        .order_by(AuditLog.id.desc())
        .limit(limit)
        .all()
    )
    return {"activity": [activity_json(log) for log in logs]}


@router.put("/users/me/password")
def frontend_change_password(
    data: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change current user's password. Security: verifies current bcrypt hash first."""
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.password_hash = hash_password(data.new_password)
    db.commit()
    AuditLogService(db).log_event("PASSWORD_CHANGED", "SUCCESS", actor=user, target_type="User", target_id=user.id, request=request)
    return {"message": "Password changed successfully"}


# ---------------------------------------------------------------------------
# Admin endpoints: /admin/*
# ---------------------------------------------------------------------------

@router.get("/admin/users")
def frontend_admin_users(admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """List users. Security: admin-only."""
    users = db.query(User).order_by(User.id).all()
    return {"users": [user_json(u) for u in users]}


@router.post("/admin/users")
def frontend_admin_create_user(
    data: AdminCreateUserRequest,
    request: Request,
    admin: User = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Create user from admin UI. Security: admin-only, password is bcrypt-hashed."""
    email = data.email.lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Unable to create user with these details")
    user = User(name=data.full_name.strip(), email=email, password_hash=hash_password(data.password), role=data.role.value)
    db.add(user)
    db.commit()
    db.refresh(user)
    AuditLogService(db).log_event("USER_CREATED_BY_ADMIN", "SUCCESS", actor=admin, target_type="User", target_id=user.id, request=request)
    return {"message": "User created", "user": user_json(user)}


@router.post("/admin/users/role")
def frontend_admin_change_role(
    data: AdminRoleChangeRequest,
    request: Request,
    admin: User = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Change user role. Security: admin cannot change their own role."""
    user = db.get(User, data.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=403, detail="Admin cannot change their own role")
    user.role = data.new_role.value
    db.commit()
    db.refresh(user)
    AuditLogService(db).log_event(
        "ROLE_CHANGED", "SUCCESS", actor=admin, target_type="User", target_id=user.id, request=request, details=f"new_role={user.role}"
    )
    return {"message": "Role updated", "user": user_json(user)}


@router.delete("/admin/users/{user_id}")
def frontend_admin_delete_user(
    user_id: int,
    request: Request,
    admin: User = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Deactivate user. Security: admin cannot deactivate self; audit is preserved."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=403, detail="Admin cannot deactivate their own account")
    user.is_active = False
    db.commit()
    AuditLogService(db).log_event("USER_DEACTIVATED", "SUCCESS", actor=admin, target_type="User", target_id=user.id, request=request)
    return {"message": "User deactivated", "user": user_json(user)}


@router.post("/admin/users/password-reset")
def frontend_admin_password_reset(
    data: AdminPasswordResetRequest,
    request: Request,
    admin: User = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Create reset token for user. Security: token is stored hashed; raw token returned only for classroom demo."""
    token = AuthService(db).create_reset_token(str(data.user_email), request)
    AuditLogService(db).log_event("ADMIN_PASSWORD_RESET_REQUESTED", "SUCCESS", actor=admin, target_type="User", target_id=str(data.user_email), request=request)
    if token:
        return {"message": f"Password reset token created for demo: {token}", "demo_reset_token": token}
    return {"message": "If this user exists, a reset token has been created."}


@router.get("/admin/audit/integrity")
def frontend_audit_integrity(admin: User = Depends(require_roles(UserRole.ADMIN)), db: Session = Depends(get_db)):
    """Verify audit hash chain. Security: detects log tampering in the prototype audit table."""
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    tampered_ids: list[int] = []
    previous = None
    for log in logs:
        payload = {
            "actor_user_id": log.actor_user_id,
            "action": log.action,
            "target_type": log.target_type,
            "target_id": log.target_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "status": log.status,
            "details": log.details,
            "previous_hash": log.previous_hash,
        }
        expected_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        if log.previous_hash != previous or log.entry_hash != expected_hash:
            tampered_ids.append(log.id)
        previous = log.entry_hash
    total = len(logs)
    tampered = len(tampered_ids)
    return {
        "integrity_check": {
            "total": total,
            "valid": total - tampered,
            "tampered": tampered,
            "tampered_ids": tampered_ids,
        }
    }


