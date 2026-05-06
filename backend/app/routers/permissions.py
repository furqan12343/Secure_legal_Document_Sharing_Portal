"""
File: permissions.py
Purpose: Access request and lawyer approval/rejection endpoints.
Security: Only assigned lawyer can approve/reject and approved access creates ACL rows.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.db import get_db
from app.middleware import get_current_user, require_roles
from app.models import User, UserRole
from app.schemas import PermissionRequestCreate, PermissionRequestResponse
from app.services.audit_log_service import AuditLogService
from app.services.permission_service import PermissionService

router = APIRouter(prefix="/permissions", tags=["Permissions"])

@router.post("/documents/{document_id}/request", response_model=PermissionRequestResponse)
def request_access(document_id: int, data: PermissionRequestCreate, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Request document access. Security: admin blocked and duplicate pending request blocked."""
    req = PermissionService(db).request_access(user, document_id, data.reason)
    AuditLogService(db).log_event("PERMISSION_REQUESTED", "SUCCESS", actor=user, target_type="Document", target_id=document_id, request=request)
    return req

@router.get("/requests", response_model=list[PermissionRequestResponse])
def list_requests(lawyer: User = Depends(require_roles(UserRole.LAWYER)), db: Session = Depends(get_db)):
    """List lawyer requests. Security: only current lawyer's requests are returned."""
    return PermissionService(db).list_for_lawyer(lawyer)

@router.patch("/requests/{request_id}/approve", response_model=PermissionRequestResponse)
def approve(request_id: int, request: Request, lawyer: User = Depends(require_roles(UserRole.LAWYER)), db: Session = Depends(get_db)):
    """Approve request. Security: only assigned lawyer can approve."""
    req = PermissionService(db).approve(lawyer, request_id)
    AuditLogService(db).log_event("PERMISSION_APPROVED", "SUCCESS", actor=lawyer, target_type="PermissionRequest", target_id=request_id, request=request)
    return req

@router.patch("/requests/{request_id}/reject", response_model=PermissionRequestResponse)
def reject(request_id: int, request: Request, lawyer: User = Depends(require_roles(UserRole.LAWYER)), db: Session = Depends(get_db)):
    """Reject request. Security: only assigned lawyer can reject."""
    req = PermissionService(db).reject(lawyer, request_id)
    AuditLogService(db).log_event("PERMISSION_REJECTED", "SUCCESS", actor=lawyer, target_type="PermissionRequest", target_id=request_id, request=request)
    return req
