"""
File: permission_service.py
Purpose: Permission request, approval/rejection, and document sharing.
Security: Only the assigned lawyer can approve/share; admins cannot receive document access.
"""
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import Document, DocumentAccess, PermissionRequest, PermissionType, RequestStatus, User, UserRole
from app.services.rbac_service import RBACService

class PermissionService:
    def __init__(self, db: Session):
        self.db = db
        self.rbac = RBACService(db)

    def request_access(self, user: User, document_id: int, reason: str | None = None) -> PermissionRequest:
        """Request access. Security: admins blocked, duplicate pending requests blocked, lawyer is selected from case."""
        doc = self.db.get(Document, document_id)
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if user.role == UserRole.ADMIN.value:
            raise HTTPException(status_code=403, detail="Admin cannot request legal document access")
        if self.rbac.can_access_document(user, doc):
            raise HTTPException(status_code=400, detail="You already have access")
        pending = self.db.query(PermissionRequest).filter_by(document_id=doc.id, requested_by_id=user.id, status=RequestStatus.PENDING.value).first()
        if pending:
            raise HTTPException(status_code=400, detail="A pending request already exists")
        req = PermissionRequest(document_id=doc.id, requested_by_id=user.id, requested_to_lawyer_id=doc.case.lawyer_id, reason=reason)
        self.db.add(req); self.db.commit(); self.db.refresh(req)
        return req

    def list_for_lawyer(self, lawyer: User) -> list[PermissionRequest]:
        """List requests. Security: lawyers only see requests assigned to them."""
        if lawyer.role != UserRole.LAWYER.value:
            raise HTTPException(status_code=403, detail="Only lawyers can view requests")
        return self.db.query(PermissionRequest).filter_by(requested_to_lawyer_id=lawyer.id).order_by(PermissionRequest.id.desc()).all()

    def approve(self, lawyer: User, request_id: int) -> PermissionRequest:
        """Approve request. Security: only assigned lawyer can approve and approval creates ACL rows."""
        req = self._reviewable(lawyer, request_id)
        req.status = RequestStatus.APPROVED.value
        req.reviewed_at = datetime.now(timezone.utc)
        self.grant(req.document_id, req.requested_by_id, lawyer.id, PermissionType.VIEW.value)
        self.grant(req.document_id, req.requested_by_id, lawyer.id, PermissionType.DOWNLOAD.value)
        self.db.commit(); self.db.refresh(req)
        return req

    def reject(self, lawyer: User, request_id: int) -> PermissionRequest:
        """Reject request. Security: only assigned lawyer can reject and no ACL is created."""
        req = self._reviewable(lawyer, request_id)
        req.status = RequestStatus.REJECTED.value
        req.reviewed_at = datetime.now(timezone.utc)
        self.db.commit(); self.db.refresh(req)
        return req

    def share(self, lawyer: User, document_id: int, target_user_id: int, permission: str) -> DocumentAccess:
        """Share document. Security: managing lawyer only, target cannot be admin, permission value is validated."""
        doc = self.db.get(Document, document_id)
        target = self.db.get(User, target_user_id)
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if not self.rbac.can_manage_document(lawyer, doc):
            raise HTTPException(status_code=403, detail="You cannot share this document")
        if not target or target.role == UserRole.ADMIN.value:
            raise HTTPException(status_code=400, detail="Target user is not valid for document sharing")
        if permission not in {p.value for p in PermissionType}:
            raise HTTPException(status_code=400, detail="Invalid permission")
        access = self.grant(document_id, target_user_id, lawyer.id, permission)
        self.db.commit(); self.db.refresh(access)
        return access

    def grant(self, document_id: int, user_id: int, granted_by_id: int, permission: str) -> DocumentAccess:
        """Grant ACL. Security: document access is explicit and auditable."""
        existing = self.db.query(DocumentAccess).filter_by(document_id=document_id, user_id=user_id, permission_type=permission).first()
        if existing:
            return existing
        access = DocumentAccess(document_id=document_id, user_id=user_id, granted_by_id=granted_by_id, permission_type=permission)
        self.db.add(access)
        return access

    def _reviewable(self, lawyer: User, request_id: int) -> PermissionRequest:
        """Return request if lawyer can review. Security: prevents approving other lawyers' requests."""
        req = self.db.get(PermissionRequest, request_id)
        if not req:
            raise HTTPException(status_code=404, detail="Permission request not found")
        if lawyer.role != UserRole.LAWYER.value or req.requested_to_lawyer_id != lawyer.id:
            raise HTTPException(status_code=403, detail="You cannot review this request")
        if req.status != RequestStatus.PENDING.value:
            raise HTTPException(status_code=400, detail="Request is not pending")
        return req
