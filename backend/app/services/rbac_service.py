"""
File: rbac_service.py
Purpose: Role and document permission checks.
Security: Blocks IDOR by checking every document access request server-side.
"""
from sqlalchemy.orm import Session
from app.models import Case, Document, DocumentAccess, PermissionType, User, UserRole

class RBACService:
    def __init__(self, db: Session):
        self.db = db

    def can_upload_to_case(self, user: User, case: Case) -> bool:
        """Check upload rights. Security: only assigned lawyer/client can upload to a case."""
        return (user.role == UserRole.LAWYER.value and case.lawyer_id == user.id) or (user.role == UserRole.CLIENT.value and case.client_id == user.id)

    def can_manage_document(self, user: User, document: Document) -> bool:
        """Check document management. Security: admin is blocked from legal document management."""
        if user.role == UserRole.ADMIN.value:
            return False
        if document.case and document.case.lawyer_id == user.id:
            return True
        return self._has_acl(document.id, user.id, PermissionType.MANAGE.value)

    def can_access_document(self, user: User, document: Document, permission: PermissionType = PermissionType.VIEW) -> bool:
        """Check view/download rights. Security: admin blocked and ACL required for shared users."""
        if user.role == UserRole.ADMIN.value:
            return False
        if document.case and (document.case.lawyer_id == user.id or document.case.client_id == user.id):
            return True
        if permission == PermissionType.DOWNLOAD:
            return self._has_acl(document.id, user.id, PermissionType.DOWNLOAD.value) or self._has_acl(document.id, user.id, PermissionType.MANAGE.value)
        return any(self._has_acl(document.id, user.id, p.value) for p in [PermissionType.VIEW, PermissionType.DOWNLOAD, PermissionType.MANAGE])

    def _has_acl(self, document_id: int, user_id: int, permission: str) -> bool:
        """Check ACL row. Security: never trusts client-side role/permission claims."""
        return self.db.query(DocumentAccess).filter_by(document_id=document_id, user_id=user_id, permission_type=permission).first() is not None
