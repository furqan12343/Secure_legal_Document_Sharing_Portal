"""
File: documents.py
Purpose: Document upload, listing, metadata, download, and sharing endpoints.
Security: Upload scans/encrypts; download decrypts only after RBAC/ACL check.
"""
from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.db import get_db
from app.middleware import get_current_user
from app.models import PermissionType, User
from app.schemas import DocumentResponse, DocumentShareRequest
from app.services.audit_log_service import AuditLogService
from app.services.document_service import DocumentService
from app.services.permission_service import PermissionService

router = APIRouter(prefix="/documents", tags=["Documents"])

@router.post("/upload", response_model=DocumentResponse)
async def upload(case_id: int, request: Request, file: UploadFile = File(...), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Upload document. Security: validates, scans malware, encrypts, stores only metadata."""
    try:
        doc = await DocumentService(db).upload_document(user, case_id, file)
        AuditLogService(db).log_event("DOCUMENT_UPLOADED", "SUCCESS", actor=user, target_type="Document", target_id=doc.id, request=request)
        return doc
    except Exception:
        AuditLogService(db).log_event("DOCUMENT_UPLOAD_FAILED", "FAILED", actor=user, target_type="Document", request=request)
        raise

@router.get("", response_model=list[DocumentResponse])
def list_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List documents. Security: filtered by current user's document access rights."""
    return DocumentService(db).visible_documents(user)

@router.get("/{document_id}", response_model=DocumentResponse)
def metadata(document_id: int, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """View metadata. Security: requires VIEW permission."""
    try:
        doc = DocumentService(db).authorized_document(user, document_id, PermissionType.VIEW)
        AuditLogService(db).log_event("DOCUMENT_VIEWED", "SUCCESS", actor=user, target_type="Document", target_id=doc.id, request=request)
        return doc
    except Exception:
        AuditLogService(db).log_event("FAILED_DOCUMENT_VIEW", "FAILED", actor=user, target_type="Document", target_id=document_id, request=request)
        raise

@router.get("/{document_id}/download")
def download(document_id: int, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Download document. Security: requires DOWNLOAD permission before decryption."""
    try:
        doc, data = DocumentService(db).decrypt_for_download(user, document_id)
        AuditLogService(db).log_event("DOCUMENT_DOWNLOADED", "SUCCESS", actor=user, target_type="Document", target_id=doc.id, request=request)
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
        AuditLogService(db).log_event("FAILED_DOCUMENT_DOWNLOAD", "FAILED", actor=user, target_type="Document", target_id=document_id, request=request)
        raise

@router.post("/{document_id}/share")
def share(document_id: int, data: DocumentShareRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Share document. Security: managing lawyer only; admin cannot receive document access."""
    access = PermissionService(db).share(user, document_id, data.target_user_id, data.permission_type)
    AuditLogService(db).log_event("DOCUMENT_SHARED", "SUCCESS", actor=user, target_type="Document", target_id=document_id, request=request, details=f"target_user={data.target_user_id}, permission={data.permission_type}")
    return {"message": "Document shared", "access_id": access.id}
