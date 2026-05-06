"""
File: cases.py
Purpose: Case endpoints.
Security: Lawyers create cases; listing is filtered by relationship to user.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.db import get_db
from app.middleware import get_current_user, require_roles
from app.models import User, UserRole
from app.schemas import CaseCreateRequest, CaseResponse
from app.services.audit_log_service import AuditLogService
from app.services.case_service import CaseService

router = APIRouter(prefix="/cases", tags=["Cases"])

@router.post("", response_model=CaseResponse)
def create_case(data: CaseCreateRequest, request: Request, lawyer: User = Depends(require_roles(UserRole.LAWYER)), db: Session = Depends(get_db)):
    """Create case. Security: only lawyer can create a case for a valid client."""
    case = CaseService(db).create_case(lawyer, data)
    AuditLogService(db).log_event("CASE_CREATED", "SUCCESS", actor=lawyer, target_type="Case", target_id=case.id, request=request)
    return case

@router.get("", response_model=list[CaseResponse])
def list_cases(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List cases. Security: only cases linked to current user are returned."""
    return CaseService(db).visible_cases(user)
