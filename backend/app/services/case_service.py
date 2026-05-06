"""
File: case_service.py
Purpose: Create and list legal cases.
Security: Only lawyers can create cases and cases are linked to one lawyer/client.
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import Case, User, UserRole
from app.schemas import CaseCreateRequest

class CaseService:
    def __init__(self, db: Session):
        self.db = db

    def create_case(self, lawyer: User, data: CaseCreateRequest) -> Case:
        """Create case. Security: only LAWYER role and valid CLIENT target are accepted."""
        if lawyer.role != UserRole.LAWYER.value:
            raise HTTPException(status_code=403, detail="Only lawyers can create cases")
        client = self.db.get(User, data.client_id)
        if not client or client.role != UserRole.CLIENT.value:
            raise HTTPException(status_code=400, detail="Selected client is not valid")
        case = Case(case_title=data.case_title.strip(), lawyer_id=lawyer.id, client_id=client.id)
        self.db.add(case); self.db.commit(); self.db.refresh(case)
        return case

    def visible_cases(self, user: User) -> list[Case]:
        """List visible cases. Security: user receives only cases tied to them; admins see none."""
        if user.role == UserRole.LAWYER.value:
            return self.db.query(Case).filter(Case.lawyer_id == user.id).all()
        if user.role == UserRole.CLIENT.value:
            return self.db.query(Case).filter(Case.client_id == user.id).all()
        return []
