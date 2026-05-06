"""
File: schemas.py
Purpose: Pydantic request/response validation models.
Security: The backend validates all user input and never trusts frontend-only checks.
"""
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from app.models import UserRole

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: UserRole

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    name: str
    user_id: int

class UserCreateRequest(RegisterRequest):
    pass

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime

class RoleUpdateRequest(BaseModel):
    role: UserRole

class StatusUpdateRequest(BaseModel):
    is_active: bool

class CaseCreateRequest(BaseModel):
    case_title: str = Field(min_length=3, max_length=200)
    client_id: int

class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    case_title: str
    lawyer_id: int
    client_id: int
    created_at: datetime

class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    case_id: int
    uploaded_by_id: int
    original_filename: str
    file_hash: str
    mime_type: str | None
    file_size: int
    scan_status: str
    created_at: datetime

class DocumentShareRequest(BaseModel):
    target_user_id: int
    permission_type: str = "VIEW"

class PermissionRequestCreate(BaseModel):
    reason: str | None = Field(default=None, max_length=500)

class PermissionRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    document_id: int
    requested_by_id: int
    requested_to_lawyer_id: int
    status: str
    reason: str | None
    created_at: datetime
    reviewed_at: datetime | None

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor_user_id: int | None
    action: str
    target_type: str | None
    target_id: str | None
    ip_address: str | None
    status: str
    details: str | None
    previous_hash: str | None
    entry_hash: str
    created_at: datetime

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=8, max_length=128)
