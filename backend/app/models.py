"""
File: models.py
Purpose: Database classes for users, cases, documents, ACLs, permission requests, and logs.
Security: Passwords are stored as hashes only, documents are stored encrypted, and access is explicit.
"""
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db import Base

def utcnow():
    return datetime.now(timezone.utc)

class UserRole(str, Enum):
    LAWYER = "LAWYER"
    CLIENT = "CLIENT"
    ASSISTANT = "ASSISTANT"
    ADMIN = "ADMIN"

class PermissionType(str, Enum):
    VIEW = "VIEW"
    DOWNLOAD = "DOWNLOAD"
    MANAGE = "MANAGE"

class RequestStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class ScanStatus(str, Enum):
    SAFE = "SAFE"
    BLOCKED = "BLOCKED"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    case_title = Column(String(200), nullable=False)
    lawyer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    lawyer = relationship("User", foreign_keys=[lawyer_id])
    client = relationship("User", foreign_keys=[client_id])

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    uploaded_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), unique=True, nullable=False)
    encrypted_file_path = Column(String(500), nullable=False)
    file_hash = Column(String(64), nullable=False)
    mime_type = Column(String(120), nullable=True)
    file_size = Column(Integer, nullable=False)
    scan_status = Column(String(30), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    case = relationship("Case")
    uploader = relationship("User")

class DocumentAccess(Base):
    __tablename__ = "document_access"
    __table_args__ = (UniqueConstraint("document_id", "user_id", "permission_type", name="uq_doc_user_perm"),)
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permission_type = Column(String(30), nullable=False)
    granted_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class PermissionRequest(Base):
    __tablename__ = "permission_requests"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    requested_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    requested_to_lawyer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(30), default=RequestStatus.PENDING.value, nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    reviewed_at = Column(DateTime, nullable=True)
    document = relationship("Document")
    requested_by = relationship("User", foreign_keys=[requested_by_id])

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    actor_user_id = Column(Integer, nullable=True)
    action = Column(String(80), nullable=False)
    target_type = Column(String(80), nullable=True)
    target_id = Column(String(80), nullable=True)
    ip_address = Column(String(80), nullable=True)
    user_agent = Column(Text, nullable=True)
    status = Column(String(30), nullable=False)
    details = Column(Text, nullable=True)
    previous_hash = Column(String(64), nullable=True)
    entry_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False)
    ip_address = Column(String(80), nullable=True)
    success = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class FileScanResult(Base):
    __tablename__ = "file_scan_results"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=True)
    filename = Column(String(255), nullable=False)
    scan_result = Column(String(30), nullable=False)
    risk_score = Column(Integer, nullable=False)
    scanner_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
