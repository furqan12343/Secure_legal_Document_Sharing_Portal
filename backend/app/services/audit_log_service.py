"""
File: audit_log_service.py
Purpose: Store and read security audit logs.
Security: Uses hash chaining to make log tampering easier to detect.
"""
import hashlib, json
from fastapi import Request
from sqlalchemy import desc
from sqlalchemy.orm import Session
from app.models import AuditLog, User

class AuditLogService:
    def __init__(self, db: Session):
        self.db = db

    def log_event(self, action: str, status: str, actor: User | None = None, target_type: str | None = None,
                  target_id: str | int | None = None, request: Request | None = None, details: str | None = None) -> AuditLog:
        """Write audit log. Security: captures actor/IP/user-agent and links entry to previous hash."""
        previous = self.db.query(AuditLog).order_by(desc(AuditLog.id)).first()
        payload = {
            "actor_user_id": actor.id if actor else None,
            "action": action,
            "target_type": target_type,
            "target_id": str(target_id) if target_id is not None else None,
            "ip_address": request.client.host if request and request.client else None,
            "user_agent": request.headers.get("user-agent") if request else None,
            "status": status,
            "details": details,
            "previous_hash": previous.entry_hash if previous else None,
        }
        entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        log = AuditLog(entry_hash=entry_hash, **payload)
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        return log

    def recent(self, limit: int = 100) -> list[AuditLog]:
        """Return recent logs. Security: this must be called only from admin-protected routes."""
        return self.db.query(AuditLog).order_by(desc(AuditLog.id)).limit(limit).all()
