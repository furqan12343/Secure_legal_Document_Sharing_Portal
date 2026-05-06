"""
File: utils.py
Purpose: File validation, filename sanitization, and text cleanup helpers.
Security: Rejects dangerous uploads and reduces path traversal/XSS risks.
"""
import os, re, html
from pathlib import Path
from fastapi import HTTPException
from app.core.config import settings

SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]")

def clean_text(value: str, max_length: int = 500) -> str:
    """Escape and trim text. Security: reduces unsafe HTML output in the simple frontend."""
    return html.escape((value or "").strip())[:max_length]

def sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filename. Security: removes path separators and unusual characters."""
    name = os.path.basename(filename or "uploaded_file")
    name = SAFE_NAME.sub("_", name)
    return name[:180] or "uploaded_file"

def validate_upload(filename: str, content_type: str | None, file_bytes: bytes) -> None:
    """Validate upload. Security: checks extension, MIME sanity, empty file, and size limit."""
    ext = Path(filename).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type not allowed. Allowed: {', '.join(settings.allowed_extensions)}")
    if content_type in {"application/x-msdownload", "application/x-sh", "application/x-executable"}:
        raise HTTPException(status_code=400, detail="This file content type is not allowed")
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(file_bytes) > settings.max_upload_bytes:
        raise HTTPException(status_code=400, detail=f"File too large. Max {settings.max_upload_mb} MB")
