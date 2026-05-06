"""
File: config.py
Purpose: Load settings from environment variables.
Security: Secrets are read from .env/environment, not hardcoded in source code.
"""
import base64, os
from pathlib import Path
from dataclasses import dataclass
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")

@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Secure Legal Document Exchange Portal")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./secure_legal_portal.db")
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    file_master_key_base64: str = os.getenv("FILE_MASTER_KEY_BASE64", "")
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "10"))
    allowed_extensions: tuple[str, ...] = tuple(
        x.strip().lower() for x in os.getenv("ALLOWED_EXTENSIONS", ".pdf,.png,.jpg,.jpeg,.txt,.docx,.doc").split(",") if x.strip()
    )

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    def require_jwt_secret(self) -> str:
        """Return JWT secret or fail fast if missing. Security: avoids insecure default signing key."""
        if not self.jwt_secret_key or "replace-with" in self.jwt_secret_key:
            raise RuntimeError("Set JWT_SECRET_KEY in backend/.env before running.")
        return self.jwt_secret_key

    def file_key(self) -> bytes:
        """Decode AES key. Security: requires exactly 32 bytes for AES-256."""
        if not self.file_master_key_base64 or "replace-with" in self.file_master_key_base64:
            raise RuntimeError("Set FILE_MASTER_KEY_BASE64 in backend/.env. Generate with scripts/generate_key.py.")
        key = base64.b64decode(self.file_master_key_base64)
        if len(key) != 32:
            raise RuntimeError("FILE_MASTER_KEY_BASE64 must decode to exactly 32 bytes.")
        return key

settings = Settings()
