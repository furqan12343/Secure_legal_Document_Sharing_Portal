"""
File: encryption_service.py
Purpose: AES-256-GCM encryption/decryption and SHA-256 file hashing.
Security: Files are encrypted before storage and decrypted only after authorization.
"""
import hashlib, os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import BASE_DIR, settings

class EncryptionService:
    def __init__(self):
        self.key = settings.file_key()
        self.storage_dir = BASE_DIR / "storage" / "encrypted_files"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def sha256(self, data: bytes) -> str:
        """Hash file bytes. Security: provides integrity evidence for uploaded plaintext."""
        return hashlib.sha256(data).hexdigest()

    def encrypt_file(self, data: bytes, stored_filename: str) -> Path:
        """Encrypt file. Security: AES-GCM with fresh nonce gives confidentiality and tamper detection."""
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.key).encrypt(nonce, data, None)
        path = self.storage_dir / stored_filename
        path.write_bytes(nonce + ciphertext)
        return path

    def decrypt_file(self, path: str | Path) -> bytes:
        """Decrypt file. Security: AES-GCM rejects tampered ciphertext."""
        blob = Path(path).read_bytes()
        return AESGCM(self.key).decrypt(blob[:12], blob[12:], None)
