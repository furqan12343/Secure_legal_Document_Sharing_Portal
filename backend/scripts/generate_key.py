"""
File: generate_key.py
Purpose: Generate a base64 32-byte key for AES-256-GCM file encryption.
Security: Put this value in .env as FILE_MASTER_KEY_BASE64; never commit real keys.
"""
import base64, os
print(base64.b64encode(os.urandom(32)).decode())
