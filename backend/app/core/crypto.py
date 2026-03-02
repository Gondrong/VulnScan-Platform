"""
Credential encryption/decryption using Fernet (AES-128-CBC).
Key is derived from SECRET_KEY in settings.
"""
import base64
import logging
from cryptography.fernet import Fernet, InvalidToken
from app.core.config import settings

logger = logging.getLogger("vulnscan.crypto")


def _fernet() -> Fernet:
    raw = settings.SECRET_KEY.encode("utf-8")
    key = base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])
    return Fernet(key)


def encrypt_str(s: str) -> str:
    """Encrypt a string using the platform's SECRET_KEY."""
    return _fernet().encrypt(s.encode("utf-8")).decode("utf-8")


def decrypt_str(token: str) -> str:
    """
    Decrypt a Fernet-encrypted string.
    Raises a clear error if SECRET_KEY has changed since encryption.
    """
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError(
            "Cannot decrypt credential — the SECRET_KEY has changed since this "
            "credential was stored. Please delete and re-add the credential "
            "in the Credentials page with the current SECRET_KEY."
        )
    except Exception as e:
        raise ValueError(f"Decryption error: {e}")
