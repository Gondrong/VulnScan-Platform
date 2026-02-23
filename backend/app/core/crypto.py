import base64
from cryptography.fernet import Fernet
from app.core.config import settings

def _fernet() -> Fernet:
    raw = settings.SECRET_KEY.encode("utf-8")
    key = base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])
    return Fernet(key)

def encrypt_str(s: str) -> str:
    return _fernet().encrypt(s.encode("utf-8")).decode("utf-8")

def decrypt_str(token: str) -> str:
    return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")