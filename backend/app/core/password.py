"""
Centralized password hashing — bcrypt with automatic SHA256 legacy migration.

Usage:
    from app.core.password import hash_password, verify_password

    hashed = hash_password("my-secret")
    ok     = verify_password("my-secret", hashed)   # True
"""

import hashlib
import bcrypt


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored hash.

    Supports both bcrypt hashes (new) and legacy SHA256 hex digests.
    """
    if stored_hash.startswith("$2"):
        # bcrypt hash
        return bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))
    # Legacy SHA256 — compare and signal caller to re-hash
    return hashlib.sha256(plain.encode("utf-8")).hexdigest() == stored_hash


def needs_rehash(stored_hash: str) -> bool:
    """Return True if the hash is a legacy SHA256 that should be upgraded."""
    return not stored_hash.startswith("$2")
