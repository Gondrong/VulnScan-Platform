"""
Credential resolution for private-repo clones.

The scan job stores only a `credential_id` in meta_json — never the secret. The
worker re-resolves and decrypts the credential in memory at clone time, so the
plaintext token/key never lands in the database. The same resolver backs the
route's pre-flight check.
"""
from __future__ import annotations

import logging

from app.core.crypto import decrypt_str
from app.db import models
from app.db.session import SessionLocal

logger = logging.getLogger("vulnscan.code_scan.credentials")


def resolve_auth(workspace_id: int, credential_id: int | None) -> dict | None:
    """Return an auth dict {scheme, username, secret, passphrase} for ingest,
    or None if there is no (usable) credential. Never raises."""
    if not credential_id:
        return None
    db = SessionLocal()
    try:
        c = (
            db.query(models.Credential)
            .filter(
                models.Credential.id == credential_id,
                models.Credential.workspace_id == workspace_id,
            )
            .first()
        )
        if not c:
            return None
        stype = (c.secret_type or "password").lower()
        scheme = "ssh" if stype in ("ssh_key", "ssh-key", "sshkey") else "https"
        secret = decrypt_str(c.secret_enc or "") if c.secret_enc else ""
        passphrase = decrypt_str(c.passphrase_enc) if c.passphrase_enc else ""
        return {
            "scheme": scheme,
            "username": c.username or "",
            "secret": secret,
            "passphrase": passphrase,
        }
    except Exception as e:  # noqa: BLE001 — resolution failure → treated as no cred
        logger.warning("Credential %s resolution failed: %s", credential_id, e)
        return None
    finally:
        db.close()
