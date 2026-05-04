"""
Web Authentication helper routes:

  POST /scan/web-auth/inspect     — fetch a login page and return its forms
  POST /scan/web-auth/test-login  — try the configured auth flow once,
                                    return success/cookies/error
"""
import ipaddress
import logging
import socket
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role

logger = logging.getLogger("vulnscan.api.web_auth")
router = APIRouter(prefix="/scan/web-auth", tags=["web-auth"])


class InspectRequest(BaseModel):
    login_url: str = Field(..., min_length=1, max_length=2048)


def _ssrf_guard(url: str) -> None:
    """Reject URLs that point at private / loopback / metadata addresses."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "login_url must use http or https")
    if not parsed.hostname:
        raise HTTPException(400, "login_url has no hostname")

    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        raise HTTPException(400, f"Could not resolve login_url host: {e}")

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise HTTPException(
                400,
                f"login_url resolves to a blocked address ({addr}). "
                "Private, loopback, link-local, and metadata IPs are not allowed.",
            )


@router.post("/inspect")
async def inspect_login(
    body: InspectRequest,
    user=Depends(require_role("admin", "analyst")),
):
    """
    Fetch a login page and return its forms so the Profile UI can pre-fill
    field-name dropdowns (username field, password field, CSRF token).

    Returns the same shape regardless of success/failure — `error` is set
    when the page could not be fetched. SSRF guard rejects internal hosts.
    """
    from app.scanner.login_inspector import inspect_login_page

    url = body.login_url.strip()
    _ssrf_guard(url)

    logger.info("Inspect login: actor=%s url=%s", user.get("sub", "?"), url[:120])
    result = await inspect_login_page(url)
    return result.to_dict()


# ─── Test login ────────────────────────────────────────────────────────────

class TestLoginRequest(BaseModel):
    web_auth: dict = Field(..., description="Same shape as scan job's web_auth block")
    base_url: str  = Field(..., min_length=1, max_length=2048,
                           description="Scan target — used as base for relative login_url")


@router.post("/test-login")
async def test_login(
    body: TestLoginRequest,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Run the configured authentication flow ONCE against the target and
    return whether it worked. Lets the user verify credentials before
    kicking off a long scan.

    Resolves credential_id (if present) from the encrypted Credentials
    store the same way the web.auth scan plugin does.
    """
    from app.scanner.auth_session import establish_session
    from app.core.crypto import decrypt_str
    from app.db import models

    base_url = body.base_url.strip()
    _ssrf_guard(base_url)

    config = dict(body.web_auth or {})
    if not config.get("type"):
        raise HTTPException(400, "web_auth.type is required")

    # Resolve credential_id → username/password (or token)
    cred_id = config.pop("credential_id", None)
    if cred_id:
        cred = (
            db.query(models.Credential)
            .filter(
                models.Credential.id == int(cred_id),
                models.Credential.workspace_id == user["ws"],
            )
            .first()
        )
        if not cred:
            raise HTTPException(404, f"Credential #{cred_id} not found in workspace")
        try:
            secret = decrypt_str(cred.secret_enc or "")
        except Exception as e:
            raise HTTPException(500, f"Could not decrypt credential #{cred_id}: {e}")
        if (config.get("type") or "").lower() == "bearer":
            config.setdefault("token", secret)
        else:
            config.setdefault("username", cred.username or "")
            config.setdefault("password", secret)

    # If login_url is relative, the base_url provides the origin
    if config.get("type") == "form":
        login_url = (config.get("login_url") or "").strip()
        if login_url and not login_url.startswith("http"):
            from urllib.parse import urljoin
            config["login_url"] = urljoin(base_url, login_url)
        action_url = (config.get("action_url") or "").strip()
        if action_url and not action_url.startswith("http"):
            from urllib.parse import urljoin
            config["action_url"] = urljoin(base_url, action_url)

    sess = await establish_session(config, base_url=base_url, timeout=15.0)

    return {
        "success":         sess.success,
        "method":          sess.method,
        "cookies_count":   len(sess.cookies),
        "headers_count":   len(sess.headers),
        "evidence":        sess.evidence,
        "error":           sess.error,
        # Don't return raw cookie/header values — they may include session tokens.
        "cookie_names":    list(sess.cookies.keys()),
        "header_names":    list(sess.headers.keys()),
    }
