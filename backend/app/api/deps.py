"""
Shared FastAPI dependencies for route handlers.
"""
from fastapi import Depends, HTTPException

from app.core.auth import require_auth
from app.db.session import SessionLocal, get_db  # noqa: F401 - re-exported


def require_role(*roles: str):
    """
    Dependency factory — requires the authenticated user to have one of the given roles.

    Usage:
        @router.post("/admin-only")
        def admin_endpoint(claims=Depends(require_role("admin"))):
            ...
    """
    def _check(claims: dict = Depends(require_auth)) -> dict:
        claim_role = str(claims.get("role", "")).lower()
        allowed = {str(r).lower() for r in roles}
        if claim_role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {list(roles)}",
            )
        return claims
    return _check
