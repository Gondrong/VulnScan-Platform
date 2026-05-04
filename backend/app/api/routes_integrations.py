import json
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.db import models

logger = logging.getLogger("vulnscan.api.integrations")
router = APIRouter(prefix="/integrations", tags=["integrations"])

VALID_PROVIDERS = {"slack", "email", "webhook", "teams"}


class IntegrationSaveRequest(BaseModel):
    enabled: bool
    config: dict  # Dynamic config depending on provider (webhook, email, slack)


@router.get("")
def list_integrations(user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    ws_id = user["ws"]
    rows = (
        db.query(models.Integration)
        .filter(models.Integration.workspace_id == ws_id)
        .all()
    )
    res = []
    for r in rows:
        try:
            cfg = json.loads(r.config_json)
        except Exception:
            cfg = {}
        res.append({
            "id": r.id,
            "provider": r.provider,
            "enabled": r.enabled,
            "config": cfg,
            "created_at": r.created_at,
        })
    return res


@router.post("/{provider}")
def save_integration(
    provider: str,
    body: IntegrationSaveRequest,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")

    ws_id = user["ws"]
    integration = (
        db.query(models.Integration)
        .filter(models.Integration.workspace_id == ws_id, models.Integration.provider == provider)
        .first()
    )

    if not integration:
        integration = models.Integration(
            workspace_id=ws_id,
            provider=provider,
            enabled=body.enabled,
            config_json=json.dumps(body.config),
        )
        db.add(integration)
    else:
        integration.enabled = body.enabled
        integration.config_json = json.dumps(body.config)
        
    db.commit()
    db.refresh(integration)
    return {"id": integration.id, "provider": provider, "status": "saved"}


@router.post("/{provider}/test")
def test_integration(
    provider: str,
    body: Optional[IntegrationSaveRequest] = Body(None),
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    Send a test notification.

    If a body with `config` is supplied, the test uses that (so the user can
    verify their inputs before saving). Otherwise it falls back to the
    currently-saved config for the provider.
    """
    from app.scanner.notifier import dispatch_test_notification

    if provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")

    config: dict | None = None
    source = ""
    if body is not None and isinstance(body.config, dict) and body.config:
        config = body.config
        source = "request"
    else:
        existing = (
            db.query(models.Integration)
            .filter(
                models.Integration.workspace_id == user["ws"],
                models.Integration.provider == provider,
            )
            .first()
        )
        if existing:
            try:
                config = json.loads(existing.config_json)
                source = "saved"
            except Exception:
                config = None

    if not config:
        raise HTTPException(
            status_code=400,
            detail=(
                "No config available for test. Provide one in the request body, "
                "or save the integration first."
            ),
        )

    logger.info("Integration test: provider=%s actor=%s source=%s", provider, user.get("sub", "?"), source)
    success = dispatch_test_notification(provider, config)
    if not success:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Test notification via {provider} did not succeed. "
                "Check the backend logs for the exact error (often: invalid webhook URL, "
                "SMTP auth failure, or unreachable host)."
            ),
        )

    return {"status": "ok", "message": f"Test notification sent via {provider}"}


@router.delete("/{provider}")
def delete_integration(
    provider: str,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Remove a saved integration for the workspace."""
    if provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")

    existing = (
        db.query(models.Integration)
        .filter(
            models.Integration.workspace_id == user["ws"],
            models.Integration.provider == provider,
        )
        .first()
    )
    if not existing:
        raise HTTPException(status_code=404, detail=f"No {provider} integration found")

    db.delete(existing)
    db.commit()
    logger.info("Integration deleted: provider=%s actor=%s", provider, user.get("sub", "?"))
    return {"status": "ok", "provider": provider, "deleted": True}
