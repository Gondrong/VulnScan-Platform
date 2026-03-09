import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_auth
from app.db.session import get_db
from app.db import models

logger = logging.getLogger("vulnscan.api.integrations")
router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationSaveRequest(BaseModel):
    enabled: bool
    config: dict  # Dynamic config depending on provider (webhook, email, slack)


@router.get("")
def list_integrations(claims=Depends(require_auth), db: Session = Depends(get_db)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    ws_id = claims["ws"]
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
def save_integration(provider: str, body: IntegrationSaveRequest, claims=Depends(require_auth), db: Session = Depends(get_db)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")

    valid_providers = {"slack", "email", "webhook"}
    if provider not in valid_providers:
        raise HTTPException(status_code=400, detail="Invalid provider")

    ws_id = claims["ws"]
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
def test_integration(provider: str, body: IntegrationSaveRequest, claims=Depends(require_auth)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")

    from app.scanner.notifier import dispatch_test_notification
    valid_providers = {"slack", "email", "webhook"}
    if provider not in valid_providers:
        raise HTTPException(status_code=400, detail="Invalid provider")

    success = dispatch_test_notification(provider, body.config)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to send test notification via {provider}")
    
    return {"status": "ok", "message": "Test notification sent"}
