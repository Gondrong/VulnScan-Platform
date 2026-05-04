"""
API Scanner Routes — endpoints for launching API-specific security scans.
Accepts OpenAPI/Swagger/Postman specs or manual endpoint definitions.
"""
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import redis
from rq import Queue
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models

logger = logging.getLogger("vulnscan.api.api_scanner")
router = APIRouter(prefix="/scan/api-scanner", tags=["api-scanner"])

# Hard caps on spec ingestion to keep workers safe
_MAX_SPEC_BYTES = 5 * 1024 * 1024  # 5 MB
_FETCH_TIMEOUT_SECONDS = 10


def _safe_fetch_spec(url: str, max_bytes: int = _MAX_SPEC_BYTES) -> str:
    """
    Fetch a remote API spec while blocking SSRF and oversize responses.

    Rejects:
      • non-http(s) schemes
      • hostnames resolving to private / loopback / link-local /
        cloud-metadata addresses
      • bodies exceeding `max_bytes`
    """
    import urllib.request

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "spec_url must use http or https")
    if not parsed.hostname:
        raise HTTPException(400, "spec_url has no hostname")

    # Resolve and reject private / loopback / link-local / metadata
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        raise HTTPException(400, f"Could not resolve spec_url host: {e}")
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
                f"spec_url resolves to a blocked address ({addr}). "
                "Private, loopback, link-local, and metadata IPs are not allowed."
            )

    req = urllib.request.Request(url, headers={"User-Agent": "VulnScan/2.1"})
    try:
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT_SECONDS) as resp:
            chunks = []
            read = 0
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > max_bytes:
                    raise HTTPException(
                        413,
                        f"Spec exceeds {max_bytes // 1024} KB limit",
                    )
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="ignore")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Could not fetch spec from URL: {e}")


async def _read_spec_file(spec_file: UploadFile) -> str:
    """Read an uploaded spec file with a hard size cap."""
    data = await spec_file.read()
    if len(data) > _MAX_SPEC_BYTES:
        raise HTTPException(
            413,
            f"Uploaded spec exceeds {_MAX_SPEC_BYTES // 1024} KB limit",
        )
    return data.decode("utf-8", errors="ignore")


@router.post("/parse")
async def parse_spec(
    spec_file: UploadFile = File(None),
    spec_url: str = Form(""),
    user=Depends(require_role("admin", "analyst")),
):
    """
    Parse an API spec and return the list of endpoints (preview mode).
    Does NOT start a scan — just shows what was parsed.
    """
    from app.scanner.plugins.api_scanner.spec_parser import parse, endpoints_summary

    raw = ""
    if spec_file:
        raw = await _read_spec_file(spec_file)
    elif spec_url:
        raw = _safe_fetch_spec(spec_url)
    else:
        raise HTTPException(400, "Provide either a spec file or spec_url")

    try:
        endpoints = parse(raw)
    except Exception as e:
        raise HTTPException(400, f"Failed to parse spec: {e}")

    summary = endpoints_summary(endpoints)

    return {
        "endpoints": [
            {
                "path": ep.path,
                "method": ep.method,
                "parameters": [{"name": p.name, "location": p.location, "type": p.param_type, "required": p.required} for p in ep.parameters],
                "content_types": ep.content_types,
                "auth_schemes": ep.auth_schemes,
                "summary": ep.summary,
                "tags": ep.tags,
            }
            for ep in endpoints
        ],
        "summary": summary,
    }


@router.post("/jobs")
async def create_api_scan_job(
    spec_file: UploadFile = File(None),
    config_json: str = Form(...),
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Create an API scanner job.

    config_json: {
        "base_url": "https://api.target.com",
        "auth": {"type": "bearer", "token": "..."},
        "checks": ["sqli", "ssti", "xxe", "ssrf", "xss", "cmdi", "code_injection", "graphql", "config_checks", "jwt_checks"],
        "max_concurrent": 5,
        "timeout": 10,
        "spec_url": "https://api.target.com/openapi.json",
        "manual_endpoints": [{"path": "/api/users", "method": "GET"}]
    }
    """
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError:
        raise HTTPException(400, "config_json is not valid JSON")

    base_url = config.get("base_url", "")
    if not base_url:
        raise HTTPException(400, "base_url is required in config")

    # Parse spec if provided (with size cap + SSRF guard)
    spec_raw = None
    if spec_file:
        spec_raw = await _read_spec_file(spec_file)
        config["spec_data"] = spec_raw
    elif config.get("spec_url"):
        spec_raw = _safe_fetch_spec(config["spec_url"])
        config["spec_data"] = spec_raw

    # Validate checks
    valid_checks = {
        "sqli", "cmdi", "ssti", "xss", "xxe", "ssrf", "code_injection",
        "graphql", "config_checks", "jwt_checks",
        "bola", "mass_assignment", "excessive_data", "type_confusion",
        "spec_hygiene",
    }
    requested_checks = set(config.get("checks", list(valid_checks)))
    invalid = requested_checks - valid_checks
    if invalid:
        raise HTTPException(400, f"Invalid checks: {invalid}. Valid: {', '.join(sorted(valid_checks))}")

    # Create scan job
    job = models.ScanJob(
        workspace_id=user["ws"],
        target=base_url,
        profile_id=None,
        status="queued",
        scan_type="api",
        meta_json=json.dumps({
            "api_scanner_config": config,
            "checks": list(requested_checks),
            "spec_provided": bool(spec_raw),
            "manual_endpoints": len(config.get("manual_endpoints", [])),
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Enqueue
    try:
        redis_conn = redis.from_url(settings.REDIS_URL)
        q = Queue("scans", connection=redis_conn)
        from app.worker_tasks import run_scan_job
        q.enqueue(run_scan_job, job.id,
                  job_timeout=settings.SCAN_BUDGET_SECONDS + 300)
        logger.info("API scan job #%d queued: target=%s checks=%s", job.id, base_url, requested_checks)
    except Exception as e:
        job.status = "failed"
        job.meta_json = json.dumps({"error": str(e)})
        db.commit()
        raise HTTPException(503, f"Could not enqueue job: {e}")

    return {
        "id": job.id,
        "target": base_url,
        "status": "queued",
        "scan_type": "api",
        "checks": list(requested_checks),
    }


@router.get("/checks")
def list_available_checks(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Return all available API scanner check categories."""
    return {
        "checks": [
            {"id": "config_checks", "name": "Configuration Checks", "description": "Missing auth, CORS, methods, errors, rate limit, exposed docs", "category": "passive"},
            {"id": "spec_hygiene", "name": "API Spec Hygiene", "description": "Passive spec analysis: missing auth, wildcard CORS, secrets in examples, plain HTTP", "category": "passive"},
            {"id": "sqli", "name": "SQL Injection", "description": "Error-based, boolean-blind, time-blind, UNION, NoSQL", "category": "injection"},
            {"id": "cmdi", "name": "Command Injection", "description": "In-band, blind time, Windows/Linux, header injection", "category": "injection"},
            {"id": "ssti", "name": "SSTI", "description": "Jinja2, Twig, Freemarker, Pebble, Mako, Velocity", "category": "injection"},
            {"id": "xss", "name": "Cross-Site Scripting", "description": "Reflected, context-aware, WAF bypass, polyglot", "category": "injection"},
            {"id": "xxe", "name": "XML External Entity", "description": "File read, blind XXE, content-type override", "category": "injection"},
            {"id": "ssrf", "name": "SSRF", "description": "Cloud metadata (AWS/GCP/Azure), internal probing, IP bypass", "category": "injection"},
            {"id": "code_injection", "name": "Code Injection", "description": "Python/PHP/Node.js/Ruby eval detection", "category": "injection"},
            {"id": "graphql", "name": "GraphQL Security", "description": "Introspection, batch abuse, depth attack, field suggestions", "category": "graphql"},
            {"id": "jwt_checks", "name": "JWT Security", "description": "alg:none bypass, weak secrets, missing claims", "category": "auth"},
            {"id": "bola", "name": "Broken Object-Level Authorization", "description": "OWASP API1 — IDOR via two-identity comparison or ID enumeration", "category": "auth"},
            {"id": "mass_assignment", "name": "Mass Assignment / BOPLA", "description": "OWASP API3 — server accepts undeclared properties (is_admin, role, balance)", "category": "auth"},
            {"id": "excessive_data", "name": "Excessive Data Exposure", "description": "OWASP API3 — responses leak credentials, PII, or fields beyond the schema", "category": "data"},
            {"id": "type_confusion", "name": "Type Confusion / Parameter Pollution", "description": "Wrong-type values trigger 5xx or divergent responses (NoSQL operator injection precursor)", "category": "injection"},
        ],
    }
