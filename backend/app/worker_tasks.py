import asyncio
import json
import logging
import traceback
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.compliance.mapper import map_compliance_by_cve_or_category
from app.cve.dataset_loader import load_json
from app.db import models
from app.db.session import SessionLocal
from app.graph.neo4j_client import Neo4jClient
from app.risk.cvss_engine import severity_from_score
from app.risk.risk_engine import compute_risk
from app.risk.sla_engine import assign_sla_days
from app.scanner.engine import scan_target

logger = logging.getLogger("vulnscan.worker")


def _load_compliance(ws_id: int, db: Session) -> list[dict]:
    ds = (
        db.query(models.CveDataset)
        .filter(
            models.CveDataset.workspace_id == ws_id,
            models.CveDataset.kind == "compliance_map",
            models.CveDataset.enabled == True,
        )
        .all()
    )
    rows = []
    for d in ds:
        try:
            rows += load_json(d.path)
        except Exception as e:
            logger.warning("Failed to load compliance dataset %s: %s", d.path, e)
    return rows


def _run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("Loop is closed")
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=300)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def run_scan_job(job_id: int) -> None:
    db: Session = SessionLocal()
    neo = None
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job:
            logger.error("Job #%d not found", job_id)
            return

        ws_id = job.workspace_id
        prof = (
            db.query(models.Profile)
            .filter(
                models.Profile.id == job.profile_id,
                models.Profile.workspace_id == ws_id,
            )
            .first()
        )
        if not prof:
            job.status = "failed"
            job.meta_json = json.dumps({
                "error": "Profile not found",
                "error_type": "configuration",
                "error_detail": f"Profile ID {job.profile_id} does not exist in workspace {ws_id}. "
                                "Create a scan profile first under Configuration → Profiles.",
            })
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        job.status = "running"
        db.commit()
        logger.info("Starting scan job #%d target=%s type=%s", job_id, job.target, job.scan_type)

        profile = {
            "plugin_selection_json": prof.plugin_selection_json,
            "options_json": prof.options_json,
        }

        # Pass scan_type to engine so external scans bypass allowlist
        scan_type = job.scan_type or "internal"

        try:
            findings = _run_async(scan_target(job.target, profile, ws_id, scan_type))
        except Exception as e:
            tb = traceback.format_exc()
            logger.exception("scan_target failed for job #%d: %s", job_id, e)
            job.status = "failed"
            job.meta_json = json.dumps({
                "error": str(e),
                "error_type": "scan_engine",
                "error_detail": (
                    f"The scan engine encountered an error while scanning '{job.target}'. "
                    f"This may be caused by: network unreachable, DNS resolution failure, "
                    f"target refused connection, or a plugin crash.\n\n"
                    f"Technical detail: {str(e)[:500]}"
                ),
                "traceback": tb[:2000],
            })
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        suppressed = {
            s.fingerprint
            for s in db.query(models.SuppressedFinding)
            .filter(models.SuppressedFinding.workspace_id == ws_id)
            .all()
        }

        compliance_db = _load_compliance(ws_id, db)

        try:
            opt = json.loads(prof.options_json or "{}")
        except Exception:
            opt = {}
        criticality = int((opt.get("asset") or {}).get("criticality", 2))

        try:
            neo = Neo4jClient()
        except Exception as e:
            logger.warning("Neo4j unavailable: %s", e)

        saved_count = 0
        for f in findings:
            if f.fingerprint in suppressed:
                continue

            kev = bool(getattr(f, "is_kev", False))
            cvss = getattr(f, "cvss", None)
            confidence = float(getattr(f, "confidence", 1.0) or 1.0)
            exploit_known = kev

            risk = compute_risk(
                cvss=cvss, kev=kev, criticality=criticality,
                exploit_known=exploit_known, confidence=confidence,
            )
            sev = severity_from_score(risk)
            sla_days = assign_sla_days(sev)

            comp = map_compliance_by_cve_or_category(
                getattr(f, "cve", None), f.plugin_id, compliance_db
            )

            row = models.Finding(
                workspace_id=ws_id,
                job_id=job.id,
                target=job.target,
                plugin_id=f.plugin_id,
                title=f.title,
                severity=sev,
                description=f.description or "",
                remediation=getattr(f, "remediation", "") or "",
                references_json=json.dumps(getattr(f, "references", []) or []),
                evidence=f.evidence or "",
                fingerprint=f.fingerprint,
                cvss_base=cvss,
                risk_score=risk,
                confidence=confidence,
                sla_days=sla_days,
                compliance_json=json.dumps(comp) if comp else None,
                is_kev=kev,
            )
            db.add(row)
            saved_count += 1

            if neo:
                cve = getattr(f, "cve", None)
                if cve and str(cve).startswith("CVE-"):
                    try:
                        neo.upsert_finding(ws_id, job.target, f.plugin_id, cve, risk)
                    except Exception as e:
                        logger.debug("Neo4j upsert failed: %s", e)

        db.commit()
        logger.info("Job #%d done: %d findings saved (total=%d)", job_id, saved_count, len(findings))

        job.status = "done"
        job.finished_at = datetime.now(timezone.utc)
        job.meta_json = json.dumps(
            {"findings_total": len(findings), "findings_saved": saved_count}
        )
        db.commit()

    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("Unhandled error in run_scan_job #%d: %s", job_id, e)
        try:
            job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.meta_json = json.dumps({
                    "error": str(e),
                    "error_type": "unhandled",
                    "error_detail": f"An unexpected error occurred during scan processing.\n\nTechnical detail: {str(e)[:500]}",
                    "traceback": tb[:2000],
                })
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        if neo:
            try:
                neo.close()
            except Exception:
                pass
        db.close()
