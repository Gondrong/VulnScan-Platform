import os
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
from app.cve.enricher import CveSeverityEnricher

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
                                "Create a scan profile first under Configuration -> Profiles.",
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

        # Progress callback - updates meta_json so frontend can poll
        # Uses a SEPARATE db session to avoid corrupting the main session
        _scan_start = datetime.now(timezone.utc)
        _plugin_log = []

        def _progress(step, total, plugin_id, plugin_name, status):
            elapsed = (datetime.now(timezone.utc) - _scan_start).total_seconds()
            entry = {"plugin_id": plugin_id, "name": plugin_name, "status": status, "t": round(elapsed, 1)}
            # Update log (replace if same plugin, append if new)
            existing = next((i for i, e in enumerate(_plugin_log) if e["plugin_id"] == plugin_id), None)
            if existing is not None:
                _plugin_log[existing] = entry
            else:
                _plugin_log.append(entry)

            progress_json = json.dumps({
                "progress": {
                    "step": step,
                    "total": total,
                    "pct": round((step + (1 if status != "running" else 0)) / max(total, 1) * 100),
                    "current_plugin": plugin_id,
                    "current_name": plugin_name,
                    "status": status,
                    "elapsed": round(elapsed, 1),
                    "plugins": _plugin_log[-20:],
                }
            })

            # Use a separate session so failures don't corrupt the main session
            progress_db = None
            try:
                progress_db = SessionLocal()
                progress_db.query(models.ScanJob).filter(
                    models.ScanJob.id == job_id
                ).update({"meta_json": progress_json})
                progress_db.commit()
            except Exception as exc:
                logger.debug("Progress update failed for job #%d: %s", job_id, exc)
                if progress_db:
                    try:
                        progress_db.rollback()
                    except Exception:
                        pass
            finally:
                if progress_db:
                    try:
                        progress_db.close()
                    except Exception:
                        pass

        try:
            findings = _run_async(scan_target(job.target, profile, ws_id, scan_type, progress_callback=_progress))
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

        # Initialize multi-source CVE enricher (NVD + CVEDetails)
        data_dir = os.environ.get("CVE_DATA_DIR", "/app/data/cve")
        try:
            enricher = CveSeverityEnricher(data_dir)
        except Exception as e:
            logger.warning("CVE enricher init failed: %s (using NVD only)", e)
            enricher = None

        saved_count = 0
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            if f.fingerprint in suppressed:
                continue

            kev = bool(getattr(f, "is_kev", False))
            cvss = getattr(f, "cvss", None)
            confidence = float(getattr(f, "confidence", 1.0) or 1.0)
            exploit_known = kev

            # Enrich CVSS with multi-source data (NVD + CVEDetails)
            cve_id = getattr(f, "cve", None)
            if enricher and cve_id and str(cve_id).startswith("CVE-"):
                enriched_cvss, enriched_conf = enricher.enrich_finding_cvss(cve_id, cvss)
                if enriched_cvss is not None:
                    cvss = enriched_cvss
                    # Use enriched confidence (1.0 if multi-source agrees, 0.95 single)
                    confidence = max(confidence, enriched_conf)

            # Pass plugin original severity so info findings stay info
            plugin_sev = getattr(f, "severity", "") or ""

            risk = compute_risk(
                cvss=cvss, kev=kev, criticality=criticality,
                exploit_known=exploit_known, confidence=confidence,
                plugin_severity=plugin_sev,
            )
            sev = severity_from_score(risk)
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            sla_days = assign_sla_days(sev)

            # Build remediation text with correct SLA using FINAL severity
            remediation_text = getattr(f, "remediation", "") or ""
            if sev != "info":
                sla_policy = (
                    f"[SLA POLICY] This is a {sev.upper()} severity vulnerability "
                    f"with a {sla_days}-day remediation SLA."
                )
                if sev == "critical":
                    sla_policy += (" Prioritize patching immediately. Apply vendor-provided"
                                   " fixes and consider temporary mitigations while permanent"
                                   " fixes are deployed.")
                elif sev == "high":
                    sla_policy += (" Apply available patches promptly, review vendor advisories,"
                                   " and implement compensating controls if immediate patching"
                                   " is not feasible.")
                elif sev == "medium":
                    sla_policy += (" Plan patching during the next maintenance window. Review"
                                   " if compensating controls are already in place.")
                elif sev == "low":
                    sla_policy += (" Address during regular patching cycles. Document any"
                                   " accepted risk if remediation is deferred.")
                if remediation_text:
                    remediation_text = f"{remediation_text}\n\n{sla_policy}"
                else:
                    remediation_text = sla_policy

            comp = map_compliance_by_cve_or_category(
                getattr(f, "cve", None), f.plugin_id, compliance_db
            )

            # Sanitize NUL bytes - PostgreSQL text columns reject \x00
            def _sanitize(s):
                if not s:
                    return s
                if isinstance(s, str):
                    return s.replace("\x00", "")
                return s

            row = models.Finding(
                workspace_id=ws_id,
                job_id=job.id,
                target=job.target,
                plugin_id=f.plugin_id,
                title=_sanitize(f.title),
                severity=sev,
                description=_sanitize(f.description or ""),
                remediation=_sanitize(remediation_text),
                references_json=json.dumps(getattr(f, "references", []) or []),
                evidence=_sanitize(f.evidence or ""),
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

        # Send notifications
        from app.scanner.notifier import (
            send_slack_notification,
            send_webhook_notification,
            send_email_notification,
        )
        integrations = (
            db.query(models.Integration)
            .filter(models.Integration.workspace_id == ws_id, models.Integration.enabled == True)
            .all()
        )
        if integrations:
            crit = sev_counts.get("critical", 0)
            high = sev_counts.get("high", 0)
            med = sev_counts.get("medium", 0)
            low = sev_counts.get("low", 0)
            info = sev_counts.get("info", 0)

            duration_secs = 0
            if job.created_at and job.finished_at:
                duration_secs = max(0, int((job.finished_at - job.created_at).total_seconds()))
            mins, secs = divmod(duration_secs, 60)
            duration_text = f"{mins}m {secs}s" if mins else f"{secs}s"

            risk_level = "INFO"
            if crit > 0:
                risk_level = "CRITICAL"
            elif high > 0:
                risk_level = "HIGH"
            elif med > 0:
                risk_level = "MEDIUM"
            elif low > 0:
                risk_level = "LOW"

            msg = (
                f"VulnScan Job #{job_id} on {job.target} completed in {duration_text}. "
                f"Risk posture: {risk_level}. Findings: {saved_count} "
                f"({crit} Critical, {high} High, {med} Medium, {low} Low, {info} Info)."
            )
            payload = {
                "job_id": job_id,
                "target": job.target,
                "status": "done",
                "findings_total": saved_count,
                "duration_seconds": duration_secs,
                "risk_level": risk_level,
                "severities": sev_counts,
            }

            top_findings = (
                db.query(models.Finding)
                .filter(models.Finding.job_id == job.id)
                .order_by(models.Finding.risk_score.desc(), models.Finding.id.desc())
                .limit(3)
                .all()
            )
            top_findings_text = "\n".join(
                f"- [{(f.severity or 'info').upper()}] {f.title[:90]}"
                for f in top_findings
                if getattr(f, "title", None)
            ) or "- No findings recorded"

            for integ in integrations:
                try:
                    cfg = json.loads(integ.config_json)
                    if integ.provider == "slack":
                        slack_payload = {
                            "text": (
                                f"Scan complete: {job.target} | Job #{job_id} | "
                                f"{saved_count} findings | Risk {risk_level}"
                            ),
                            "blocks": [
                                {
                                    "type": "header",
                                    "text": {"type": "plain_text", "text": "VulnScan Scan Completed", "emoji": True},
                                },
                                {
                                    "type": "section",
                                    "fields": [
                                        {"type": "mrkdwn", "text": f"*Target*\n`{job.target}`"},
                                        {"type": "mrkdwn", "text": f"*Job*\n#{job_id}"},
                                        {"type": "mrkdwn", "text": f"*Type*\n{(job.scan_type or 'internal').upper()}"},
                                        {"type": "mrkdwn", "text": f"*Duration*\n{duration_text}"},
                                        {"type": "mrkdwn", "text": f"*Findings*\n{saved_count}"},
                                        {"type": "mrkdwn", "text": f"*Risk*\n{risk_level}"},
                                    ],
                                },
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": (
                                            "*Severity breakdown*\n"
                                            f"Critical: *{crit}* | High: *{high}* | "
                                            f"Medium: *{med}* | Low: *{low}* | Info: *{info}*"
                                        ),
                                    },
                                },
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"*Top findings*\n{top_findings_text}",
                                    },
                                },
                            ],
                        }

                        dashboard_url = cfg.get("dashboard_url")
                        if dashboard_url:
                            slack_payload["blocks"].append(
                                {
                                    "type": "actions",
                                    "elements": [
                                        {
                                            "type": "button",
                                            "text": {"type": "plain_text", "text": "Open Dashboard", "emoji": True},
                                            "url": dashboard_url,
                                        }
                                    ],
                                }
                            )

                        send_slack_notification(cfg, slack_payload)
                    elif integ.provider == "webhook":
                        send_webhook_notification(cfg, {"event": "scan_done", "data": payload})
                    elif integ.provider == "email":
                        email_body = f"{msg}\n\nTop findings:\n{top_findings_text}"
                        send_email_notification(cfg, f"Scan Complete: {job.target}", email_body)
                except Exception as e:
                    logger.warning("Failed to run integration %s for job #%d: %s", integ.provider, job_id, e)

    except Exception as e:
        tb = traceback.format_exc()
        logger.exception("Unhandled error in run_scan_job #%d: %s", job_id, e)
        try:
            db.rollback()  # Reset corrupted session state
            job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.meta_json = json.dumps({
                    "error": str(e)[:500],
                    "error_type": "unhandled",
                    "error_detail": f"An unexpected error occurred during scan processing.\n\nTechnical detail: {str(e)[:500]}",
                    "traceback": tb[:2000],
                })
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception as inner_e:
            logger.error("Failed to mark job #%d as failed: %s", job_id, inner_e)
            # Last resort - raw SQL update to unstick the job
            try:
                db.rollback()
                db.execute(
                    models.ScanJob.__table__.update()
                    .where(models.ScanJob.id == job_id)
                    .values(
                        status="failed",
                        finished_at=datetime.now(timezone.utc),
                        meta_json=json.dumps({"error": str(e)[:200], "error_type": "crash"}),
                    )
                )
                db.commit()
            except Exception:
                logger.critical("CRITICAL: Job #%d is permanently stuck as running!", job_id)
    finally:
        if neo:
            try:
                neo.close()
            except Exception:
                pass
        db.close()
