import os
import asyncio
import json
import logging
import re
import traceback
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.compliance.mapper import map_compliance_by_cve_or_category
from app.cve.dataset_loader import load_json
from app.db import models
from app.db.session import SessionLocal
from app.graph.neo4j_client import Neo4jClient
from app.risk.cvss_engine import severity_from_score, cvss_baseline_from_severity
from app.risk.risk_engine import compute_risk
from app.risk.sla_engine import assign_sla_days
from app.scanner.engine import scan_target
from app.cve.enricher import CveSeverityEnricher

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("vulnscan.worker")


def _evidence_meta(evidence: str | None) -> dict[str, str]:
    meta: dict[str, str] = {}
    for key, value in re.findall(r"\b([a-z_]+)=((?:\"[^\"]*\")|\S+)", evidence or "", re.I):
        meta[key.lower()] = str(value).strip('"')
    return meta


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


def _notify_scan_failed(db: Session, ws_id: int, job_id: int, target: str, error: str, error_type: str) -> None:
    """Send scan_failed notifications to enabled integrations."""
    try:
        from app.scanner.notifier import (
            send_slack_notification,
            send_teams_notification,
            send_webhook_notification,
            send_email_notification,
            should_notify,
        )
        from app.api.routes_settings import _get_setting, DEFAULT_NOTIFICATION_PREFS

        integrations = (
            db.query(models.Integration)
            .filter(models.Integration.workspace_id == ws_id, models.Integration.enabled == True)
            .all()
        )
        if not integrations:
            return

        notif_prefs = _get_setting(db, ws_id, "notification_preferences", DEFAULT_NOTIFICATION_PREFS)

        msg = f"VulnScan Job #{job_id} on {target} FAILED. Type: {error_type}. Error: {error[:200]}"
        payload = {
            "event": "scan_failed",
            "data": {
                "job_id": job_id,
                "target": target,
                "status": "failed",
                "error": error[:500],
                "error_type": error_type,
            },
        }

        for integ in integrations:
            try:
                if not should_notify(notif_prefs, ["scan_failed"], integ.provider):
                    continue
                cfg = json.loads(integ.config_json)
                if integ.provider == "slack":
                    send_slack_notification(cfg, {
                        "text": msg,
                        "blocks": [
                            {"type": "header", "text": {"type": "plain_text", "text": "VulnScan Scan Failed"}},
                            {"type": "section", "fields": [
                                {"type": "mrkdwn", "text": f"*Target*\n`{target}`"},
                                {"type": "mrkdwn", "text": f"*Job*\n#{job_id}"},
                                {"type": "mrkdwn", "text": f"*Error type*\n{error_type}"},
                            ]},
                            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Error*\n```{error[:300]}```"}},
                        ],
                    })
                elif integ.provider == "teams":
                    send_teams_notification(cfg, {
                        "title": "VulnScan Scan Failed",
                        "text": msg,
                        "Target": target,
                        "Job": f"#{job_id}",
                        "Error type": error_type,
                        "Error": error[:300],
                    })
                elif integ.provider == "webhook":
                    send_webhook_notification(cfg, payload)
                elif integ.provider == "email":
                    send_email_notification(cfg, f"Scan Failed: {target}", msg)
            except Exception as e:
                logger.warning("Failed to send scan_failed notification via %s: %s", integ.provider, e)
    except Exception as e:
        logger.warning("_notify_scan_failed error: %s", e)


def run_scan_job(job_id: int) -> None:
    db: Session = SessionLocal()
    neo = None
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job:
            logger.error("Job #%d not found", job_id)
            return

        ws_id = job.workspace_id
        scan_type = job.scan_type or "internal"

        # API Scanner & IaC Scanner jobs don't need a profile — handle separately
        if scan_type in ("api", "iac"):
            job.status = "running"
            db.commit()
            logger.info("Starting %s scan job #%d target=%s", scan_type, job_id, job.target)
            prof = None
        else:
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
                _notify_scan_failed(db, ws_id, job_id, job.target, "Profile not found", "configuration")
                return

            job.status = "running"
            db.commit()
            logger.info("Starting scan job #%d target=%s type=%s", job_id, job.target, scan_type)

        if prof:
            profile = {
                "plugin_selection_json": prof.plugin_selection_json,
                "options_json": prof.options_json,
            }
        else:
            profile = {"plugin_selection_json": "{}", "options_json": "{}"}

        # ── Per-job Web Authentication override ──────────────────────────────
        # The New Scan dialog can attach a `web_auth` block to the job. It
        # overrides any profile-level web_auth and auto-enables the web.auth
        # plugin so the user doesn't have to remember to toggle it.
        try:
            _job_meta_in = json.loads(job.meta_json or "{}")
        except Exception:
            _job_meta_in = {}
        _job_web_auth = _job_meta_in.get("web_auth") if isinstance(_job_meta_in, dict) else None
        if _job_web_auth and isinstance(_job_web_auth, dict) and _job_web_auth.get("type"):
            try:
                _opts = json.loads(profile["options_json"] or "{}")
            except Exception:
                _opts = {}
            _opts["web_auth"] = _job_web_auth
            profile["options_json"] = json.dumps(_opts)

            try:
                _sel = json.loads(profile["plugin_selection_json"] or "{}")
            except Exception:
                _sel = {}
            _sel["web.auth"] = True
            profile["plugin_selection_json"] = json.dumps(_sel)

            logger.info(
                "Job #%d: applied per-job web_auth override (type=%s, credential_id=%s)",
                job_id, _job_web_auth.get("type"), _job_web_auth.get("credential_id"),
            )

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
            if scan_type == "api":
                # API Scanner — standalone mode
                api_config = json.loads(job.meta_json or "{}").get("api_scanner_config", {})
                from app.scanner.plugins.api_scanner import Check as ApiScannerCheck
                api_checker = ApiScannerCheck()
                findings = _run_async(api_checker.run_standalone(api_config, progress_callback=_progress))
            elif scan_type == "iac":
                # IaC Scanner — standalone mode (file/archive driven)
                iac_config = json.loads(job.meta_json or "{}").get("iac_scanner_config", {})
                from app.scanner.plugins.iac_scanner import Check as IacScannerCheck
                iac_checker = IacScannerCheck()
                findings = _run_async(iac_checker.run_standalone(iac_config, progress_callback=_progress))
            else:
                findings = _run_async(scan_target(job.target, profile, ws_id, scan_type, progress_callback=_progress, job_id=job.id))
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
            _notify_scan_failed(db, ws_id, job_id, job.target, str(e), "scan_engine")
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

        # ── Confidence threshold: drop findings below this confidence ──────
        # Default 0.20 filters out:
        #   - likely_patched   (0.10) — distro backport detected
        #   - local-only pkgs  (0.15) — not network-reachable
        # But keeps:
        #   - probe_negative   (0.20) — probe ran, negative result
        #   - provisional      (0.35) — network-facing version match
        #   - validated        (1.00) — actively confirmed
        # Configurable per-profile via options_json: {"filtering": {"min_confidence": 0.20}}
        filtering_opts = opt.get("filtering") or {}
        min_confidence = float(filtering_opts.get("min_confidence", 0.20))
        # Which validation states should always be dropped regardless of confidence
        drop_states = set(filtering_opts.get("drop_states", ["likely_patched"]))
        # Whether to drop local-only (non-network) package findings
        drop_local_only = bool(filtering_opts.get("drop_local_only", True))

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

        # Collect validated findings so we can skip lower-confidence duplicates
        validated_keys = set()
        for f in findings:
            meta = _evidence_meta(getattr(f, "evidence", ""))
            validation_state = meta.get("validation_state", "").lower()
            cve_id = getattr(f, "cve", None)
            affected = getattr(f, "affected", "") or job.target
            if validation_state == "validated" and cve_id:
                validated_keys.add((affected, cve_id))

        saved_count = 0
        dropped_count = 0
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            if f.fingerprint in suppressed:
                continue

            meta = _evidence_meta(getattr(f, "evidence", ""))
            validation_state = meta.get("validation_state", "").lower()
            validation_method = meta.get("validation_method", "").lower()
            affected = getattr(f, "affected", "") or job.target

            # Skip lower-confidence findings when a validated finding exists for the same CVE+target
            _lower_confidence_states = {"provisional", "likely_patched", "likely_not_exploitable", "probe_negative"}
            if (
                validation_state in _lower_confidence_states
                and getattr(f, "cve", None)
                and (affected, getattr(f, "cve", None)) in validated_keys
            ):
                logger.info(
                    "Skipping %s duplicate for %s %s from %s",
                    validation_state,
                    affected,
                    getattr(f, "cve", None),
                    f.plugin_id,
                )
                continue

            kev = bool(getattr(f, "is_kev", False))
            cvss = getattr(f, "cvss", None)
            confidence = float(getattr(f, "confidence", 1.0) or 1.0)
            exploit_known = kev

            # Confidence caps by validation state:
            #   validated             → uncapped (default)
            #   provisional           → ≤ 0.35 (version-only match)
            #   likely_patched        → ≤ 0.10 (distro backport detected)
            #   likely_not_exploitable → ≤ 0.15 (OWASP tested, found nothing)
            #   probe_negative        → ≤ 0.20 (endpoint probe ran, negative result)
            if validation_state == "likely_patched":
                confidence = min(confidence, 0.10)
            elif validation_state == "likely_not_exploitable":
                confidence = min(confidence, 0.15)
            elif validation_state == "probe_negative":
                confidence = min(confidence, 0.20)
            elif validation_state == "provisional":
                confidence = min(confidence, 0.35)

            # Enrich CVSS with multi-source data (NVD + CVEDetails)
            cve_id = getattr(f, "cve", None)
            if enricher and cve_id and str(cve_id).startswith("CVE-"):
                enriched_cvss, enriched_conf = enricher.enrich_finding_cvss(cve_id, cvss)
                if enriched_cvss is not None:
                    cvss = enriched_cvss
                    # Use enriched confidence, but respect validation state caps
                    _cap_map = {
                        "likely_patched": 0.10,
                        "likely_not_exploitable": 0.15,
                        "probe_negative": 0.20,
                        "provisional": 0.35,
                    }
                    cap = _cap_map.get(validation_state)
                    if cap is not None:
                        confidence = min(max(confidence, enriched_conf), cap)
                    else:
                        confidence = max(confidence, enriched_conf)

            # Fallback: derive a baseline CVSS from severity for findings without
            # a CVE-backed score (e.g. OWASP scanner findings like "Exposed debug
            # console" — there's no CVE for it but the severity is meaningful).
            if cvss is None:
                cvss = cvss_baseline_from_severity(getattr(f, "severity", None))

            # ── Drop low-confidence / invalid findings ────────────────────
            # 1. Always drop findings whose validation_state is in drop_states
            if validation_state in drop_states:
                logger.info(
                    "Dropping %s finding: %s (state=%s, confidence=%.2f)",
                    validation_state, f.title, validation_state, confidence,
                )
                dropped_count += 1
                continue

            # 2. Drop local-only (non-network) package findings
            is_local_only = (
                "network_facing=no" in (f.evidence or "")
                and validation_method == "package_version_match_local_only"
            )
            if drop_local_only and is_local_only:
                logger.info(
                    "Dropping local-only finding: %s (confidence=%.2f)",
                    f.title, confidence,
                )
                dropped_count += 1
                continue

            # 3. Drop any remaining findings below the minimum confidence threshold
            #    (but never drop info-severity findings — they're informational, not vulns)
            plugin_sev_raw = (getattr(f, "severity", "") or "").lower()
            if confidence < min_confidence and plugin_sev_raw != "info":
                logger.info(
                    "Dropping low-confidence finding: %s (confidence=%.2f < threshold=%.2f)",
                    f.title, confidence, min_confidence,
                )
                dropped_count += 1
                continue

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
            if validation_state == "likely_patched":
                validation_note = (
                    "[LIKELY PATCHED] This package version contains a distro-specific patch suffix "
                    "indicating a backported security fix. The upstream version appears vulnerable, "
                    "but the distro vendor has likely applied the relevant patches. "
                    "Verify with: apt-cache policy <package> or rpm -q --changelog <package>."
                )
                remediation_text = f"{validation_note}\n\n{remediation_text}" if remediation_text else validation_note
            elif validation_state == "likely_not_exploitable":
                validation_note = (
                    "[LOW CONFIDENCE] Active OWASP scanning tested the relevant vulnerability category "
                    "and found no evidence of exploitation on this target. The version correlation suggests "
                    "a potential vulnerability, but runtime testing did not confirm it. "
                    f"Method: {validation_method or 'owasp_cross_reference'}."
                )
                remediation_text = f"{validation_note}\n\n{remediation_text}" if remediation_text else validation_note
            elif validation_state == "probe_negative":
                validation_note = (
                    "[PROBE NEGATIVE] An endpoint probe tested for the specific attack surface "
                    "associated with this CVE but did not find it accessible. The vulnerability "
                    "may not be exploitable in the current configuration. "
                    f"Method: {validation_method or 'endpoint_probe'}."
                )
                remediation_text = f"{validation_note}\n\n{remediation_text}" if remediation_text else validation_note
            elif validation_state == "provisional":
                validation_note = (
                    "[VALIDATION] This is a provisional version correlation, not a confirmed vulnerable condition. "
                    "Validate against vendor release advisories, package build provenance, runtime exposure, and feature/config state "
                    f"before treating it as exploitable. Method: {validation_method or 'version correlation'}."
                )
                remediation_text = f"{validation_note}\n\n{remediation_text}" if remediation_text else validation_note
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
                if cve and not str(cve).startswith("CVE-"):
                    cve = None
                compliance_ids = comp if comp else None
                try:
                    neo.upsert_finding(
                        workspace_id=ws_id,
                        target=job.target,
                        plugin_id=f.plugin_id,
                        cve=cve,
                        risk_score=risk,
                        fingerprint=getattr(f, "fingerprint", ""),
                        title=getattr(f, "title", ""),
                        severity=severity,
                        compliance_ids=compliance_ids,
                    )
                except Exception as e:
                    logger.debug("Neo4j upsert failed: %s", e)

        db.commit()
        logger.info(
            "Job #%d done: %d findings saved, %d dropped (total=%d, threshold=%.2f)",
            job_id, saved_count, dropped_count, len(findings), min_confidence,
        )

        job.status = "done"
        job.finished_at = datetime.now(timezone.utc)
        job.meta_json = json.dumps(
            {
                "findings_total": len(findings),
                "findings_saved": saved_count,
                "findings_dropped": dropped_count,
                "min_confidence_threshold": min_confidence,
            }
        )
        db.commit()

        # Send notifications
        from app.scanner.notifier import (
            send_slack_notification,
            send_teams_notification,
            send_webhook_notification,
            send_email_notification,
            should_notify,
        )
        from app.api.routes_settings import _get_setting, DEFAULT_NOTIFICATION_PREFS
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
                .limit(10)
                .all()
            )
            top_findings_text = "\n".join(
                f"- [{(f.severity or 'info').upper()}] {f.title[:90]}"
                for f in top_findings
                if getattr(f, "title", None)
            ) or "- No findings recorded"

            # Determine which event types this scan result triggers
            triggered_events = ["scan_completed"]
            if crit > 0:
                triggered_events.append("critical_finding")
            has_kev = any(getattr(f, "is_kev", False) for f in top_findings)
            if has_kev:
                triggered_events.append("cisa_kev_match")

            # Load notification preferences
            notif_prefs = _get_setting(db, ws_id, "notification_preferences", DEFAULT_NOTIFICATION_PREFS)

            for integ in integrations:
                try:
                    cfg = json.loads(integ.config_json)

                    # Check preferences — skip if no triggered event is enabled for this provider
                    if not should_notify(notif_prefs, triggered_events, integ.provider):
                        logger.info("Notification skipped for %s (preferences)", integ.provider)
                        continue
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
                    elif integ.provider == "teams":
                        teams_payload = {
                            "title": "VulnScan Scan Completed",
                            "text": msg,
                            "Target": job.target,
                            "Job": f"#{job_id}",
                            "Type": (job.scan_type or "internal").upper(),
                            "Duration": duration_text,
                            "Findings": str(saved_count),
                            "Risk": risk_level,
                            "Critical": str(crit),
                            "High": str(high),
                            "Medium": str(med),
                            "Low": str(low),
                        }
                        send_teams_notification(cfg, teams_payload)
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
                _notify_scan_failed(db, job.workspace_id, job_id, job.target, str(e)[:500], "unhandled")
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
        # ── Ephemeral credential cleanup ──────────────────────────────────────
        # If the scan job carried web_auth_credential_ephemeral=True, delete
        # the linked credential now (regardless of scan outcome). This is the
        # "auto-delete after scan" feature for one-off pentest workflows.
        try:
            _cleanup_ephemeral_credential(db, job_id)
        except Exception as _eph_err:
            logger.warning("Ephemeral credential cleanup failed for job #%d: %s", job_id, _eph_err)

        if neo:
            try:
                neo.close()
            except Exception:
                pass
        db.close()


def _cleanup_ephemeral_credential(db: Session, job_id: int) -> None:
    """
    Delete the credential referenced by job.meta_json['web_auth']['credential_id']
    when meta_json['web_auth_credential_ephemeral'] is True. Best-effort —
    failures are logged but never raised.
    """
    job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
    if not job or not job.meta_json:
        return
    try:
        meta = json.loads(job.meta_json)
    except Exception:
        return
    if not isinstance(meta, dict):
        return
    if not meta.get("web_auth_credential_ephemeral"):
        return
    web_auth = meta.get("web_auth") or {}
    cred_id = web_auth.get("credential_id")
    if not cred_id:
        return

    cred = (
        db.query(models.Credential)
        .filter(
            models.Credential.id == int(cred_id),
            models.Credential.workspace_id == job.workspace_id,
        )
        .first()
    )
    if not cred:
        logger.info("Ephemeral cleanup: credential #%s already removed (job #%d)", cred_id, job_id)
        return

    cred_name = cred.name
    db.delete(cred)
    db.commit()
    logger.info(
        "Ephemeral cleanup: deleted credential #%s '%s' after job #%d completed",
        cred_id, cred_name, job_id,
    )


# ── Dataset Refresh Task ────────────────────────────────────────────────────

import subprocess
import sys
import gzip
import urllib.request
import urllib.error
import concurrent.futures
import threading
import time

_DS_KINDS_ORDER = ["nvd_cpe_cve", "cisa_kev", "epss", "vendor_advisories", "cvedetails_cvss", "cms_cve_map", "compliance_map"]
_DS_KIND_DEPENDS = {"cms_cve_map": "nvd_cpe_cve", "cvedetails_cvss": "nvd_cpe_cve"}
_DS_KIND_NAMES = {
    "nvd_cpe_cve": "nvd_auto", "cisa_kev": "kev_auto", "epss": "epss_auto",
    "vendor_advisories": "vendor_adv_auto",
    "cms_cve_map": "cms_auto", "compliance_map": "compliance_auto", "cvedetails_cvss": "cvedetails_auto",
}
_DS_CANONICAL = {
    "nvd_cpe_cve": "/data/cve/nvd_cpe_cve.json",
    "cisa_kev": "/data/cve/cisa_kev.json",
    "epss": "/data/cve/epss.json",
    "vendor_advisories": "/data/cve/vendor_advisories.json",
    "cvedetails_cvss": "/data/cve/cvedetails_cvss.json",
    "cms_cve_map": "/data/cve/cms_cve_map.json",
    "compliance_map": "/data/cve/compliance_map.json",
}

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_CVEORG_API = "https://cveawg.mitre.org/api/cve"


def _ds_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _ds_fetch_url(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# HTTP status codes worth retrying (transient server errors)
_RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}


def _ds_fetch_url_retry(url, headers=None, timeout=30, max_retries=3, label=""):
    """Fetch URL with exponential backoff retry for transient errors."""
    last_exc = None
    for attempt in range(1, max_retries + 2):  # attempt 1 = initial, 2..4 = retries
        try:
            return _ds_fetch_url(url, headers, timeout)
        except urllib.error.HTTPError as e:
            last_exc = e
            if e.code in _RETRYABLE_HTTP_CODES and attempt <= max_retries:
                delay = 10 * (2 ** (attempt - 1))  # 10s, 20s, 40s
                logger.warning("  %s: HTTP %d, retry %d/%d in %ds...",
                               label, e.code, attempt, max_retries, delay)
                time.sleep(delay)
                continue
            raise  # non-retryable (e.g. 403) or retries exhausted
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_exc = e
            if attempt <= max_retries:
                delay = 10 * (2 ** (attempt - 1))
                logger.warning("  %s: %s, retry %d/%d in %ds...",
                               label, e, attempt, max_retries, delay)
                time.sleep(delay)
                continue
            raise
    raise last_exc  # should not reach here, but just in case


def _ds_run_script(name, args, timeout=180):
    script = f"/scripts/{name}"
    if not os.path.exists(script):
        return False, f"Script not found: {script}"
    try:
        r = subprocess.run([sys.executable, script] + args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return False, (r.stderr.strip()[:500] or "non-zero exit")
        return True, ""
    except Exception as e:
        return False, str(e)


def _ds_refresh_nvd(api_key, nvd_days=120):
    from pathlib import Path
    raw_dir = Path("/data/raw/nvd")
    out_dir = Path("/data/cve")
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    start_date = (datetime.now(timezone.utc) - __import__('datetime').timedelta(days=nvd_days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    rate_delay = 0.6 if api_key else 6.0

    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    # Fetch first page (with retry for transient errors like 503)
    try:
        url = f"{_NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}&startIndex=0&resultsPerPage=2000"
        first = json.loads(_ds_fetch_url_retry(url, headers, 60, label="NVD page 1"))
    except Exception as e:
        return False, None, f"NVD first page failed: {e}"

    total = first.get("totalResults", 0)
    logger.info("NVD total: %d CVEs", total)
    pages = [first]

    if total > 2000:
        for start_idx in range(2000, total, 2000):
            time.sleep(rate_delay)
            page_num = start_idx // 2000 + 1
            try:
                url = f"{_NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}&startIndex={start_idx}&resultsPerPage=2000"
                page = json.loads(_ds_fetch_url_retry(url, headers, 60, label=f"NVD page {page_num}"))
                pages.append(page)
                logger.info("  NVD page %d: startIndex=%d, got %d", page_num, start_idx, len(page.get("vulnerabilities", [])))
            except Exception as e:
                logger.warning("  NVD page %d (startIndex=%d) failed after retries: %s", page_num, start_idx, e)

    # Write raw pages
    for i, p in enumerate(pages, 1):
        with open(raw_dir / f"nvd_api_page_{i}.json", "w") as f:
            json.dump(p, f)

    inputs = [str(raw_dir / f"nvd_api_page_{i}.json") for i in range(1, len(pages) + 1)]
    out_path = str(out_dir / f"nvd_cpe_cve_{_ds_ts()}.json")
    ok, err = _ds_run_script("nvd_flatten.py", ["--inputs"] + inputs + ["--out", out_path])
    if not ok:
        return False, None, f"nvd_flatten.py: {err}"
    return True, out_path, None


def _ds_refresh_cisa_kev():
    from pathlib import Path
    raw_dir = Path("/data/raw/cisa")
    out_dir = Path("/data/cve")
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = _ds_fetch_url(_CISA_KEV_URL, timeout=30)
        raw_path = str(raw_dir / "known_exploited_vulnerabilities.json")
        with open(raw_path, "wb") as f:
            f.write(data)
    except Exception as e:
        return False, None, f"CISA KEV fetch: {e}"

    out_path = str(out_dir / f"cisa_kev_{_ds_ts()}.json")
    ok, err = _ds_run_script("cisa_kev_convert.py", ["--in", raw_path, "--out", out_path])
    if not ok:
        return False, None, f"cisa_kev_convert.py: {err}"
    return True, out_path, None


def _ds_refresh_epss():
    from pathlib import Path
    raw_dir = Path("/data/raw/epss")
    out_dir = Path("/data/cve")
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = _ds_fetch_url(_EPSS_URL, timeout=60)
        csv_data = gzip.decompress(data)
        raw_path = str(raw_dir / "epss_scores-current.csv")
        with open(raw_path, "wb") as f:
            f.write(csv_data)
    except Exception as e:
        return False, None, f"EPSS fetch: {e}"

    out_path = str(out_dir / f"epss_{_ds_ts()}.json")
    ok, err = _ds_run_script("epss_convert.py", ["--in", raw_path, "--out", out_path])
    if not ok:
        return False, None, f"epss_convert.py: {err}"
    return True, out_path, None


def _ds_refresh_cvedetails(nvd_path, on_progress=None):
    import requests as _requests
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)

    if not os.path.exists(nvd_path):
        return False, None, f"NVD file not found: {nvd_path}"

    with open(nvd_path) as f:
        cve_ids = [e["cve"] for e in json.load(f) if e.get("cve", "").startswith("CVE-")]

    # Load cache
    cache_path = out_dir / "cvedetails_cvss.json"
    existing = {}
    if cache_path.exists():
        try:
            with open(cache_path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                existing = data
        except Exception:
            pass

    new_ids = [c for c in cve_ids if c not in existing]
    logger.info("CVE.org: %d total, %d new to fetch", len(cve_ids), len(new_ids))

    # Tunable via env: CVEORG_WORKERS (default 5), CVEORG_REQ_PER_SEC (default 5)
    max_workers = int(os.environ.get("CVEORG_WORKERS", "5"))
    req_per_sec = float(os.environ.get("CVEORG_REQ_PER_SEC", "5"))
    logger.info("CVE.org: workers=%d, rate_limit=%.1f req/s", max_workers, req_per_sec)

    # Persistent session — reuses TCP connections (skips TLS handshake per request)
    session = _requests.Session()
    session.headers.update({"Accept": "application/json", "User-Agent": "VulnScan/2.0"})
    adapter = _requests.adapters.HTTPAdapter(pool_connections=max_workers, pool_maxsize=max_workers)
    session.mount("https://", adapter)

    # Rate limiter across all threads to avoid being blocked
    _rate_lock = threading.Lock()
    _rate_interval = 1.0 / req_per_sec
    _last_request_time = [0.0]

    def _rate_wait():
        with _rate_lock:
            now = time.time()
            wait = _rate_interval - (now - _last_request_time[0])
            if wait > 0:
                time.sleep(wait)
            _last_request_time[0] = time.time()

    def _fetch_one(cve_id):
        for attempt in range(3):
            _rate_wait()
            try:
                resp = session.get(f"{_CVEORG_API}/{cve_id}", timeout=15)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 5 * (attempt + 1)))
                    logger.warning("  CVE.org 429 rate-limited, backing off %ds", retry_after)
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                d = resp.json()
                containers = d.get("containers", {})
                cna_score = adp_score = None
                for m in containers.get("cna", {}).get("metrics", []):
                    for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                        v = m.get(k)
                        if v and v.get("baseScore"):
                            cna_score = float(v["baseScore"]); break
                    if cna_score: break
                for adp in containers.get("adp", []):
                    for m in adp.get("metrics", []):
                        for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                            v = m.get(k)
                            if v and v.get("baseScore"):
                                adp_score = float(v["baseScore"]); break
                        if adp_score: break
                    if adp_score: break
                if cna_score or adp_score:
                    best = max(filter(None, [cna_score, adp_score]))
                    sev = "critical" if best >= 9 else "high" if best >= 7 else "medium" if best >= 4 else "low" if best > 0 else "info"
                    return cve_id, {"cvss": best, "severity": sev, "cna_cvss": cna_score, "adp_cvss": adp_score}
                return cve_id, None
            except _requests.exceptions.RequestException as e:
                logger.warning("  CVE.org %s attempt %d: %s", cve_id, attempt + 1, e)
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
            except Exception as e:
                logger.warning("  CVE.org %s unexpected error: %s", cve_id, e)
            break
        return cve_id, None

    if new_ids:
        done = 0
        total = len(new_ids)
        batch_size = 500
        if on_progress:
            on_progress(0, total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for batch_start in range(0, total, batch_size):
                batch = new_ids[batch_start:batch_start + batch_size]
                futures = {pool.submit(_fetch_one, c): c for c in batch}
                for f in concurrent.futures.as_completed(futures):
                    cve_id, r = f.result()
                    if r:
                        existing[cve_id] = r
                    done += 1
                    if done % 100 == 0 or done == total:
                        logger.info("  CVE.org: %d/%d", done, total)
                        if on_progress:
                            on_progress(done, total)
                # Checkpoint after each batch
                try:
                    with open(cache_path, "w") as _cf:
                        json.dump(existing, _cf)
                except Exception:
                    pass

    session.close()

    out_path = str(out_dir / f"cvedetails_cvss_{_ds_ts()}.json")
    with open(out_path, "w") as f:
        json.dump(existing, f)
    return True, out_path, None


def _ds_refresh_cms_cve_map(nvd_path):
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not os.path.exists(nvd_path):
        return False, None, f"NVD file not found: {nvd_path}"
    out_path = str(out_dir / f"cms_cve_map_{_ds_ts()}.json")
    ok, err = _ds_run_script("generate_cms_cve_map.py", ["--nvd", nvd_path, "--out", out_path])
    if not ok:
        return False, None, f"generate_cms_cve_map.py: {err}"
    return True, out_path, None


def _ds_refresh_compliance_map():
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = str(out_dir / f"compliance_map_{_ds_ts()}.json")
    ok, err = _ds_run_script("generate_compliance_map.py", ["--out", out_path])
    if not ok:
        return False, None, f"generate_compliance_map.py: {err}"
    return True, out_path, None


def _ds_refresh_vendor_advisories():
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = str(out_dir / f"vendor_advisories_{_ds_ts()}.json")
    ok, err = _ds_run_script("vendor_advisories_fetch.py", ["--out", out_path], timeout=900)
    if not ok:
        return False, None, f"vendor_advisories_fetch.py: {err}"
    return True, out_path, None


def run_dataset_refresh(workspace_id: int, kinds: list[str] | None = None) -> None:
    """Background task: fetch/convert/swap datasets from external sources."""
    import redis as _redis

    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    r = _redis.Redis.from_url(redis_url)
    lock_key = f"dataset_refresh_lock:{workspace_id}"
    status_key = f"dataset_refresh:{workspace_id}"

    if not r.set(lock_key, "1", nx=True, ex=3600):
        logger.warning("Dataset refresh already running for workspace %d", workspace_id)
        return

    requested = kinds or list(_DS_KINDS_ORDER)
    ordered = []
    for k in _DS_KINDS_ORDER:
        if k in requested:
            dep = _DS_KIND_DEPENDS.get(k)
            if dep and dep not in ordered and dep not in requested:
                ordered.append(dep)
            if k not in ordered:
                ordered.append(k)

    state = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "kinds": {k: {"status": "pending", "message": ""} for k in ordered},
        "current_kind": None,
        "finished_at": None,
    }
    r.setex(status_key, 3600, json.dumps(state))

    db = SessionLocal()
    api_key = os.environ.get("NVD_API_KEY", "")
    results: dict[str, str] = {}

    def _cveorg_progress(done, total):
        """Push CVE.org fetch progress into Redis so the frontend can display it."""
        state["kinds"]["cvedetails_cvss"]["message"] = f"{done}/{total} CVEs"
        state["kinds"]["cvedetails_cvss"]["progress"] = round(done / total * 100) if total else 0
        try:
            r.setex(status_key, 3600, json.dumps(state))
        except Exception:
            pass

    _dispatch = {
        "nvd_cpe_cve": lambda: _ds_refresh_nvd(api_key),
        "cisa_kev": lambda: _ds_refresh_cisa_kev(),
        "epss": lambda: _ds_refresh_epss(),
        "vendor_advisories": lambda: _ds_refresh_vendor_advisories(),
        "cvedetails_cvss": lambda dep: _ds_refresh_cvedetails(dep, on_progress=_cveorg_progress),
        "cms_cve_map": lambda dep: _ds_refresh_cms_cve_map(dep),
        "compliance_map": lambda: _ds_refresh_compliance_map(),
    }

    try:
        for kind in ordered:
            if not r.exists(lock_key):
                logger.info("Dataset refresh cancelled")
                state["status"] = "cancelled"
                break

            r.expire(lock_key, 3600)
            state["current_kind"] = kind
            state["kinds"][kind]["status"] = "running"
            r.setex(status_key, 3600, json.dumps(state))
            logger.info("Refreshing dataset: %s", kind)

            dep = _DS_KIND_DEPENDS.get(kind)
            dep_path = None
            if dep:
                dep_path = results.get(dep) or "/data/cve/nvd_cpe_cve.json"
                if not os.path.exists(dep_path):
                    state["kinds"][kind] = {"status": "failed", "message": f"Dependency {dep} not available"}
                    r.setex(status_key, 3600, json.dumps(state))
                    continue

            try:
                fn = _dispatch[kind]
                if dep:
                    success, out, err = fn(dep_path)
                else:
                    success, out, err = fn()
            except Exception as exc:
                success, out, err = False, None, str(exc)

            if success and out:
                # Copy timestamped file → canonical (non-timestamped) file
                canonical = _DS_CANONICAL.get(kind)
                if canonical:
                    import shutil
                    shutil.copy2(out, canonical)
                    logger.info("  %s: copied %s -> %s", kind, out, canonical)
                # DB record points to canonical path (stable, won't break if timestamped backup is deleted)
                _swap_dataset(workspace_id, kind, canonical or out, db)
                results[kind] = canonical or out
                state["kinds"][kind] = {"status": "done", "message": ""}
                logger.info("  %s: done -> %s", kind, canonical or out)
            else:
                state["kinds"][kind] = {"status": "failed", "message": err or "Unknown error"}
                logger.error("  %s: failed — %s", kind, err)

            r.setex(status_key, 3600, json.dumps(state))

        done_count = sum(1 for v in state["kinds"].values() if v["status"] == "done")
        fail_count = sum(1 for v in state["kinds"].values() if v["status"] == "failed")
        if state["status"] != "cancelled":
            state["status"] = "done" if fail_count == 0 else "partial" if done_count > 0 else "failed"

        # Clean up old timestamped files — keep only canonical files
        if done_count > 0:
            try:
                _cleanup_old_dataset_files()
            except Exception as e:
                logger.warning("Dataset cleanup failed: %s", e)

        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        state["current_kind"] = None
        r.setex(status_key, 3600, json.dumps(state))
        logger.info("Dataset refresh finished: %s", state["status"])

    except Exception as e:
        state["status"] = "failed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        state["current_kind"] = None
        r.setex(status_key, 3600, json.dumps(state))
        logger.exception("Dataset refresh crashed: %s", e)
    finally:
        r.delete(lock_key)
        db.close()


def _cleanup_old_dataset_files() -> None:
    """
    Delete old timestamped dataset files from /data/cve/.
    Keeps canonical files and any file still referenced by an enabled DB record.
    """
    import glob
    import re

    data_dir = "/data/cve"
    if not os.path.isdir(data_dir):
        return

    # Canonical filenames — NEVER delete these
    canonical_names = set(os.path.basename(p) for p in _DS_CANONICAL.values())

    # Also protect any file still referenced by an enabled dataset record
    protected = set(canonical_names)
    try:
        db = SessionLocal()
        for ds in db.query(models.CveDataset).filter(models.CveDataset.enabled == True).all():
            if ds.path:
                protected.add(os.path.basename(ds.path))
        db.close()
    except Exception as e:
        logger.warning("Cleanup: could not query DB for protected files, skipping: %s", e)
        return

    # Only match timestamped files: kind_YYYYMMDD_HHMMSS.json
    _TS_PATTERN = re.compile(r"^(.+)_\d{8}_\d{6}\.json$")

    removed = 0
    for filepath in glob.glob(os.path.join(data_dir, "*.json")):
        filename = os.path.basename(filepath)
        # Never delete canonical or DB-protected files
        if filename in protected:
            continue
        # Only delete files matching the timestamped pattern
        m = _TS_PATTERN.match(filename)
        if not m or m.group(1) not in _DS_CANONICAL:
            continue
        try:
            os.remove(filepath)
            removed += 1
            logger.info("  Cleanup: removed old dataset file %s", filename)
        except OSError as e:
            logger.warning("  Cleanup: failed to remove %s: %s", filename, e)

    if removed:
        logger.info("Dataset cleanup: removed %d old timestamped file(s)", removed)


def _swap_dataset(ws_id: int, kind: str, new_file_path: str, db: Session) -> None:
    """Atomically swap: create new dataset, disable old ones of same kind."""
    try:
        # Verify the new file exists and is non-empty before disabling the old one
        if not os.path.isfile(new_file_path):
            raise FileNotFoundError(f"New dataset file not found: {new_file_path}")
        if os.path.getsize(new_file_path) < 10:
            raise ValueError(f"New dataset file is empty or too small: {new_file_path}")

        db.query(models.CveDataset).filter(
            models.CveDataset.workspace_id == ws_id,
            models.CveDataset.kind == kind,
            models.CveDataset.enabled == True,
        ).update({"enabled": False})

        name = _DS_KIND_NAMES.get(kind, kind)
        new_ds = models.CveDataset(
            workspace_id=ws_id,
            name=name,
            kind=kind,
            path=new_file_path,
            enabled=True,
        )
        db.add(new_ds)
        db.commit()
        logger.info("Swapped dataset %s: new ID=%d", kind, new_ds.id)

        # Invalidate the Threat Intel cache for this workspace if a feeder
        # dataset was just rotated. Best-effort — never block the swap on it.
        if kind in ("nvd_cpe_cve", "cisa_kev", "epss", "vendor_advisories"):
            try:
                from app.threat_intel import aggregator as _ti
                _ti.invalidate(ws_id)
            except Exception as _ti_err:
                logger.debug("Threat Intel cache invalidation skipped: %s", _ti_err)
    except Exception as e:
        db.rollback()
        logger.error("Failed to swap dataset %s: %s", kind, e)
        raise


# ── AI Analysis Tasks ─────────────────────────────────────────────────────

def run_ai_analysis(analysis_id: int) -> None:
    """RQ task — runs AI deep analysis on scan findings."""
    from app.ai.engine import run_analysis
    run_analysis(analysis_id)


def run_ai_poc(analysis_id: int, finding_id: int) -> None:
    """RQ task — generates PoC for a single finding."""
    from app.ai.engine import generate_poc
    generate_poc(analysis_id, finding_id)

