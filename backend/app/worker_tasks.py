import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db import models
from app.scanner.engine import scan_target
from app.risk.cvss_engine import severity_from_score
from app.risk.risk_engine import compute_risk
from app.risk.sla_engine import assign_sla_days
from app.cve.dataset_loader import load_json
from app.compliance.mapper import map_compliance_by_cve_or_category
from app.graph.neo4j_client import Neo4jClient

def _load_compliance(ws_id: int, db: Session):
    ds = db.query(models.CveDataset).filter(models.CveDataset.workspace_id==ws_id, models.CveDataset.kind=="compliance_map", models.CveDataset.enabled==True).all()
    rows=[]
    for d in ds:
        try: rows += load_json(d.path)
        except: pass
    return rows

def run_scan_job(job_id: int):
    db = SessionLocal()
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id==job_id).first()
        if not job:
            return
        ws_id = job.workspace_id

        prof = db.query(models.Profile).filter(models.Profile.id==job.profile_id, models.Profile.workspace_id==ws_id).first()
        if not prof:
            job.status="failed"; db.commit(); return

        job.status="running"
        db.commit()

        profile = {"plugin_selection_json": prof.plugin_selection_json, "options_json": prof.options_json}
        findings = asyncio_run(scan_target(job.target, profile, ws_id))

        # suppression list
        suppressed = {s.fingerprint for s in db.query(models.SuppressedFinding).filter(models.SuppressedFinding.workspace_id==ws_id).all()}

        # compliance db
        compliance_db = _load_compliance(ws_id, db)

        # graph
        neo = Neo4jClient()

        # asset criticality
        try:
            opt = json.loads(prof.options_json or "{}")
        except:
            opt = {}
        criticality = int((opt.get("asset") or {}).get("criticality", 2))

        # store findings
        for f in findings:
            if f.fingerprint in suppressed:
                continue

            kev = bool(getattr(f, "is_kev", False))
            cvss = getattr(f, "cvss", None)
            confidence = float(getattr(f, "confidence", 1.0) or 1.0)

            risk = compute_risk(cvss=cvss, kev=kev, criticality=criticality, exploit_known=False, confidence=confidence)
            sev = severity_from_score(risk)

            sla_days = assign_sla_days(sev)

            comp = map_compliance_by_cve_or_category(getattr(f,"cve",None), f.plugin_id, compliance_db)

            row = models.Finding(
                workspace_id=ws_id,
                job_id=job.id,
                target=job.target,
                plugin_id=f.plugin_id,
                title=f.title,
                severity=sev,
                description=f.description or "",
                remediation=f.remediation or "",
                references_json=json.dumps(f.references or []),
                evidence=f.evidence or "",
                fingerprint=f.fingerprint,
                cvss_base=cvss,
                risk_score=risk,
                confidence=confidence,
                sla_days=sla_days,
                compliance_json=json.dumps(comp) if comp else None,
                is_kev=kev
            )
            db.add(row)

            # push to graph if CVE exists
            cve = getattr(f,"cve",None)
            if cve and str(cve).startswith("CVE-"):
                # choose a tech label: plugin_id or simplified
                tech = f.plugin_id
                try:
                    neo.upsert_finding(ws_id, job.target, tech, cve, risk)
                except:
                    pass

        db.commit()
        try:
            neo.close()
        except:
            pass

        job.status="done"
        job.finished_at=datetime.now(timezone.utc)
        db.commit()

    except Exception as e:
        try:
            job = db.query(models.ScanJob).filter(models.ScanJob.id==job_id).first()
            if job:
                job.status="failed"
                job.meta_json=json.dumps({"error": str(e)})
                db.commit()
        except:
            pass
    finally:
        db.close()

def asyncio_run(coro):
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            return asyncio.run(coro)
    except:
        pass
    return asyncio.run(coro)
