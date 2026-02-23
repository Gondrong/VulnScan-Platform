from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.cve.version_cmp import parse
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.nvd_cpe",
    name="CVE Matching (NVD CPE)",
    category="cve",
    depends_on=["cpe.builder"],
    consumes=["cpe.candidates"],
    provides=["cve.nvd_hits"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

def split_cpe23(cpe: str):
    parts = (cpe or "").split(":")
    if len(parts) < 6: return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4]}

def same_family(a: str, b: str) -> bool:
    aa=split_cpe23(a); bb=split_cpe23(b)
    return bool(aa and bb and aa["part"]==bb["part"] and aa["vendor"]==bb["vendor"] and aa["product"]==bb["product"])

def range_ok(installed: str | None, m: dict) -> bool:
    vsi=m.get("versionStartIncluding"); vee=m.get("versionEndExcluding")
    if not vsi and not vee:
        return True
    if not installed:
        return False
    v=parse(installed)
    if not v: return False
    if vsi:
        x=parse(vsi)
        if x and v < x: return False
    if vee:
        x=parse(vee)
        if x and v >= x: return False
    return True

class Check(Plugin):
    async def run(self, target, ctx):
        ws_id = ctx.get("workspace_id")
        cands = ctx.get("cpe.candidates", []) or []
        if not cands:
            return PluginResult()

        db = SessionLocal()
        hits=[]
        try:
            ds = db.query(models.CveDataset).filter(
                models.CveDataset.workspace_id==ws_id,
                models.CveDataset.kind=="nvd_cpe_cve",
                models.CveDataset.enabled==True
            ).all()
            for d in ds:
                data = load_json(d.path)
                for item in data or []:
                    for m in item.get("matches", []) or []:
                        cpe_db = m.get("cpe23")
                        if not cpe_db: continue
                        for c in cands:
                            if same_family(cpe_db, c.get("cpe23","")) and range_ok(c.get("version"), m):
                                hits.append({
                                    "cve": item.get("cve"),
                                    "summary": item.get("summary",""),
                                    "severity": item.get("severity","medium"),
                                    "cvss": item.get("cvss"),
                                    "refs": item.get("refs", []),
                                    "matched_cpe": c.get("cpe23"),
                                    "installed_version": c.get("version"),
                                    "confidence": c.get("confidence", 0.6)
                                })
                                break
        finally:
            db.close()

        findings=[]
        for h in hits[:3000]:
            cve = h.get("cve","CVE")
            fp = stable_fingerprint(target, META.plugin_id, cve, h.get("matched_cpe",""))
            findings.append(Finding(
                severity=h.get("severity","medium"),
                plugin_id=META.plugin_id,
                title=f"{cve} (NVD match)",
                description=h.get("summary",""),
                references=h.get("refs",[]),
                evidence=f"cpe={h.get('matched_cpe')} installed={h.get('installed_version')}",
                affected=target,
                fingerprint=fp,
                cvss=h.get("cvss"),
                cve=cve,
                confidence=h.get("confidence", 0.6)
            ))
        return PluginResult(findings=findings, artifacts={"cve.nvd_hits": hits})
