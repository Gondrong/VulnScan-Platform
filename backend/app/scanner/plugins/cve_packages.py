from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.cve.version_cmp import match_expr
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.packages",
    name="CVE Matching (Packages)",
    category="cve",
    depends_on=["auth.ssh.inventory"],
    consumes=["inventory.packages"],
    provides=["cve.package_hits"],
    enabled_by_default=False,
    timeout_seconds=6.0,
)

def match_osv(pkgs, db):
    hits=[]
    idx={}
    for p in pkgs:
        idx.setdefault((p["ecosystem"], p["name"]), []).append(p["version"])

    for item in db or []:
        eco=item.get("ecosystem"); name=item.get("package")
        versions=idx.get((eco,name),[])
        for ver in versions:
            for r in item.get("ranges", []) or []:
                if r.get("type")=="introduced_fixed":
                    introduced=r.get("introduced","0")
                    fixed=r.get("fixed")
                    if fixed and match_expr(ver, f">= {introduced} < {fixed}"):
                        hits.append({
                            "id": item.get("id"),
                            "cve": item.get("cve"),
                            "package": name,
                            "ecosystem": eco,
                            "installed": ver,
                            "severity": item.get("severity","medium"),
                            "refs": item.get("refs",[]),
                            "summary": item.get("summary","")
                        })
                        break
    return hits

class Check(Plugin):
    async def run(self, target, ctx):
        pkgs = ctx.get("inventory.packages", []) or []
        if not pkgs:
            return PluginResult()

        ws_id = ctx.get("workspace_id")
        db = SessionLocal()
        hits=[]
        try:
            dsets = db.query(models.CveDataset).filter(
                models.CveDataset.workspace_id==ws_id,
                models.CveDataset.kind=="osv",
                models.CveDataset.enabled==True
            ).all()
            for ds in dsets:
                hits += match_osv(pkgs, load_json(ds.path))
        finally:
            db.close()

        findings=[]
        for h in hits[:3000]:
            cve = h.get("cve") or h.get("id") or "OSV"
            fp = stable_fingerprint(target, META.plugin_id, cve, h["package"], h["installed"])
            findings.append(Finding(
                severity=h.get("severity","medium"),
                plugin_id=META.plugin_id,
                title=f"{cve}: {h['package']} {h['installed']}",
                description=h.get("summary",""),
                references=h.get("refs",[]),
                evidence=f"ecosystem={h['ecosystem']} installed={h['installed']}",
                affected=target,
                fingerprint=fp,
                cve=cve if str(cve).startswith("CVE-") else None,
                confidence=1.0
            ))
        return PluginResult(findings=findings, artifacts={"cve.package_hits": hits})
