from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.cms",
    name="CMS CVE Mapping",
    category="cve",
    depends_on=["fingerprint.web.tech"],
    consumes=["fingerprint.webtech"],
    enabled_by_default=True,
    timeout_seconds=4.0,
)

class Check(Plugin):
    async def run(self, target, ctx):
        ws_id = ctx.get("workspace_id")
        tech = ctx.get("fingerprint.webtech", []) or []
        cms = {t["name"] for t in tech if t.get("type")=="cms"}
        if not cms:
            return PluginResult()

        db = SessionLocal()
        findings=[]
        try:
            dsets = db.query(models.CveDataset).filter(
                models.CveDataset.workspace_id==ws_id,
                models.CveDataset.kind=="cms_cve_map",
                models.CveDataset.enabled==True
            ).all()
            for ds in dsets:
                data = load_json(ds.path)
                for row in data or []:
                    if row.get("cms") in cms:
                        cve = row.get("cve","CVE")
                        fp = stable_fingerprint(target, META.plugin_id, cve, row.get("cms",""))
                        findings.append(Finding(
                            severity=row.get("severity","medium"),
                            plugin_id=META.plugin_id,
                            title=f"{cve} (CMS mapping)",
                            description=row.get("summary",""),
                            references=row.get("refs",[]),
                            evidence=f"cms={row.get('cms')}",
                            affected=target,
                            fingerprint=fp,
                            cve=cve if cve.startswith("CVE-") else None,
                            confidence=0.7
                        ))
        finally:
            db.close()

        return PluginResult(findings=findings)
