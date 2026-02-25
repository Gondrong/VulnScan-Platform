from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="priority.cisa_kev",
    name="CISA KEV Prioritizer",
    category="priority",
    depends_on=["cve.match.nvd_cpe"],
    consumes=["cve.nvd_hits"],
    provides=["priority.kev_hits"],
    enabled_by_default=True,
    timeout_seconds=4.0,
)

class Check(Plugin):
    async def run(self, target, ctx):
        ws_id = ctx.get("workspace_id")
        detected = {h.get("cve","").upper() for h in (ctx.get("cve.nvd_hits", []) or []) if (h.get("cve") or "").upper().startswith("CVE-")}
        if not detected:
            return PluginResult(artifacts={"priority.kev_hits": []})

        db = SessionLocal()
        kev=set(); rows=[]
        try:
            dsets = db.query(models.CveDataset).filter(
                models.CveDataset.workspace_id==ws_id,
                models.CveDataset.kind=="cisa_kev",
                models.CveDataset.enabled==True
            ).all()
            for ds in dsets:
                data = load_json(ds.path)
                for r in data or []:
                    c = (r.get("cve") or "").upper()
                    if c.startswith("CVE-"):
                        kev.add(c); rows.append(r)
        finally:
            db.close()

        hits = sorted(list(detected.intersection(kev)))
        findings=[]
        out=[]
        kev_map = {(r.get("cve") or "").upper(): r for r in rows}
        for cve in hits:
            r = kev_map.get(cve, {"cve": cve})
            fp = stable_fingerprint(target, META.plugin_id, cve)
            findings.append(Finding(
                severity="critical",
                plugin_id=META.plugin_id,
                title=f"{cve} is in CISA KEV (prioritize)",
                description=r.get("notes","Listed in KEV"),
                evidence=f"dateAdded={r.get('dateAdded')} dueDate={r.get('dueDate')}",
                affected=target,
                fingerprint=fp,
                cve=cve,
                is_kev=True,
                confidence=1.0
            ))
            out.append(r)
        return PluginResult(findings=findings, artifacts={"priority.kev_hits": out})
