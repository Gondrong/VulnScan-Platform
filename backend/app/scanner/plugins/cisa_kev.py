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

            vendor = r.get("vendorProject", "Unknown vendor")
            product = r.get("product", "Unknown product")
            date_added = r.get("dateAdded", "unknown")
            due_date = r.get("dueDate", "unknown")
            ransomware = r.get("knownRansomwareCampaignUse", "Unknown")
            notes = r.get("notes", "Listed in CISA KEV catalog")

            description = (
                f"{cve} is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.\n\n"
                f"Vendor/Project: {vendor}\n"
                f"Product: {product}\n"
                f"Date Added to KEV: {date_added}\n"
                f"Remediation Due Date: {due_date}\n"
                f"Known Ransomware Use: {ransomware}\n\n"
                f"Notes: {notes}"
            )

            remediation = (
                f"[CRITICAL — ACTIVELY EXPLOITED] {cve} is confirmed to be actively exploited in the wild.\n\n"
                f"[CISA MANDATE] Per CISA Binding Operational Directive (BOD) 22-01, "
                f"this vulnerability must be remediated by {due_date}.\n\n"
                f"[IMMEDIATE ACTIONS]\n"
                f"1. Apply the vendor-provided patch for {vendor} {product} immediately\n"
                f"2. If patching is not possible within the deadline, implement compensating controls:\n"
                f"   - Network segmentation to isolate affected systems\n"
                f"   - WAF rules to block known exploit patterns\n"
                f"   - Disable the affected feature/service if feasible\n"
                f"3. Monitor for indicators of compromise (IOCs) related to this vulnerability\n"
                f"4. Review logs for evidence of prior exploitation\n\n"
                f"[REFERENCES]\n"
                f"- https://nvd.nist.gov/vuln/detail/{cve}\n"
                f"- https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            )

            if ransomware and ransomware.lower() not in ("unknown", ""):
                remediation += f"\n\n[RANSOMWARE ALERT] This vulnerability has been used in ransomware campaigns ({ransomware}). Prioritize patching and ensure offline backups are current."

            findings.append(Finding(
                severity="critical",
                plugin_id=META.plugin_id,
                title=f"{cve} — CISA KEV: {vendor} {product} (actively exploited)",
                description=description,
                evidence=f"dateAdded={date_added} dueDate={due_date} vendor={vendor} product={product} ransomware={ransomware}",
                affected=target,
                fingerprint=fp,
                cve=cve,
                is_kev=True,
                confidence=1.0,
                remediation=remediation,
            ))
            out.append(r)
        return PluginResult(findings=findings, artifacts={"priority.kev_hits": out})
