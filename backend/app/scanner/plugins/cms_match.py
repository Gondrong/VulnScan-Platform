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

CMS_REMEDIATION = {
    "wordpress": "Update WordPress core, themes, and plugins to the latest versions. Remove unused plugins/themes. Enable 2FA and use a WAF.",
    "drupal": "Update Drupal core and all modules. Review https://www.drupal.org/security for advisories.",
    "joomla": "Update Joomla and extensions. Restrict admin panel access by IP.",
    "magento": "Apply all Adobe Commerce security patches. Enable 2FA for admin.",
    "grafana": "Update Grafana to latest version. Review authentication settings and disable anonymous access.",
    "jenkins": "Update Jenkins and all plugins. Restrict access, enable authentication, and review script console access.",
    "gitlab": "Update GitLab to latest version. Review access controls and enable 2FA.",
    "nextcloud": "Update Nextcloud server and apps. Review sharing policies and enforce encryption.",
}

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
                        cms_name = row.get("cms", "unknown")
                        fp = stable_fingerprint(target, META.plugin_id, cve, cms_name)
                        
                        base_remediation = CMS_REMEDIATION.get(cms_name, f"Update {cms_name} to the latest version.")
                        remediation = (
                            f"[AFFECTED CMS] {cms_name.title()}\n\n"
                            f"[REMEDIATION] {base_remediation}\n\n"
                        )
                        if cve.startswith("CVE-"):
                            remediation += f"[CVE DETAILS] https://nvd.nist.gov/vuln/detail/{cve}"

                        findings.append(Finding(
                            severity=row.get("severity","medium"),
                            plugin_id=META.plugin_id,
                            title=f"{cve}: {cms_name.title()} vulnerability",
                            description=row.get("summary","") or f"CVE affecting {cms_name}",
                            references=row.get("refs",[]),
                            evidence=f"cms={cms_name} cve={cve}",
                            affected=target,
                            fingerprint=fp,
                            cve=cve if cve.startswith("CVE-") else None,
                            confidence=0.7,
                            remediation=remediation,
                        ))
        finally:
            db.close()

        return PluginResult(findings=findings)
