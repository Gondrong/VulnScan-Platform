import re, httpx
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult

META = PluginMeta(
    plugin_id="fingerprint.web.tech",
    name="Web Technology Detection",
    category="fingerprint",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["fingerprint.webtech"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

CMS_PATTERNS = [
    ("wordpress", r"wp-content|wp-includes"),
    ("drupal", r"Drupal\.settings"),
    ("joomla", r"Joomla!"),
    ("magento", r"Mage\.Cookies"),
]
FRAMEWORK_PATTERNS = [
    ("laravel", r"laravel_session"),
    ("nextjs", r"__NEXT_DATA__"),
    ("react", r"data-reactroot"),
    ("vue", r"__VUE__"),
]

class Check(Plugin):
    async def run(self, target, ctx):
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        detected=[]
        for item in http_items:
            url = item.get("url")
            if not url: continue
            try:
                async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=True) as client:
                    r = await client.get(url)
                    html = r.text or ""
                    for name, pat in CMS_PATTERNS:
                        if re.search(pat, html, re.I):
                            detected.append({"type":"cms","name":name,"confidence":0.9})
                    for name, pat in FRAMEWORK_PATTERNS:
                        if re.search(pat, html, re.I):
                            detected.append({"type":"framework","name":name,"confidence":0.7})
                    server = (r.headers.get("server") or "").lower()
                    if "nginx" in server: detected.append({"type":"server","name":"nginx","confidence":0.8})
                    if "apache" in server: detected.append({"type":"server","name":"apache","confidence":0.8})
            except:
                pass

        uniq=[]; seen=set()
        for d in detected:
            k=(d["type"],d["name"])
            if k in seen: continue
            seen.add(k); uniq.append(d)
        return PluginResult(findings=[], artifacts={"fingerprint.webtech": uniq})
