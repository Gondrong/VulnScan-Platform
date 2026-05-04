import base64, httpx, mmh3
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult

META = PluginMeta(
    plugin_id="fingerprint.favicon.hash",
    name="Favicon Hash Fingerprint",
    category="fingerprint",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["fingerprint.favicon"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

class Check(Plugin):
    async def run(self, target, ctx):
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        hashes=[]
        for item in http_items:
            url = item.get("url")
            if not url: continue
            try:
                async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=True) as client:
                    r = await client.get(url.rstrip("/") + "/favicon.ico")
                    if r.status_code == 200 and r.content:
                        b64 = base64.b64encode(r.content)
                        h = mmh3.hash(b64)
                        hashes.append({"url": url, "hash": h})
            except:
                pass
        return PluginResult(findings=[], artifacts={"fingerprint.favicon": hashes})
