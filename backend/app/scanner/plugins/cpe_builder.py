import re
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult

META = PluginMeta(
    plugin_id="cpe.builder",
    name="Extended CPE Builder",
    category="fingerprint",
    depends_on=["fingerprint.http","fingerprint.banner.multi","fingerprint.web.tech","fingerprint.favicon.hash"],
    consumes=["fingerprint.http","fingerprint.banners","fingerprint.webtech","fingerprint.favicon"],
    provides=["cpe.candidates"],
    enabled_by_default=True,
    timeout_seconds=4.0,
)

def mk(vendor, product, version=None, conf=0.7, source=""):
    ver = version if version else "*"
    return {
        "cpe23": f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*",
        "vendor": vendor, "product": product, "version": version,
        "confidence": conf, "source": source
    }

class Check(Plugin):
    async def run(self, target, ctx):
        cands=[]

        # from HTTP server header
        http = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        for item in http:
            server = (item.get("server") or "")
            m = re.search(r"\bnginx\/([0-9][0-9A-Za-z\.\-\+~]+)", server, re.I)
            if m: cands.append(mk("nginx","nginx",m.group(1),0.85,"http:server"))
            m = re.search(r"\bapache\/([0-9][0-9A-Za-z\.\-\+~]+)", server, re.I)
            if m: cands.append(mk("apache","http_server",m.group(1),0.80,"http:server"))

        # from banners (ssh/redis/elastic)
        banners = (ctx.get("fingerprint.banners", {}) or {}).get("banners", [])
        for b in banners:
            txt = b.get("banner","")
            m = re.search(r"OpenSSH[_-]([0-9\.p]+)", txt, re.I)
            if m: cands.append(mk("openbsd","openssh",m.group(1),0.90,"ssh"))
            m = re.search(r"redis_version:([0-9\.]+)", txt, re.I)
            if m: cands.append(mk("redis","redis",m.group(1),0.90,"redis"))
            if "cluster_name" in txt.lower():
                cands.append(mk("elastic","elasticsearch",None,0.75,"elastic"))

        # from web tech detect
        tech = ctx.get("fingerprint.webtech", []) or []
        for t in tech:
            if t["type"]=="cms" and t["name"]=="wordpress":
                cands.append(mk("wordpress","wordpress",None,0.70,"cms"))
            if t["type"]=="framework" and t["name"]=="laravel":
                cands.append(mk("laravel","laravel",None,0.60,"framework"))

        # favicon mapping will be added by separate dataset-based plugin in future; here keep candidates list only

        # dedup
        uniq=[]; seen=set()
        for c in cands:
            k=(c["vendor"],c["product"],c["version"])
            if k in seen: continue
            seen.add(k); uniq.append(c)

        return PluginResult(findings=[], artifacts={"cpe.candidates": uniq})
