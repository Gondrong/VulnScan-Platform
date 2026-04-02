import re
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult

META = PluginMeta(
    plugin_id="cpe.builder",
    name="Extended CPE Builder",
    category="fingerprint",
    depends_on=["fingerprint.http", "fingerprint.banner.multi", "fingerprint.web.tech", "fingerprint.favicon.hash", "fingerprint.deep"],
    consumes=["fingerprint.http", "fingerprint.banners", "fingerprint.webtech", "fingerprint.favicon", "fingerprint.deep"],
    provides=["cpe.candidates"],
    enabled_by_default=True,
    timeout_seconds=4.0,
)


def mk(vendor, product, version=None, conf=0.7, source=""):
    ver = version if version else "*"
    return {
        "cpe23": f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*",
        "vendor": vendor, "product": product, "version": version,
        "confidence": conf, "source": source,
    }


# ── Server header patterns ────────────────────────────────────────────────────
# Each entry: (regex, vendor, product, confidence)
_SERVER_PATTERNS = [
    (r"\bnginx\/([0-9][0-9A-Za-z.\-+~]+)", "f5", "nginx", 0.85),
    (r"\bapache\/([0-9][0-9A-Za-z.\-+~]+)", "apache", "http_server", 0.80),
    (r"\bapache[- ]httpd\/([0-9][0-9A-Za-z.\-+~]+)", "apache", "http_server", 0.80),
    (r"\bMicrosoft-IIS\/([0-9.]+)", "microsoft", "internet_information_services", 0.90),
    (r"\bIIS\/([0-9.]+)", "microsoft", "internet_information_services", 0.85),
    (r"\bLiteSpeed\/([0-9.]+)", "litespeedtech", "litespeed_web_server", 0.80),
    (r"\bopenresty\/([0-9.]+)", "openresty", "openresty", 0.80),
    (r"\bApache[- ]Tomcat\/([0-9.]+)", "apache", "tomcat", 0.85),
    (r"\bTomcat\/([0-9.]+)", "apache", "tomcat", 0.80),
    (r"\bJetty\(([0-9.]+)", "eclipse", "jetty", 0.80),
    (r"\bCaddy", None, None, 0.0),  # Caddy rarely shows version; skip
    (r"\bcloudflare", None, None, 0.0),  # CDN, not a vuln target
    (r"\benvoy\/([0-9.]+)", "envoyproxy", "envoy", 0.70),
    (r"\bAkka-Http\/([0-9.]+)", "lightbend", "akka_http", 0.70),
    (r"\bgunicorn\/([0-9.]+)", "gunicorn", "gunicorn", 0.60),
    (r"\bwerkzeug\/([0-9.]+)", "palletsprojects", "werkzeug", 0.70),
    (r"\buvicorn\/([0-9.]+)", "encode", "uvicorn", 0.60),
]

# ── X-Powered-By / X-AspNet-Version patterns ─────────────────────────────────
_POWERED_BY_PATTERNS = [
    (r"\bPHP\/([0-9.]+)", "php", "php", 0.85),
    (r"\bASP\.NET\b", "microsoft", "asp.net", 0.80),
    (r"\bExpress\b", "expressjs", "express", 0.60),
    (r"\bJSF\/([0-9.]+)", "oracle", "javaserver_faces", 0.70),
    (r"\bServlet\/([0-9.]+)", "oracle", "servlet", 0.65),
    (r"\bPhusion Passenger\b", "phusion", "passenger", 0.65),
    (r"\bNext\.js\b", "vercel", "next.js", 0.70),
]

# ── Web tech → CPE mapping ────────────────────────────────────────────────────
_TECH_TO_CPE = {
    # CMS
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla\\!"),
    "magento": ("magento", "magento"),
    "shopify": ("shopify", "shopify"),
    "ghost": ("ghost", "ghost"),
    "typo3": ("typo3", "typo3"),
    "umbraco": ("umbraco", "umbraco_cms"),
    # Frameworks
    "laravel": ("laravel", "laravel"),
    "django": ("djangoproject", "django"),
    "flask": ("palletsprojects", "flask"),
    "rails": ("rubyonrails", "rails"),
    "ruby_on_rails": ("rubyonrails", "rails"),
    "spring": ("vmware", "spring_framework"),
    "spring_boot": ("vmware", "spring_boot"),
    "express": ("expressjs", "express"),
    "nextjs": ("vercel", "next.js"),
    "next.js": ("vercel", "next.js"),
    "nuxt": ("nuxt", "nuxt.js"),
    "angular": ("google", "angular"),
    "react": ("facebook", "react"),
    "vue": ("vuejs", "vue.js"),
    "symfony": ("symfony", "symfony"),
    "codeigniter": ("codeigniter", "codeigniter"),
    "cakephp": ("cakephp", "cakephp"),
    "fastapi": ("tiangolo", "fastapi"),
    # JavaScript runtimes
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    # Databases (from headers/error pages)
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
}

# ── Deep fingerprint → CPE mapping ───────────────────────────────────────────
_DEEP_NAME_TO_CPE = {
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla\\!"),
    "apache": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "spring_boot": ("pivotal_software", "spring_boot"),
    "nextjs": ("vercel", "next.js"),
    "tomcat": ("apache", "tomcat"),
    "asp.net": ("microsoft", "asp.net"),
    "flask": ("palletsprojects", "flask"),
    "django": ("djangoproject", "django"),
    "express": ("expressjs", "express"),
    "rails": ("rubyonrails", "rails"),
}


class Check(Plugin):
    async def run(self, target, ctx):
        cands = []

        # ── 1. From HTTP response data (Server header + X-Powered-By) ─────
        http = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        for item in http:
            # Server header
            server = (item.get("server") or "")
            for pattern, vendor, product, conf in _SERVER_PATTERNS:
                if vendor is None:
                    continue  # Skip non-matchable entries (CDNs, etc.)
                m = re.search(pattern, server, re.I)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    cands.append(mk(vendor, product, version, conf, "http:server"))

            # X-Powered-By header
            powered_by = (item.get("powered_by") or "")
            for pattern, vendor, product, conf in _POWERED_BY_PATTERNS:
                m = re.search(pattern, powered_by, re.I)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    cands.append(mk(vendor, product, version, conf, "http:powered_by"))

            # X-AspNet-Version header (if present in raw headers)
            aspnet_ver = (item.get("aspnet_version") or "")
            if aspnet_ver:
                cands.append(mk("microsoft", "asp.net", aspnet_ver, 0.85, "http:aspnet_version"))

            # X-Generator header (common in CMS)
            generator = (item.get("generator") or "")
            m = re.search(r"WordPress[/ ]?([0-9.]+)?", generator, re.I)
            if m:
                cands.append(mk("wordpress", "wordpress", m.group(1), 0.85, "http:generator"))
            m = re.search(r"Drupal[/ ]?([0-9.]+)?", generator, re.I)
            if m:
                cands.append(mk("drupal", "drupal", m.group(1), 0.85, "http:generator"))
            m = re.search(r"Joomla[/ ]?([0-9.]+)?", generator, re.I)
            if m:
                cands.append(mk("joomla", "joomla\\!", m.group(1), 0.85, "http:generator"))

        # ── 2. From banners (SSH, Redis, Elasticsearch, MySQL, etc.) ──────
        banners_data = ctx.get("fingerprint.banners", {}) or {}
        banners = banners_data.get("banners", []) if isinstance(banners_data, dict) else []
        for b in banners:
            txt = b.get("banner", "")
            m = re.search(r"OpenSSH[_-]([0-9.p]+)", txt, re.I)
            if m:
                cands.append(mk("openbsd", "openssh", m.group(1), 0.90, "ssh"))
            m = re.search(r"redis_version:([0-9.]+)", txt, re.I)
            if m:
                cands.append(mk("redis", "redis", m.group(1), 0.90, "redis"))
            m = re.search(r"mysql_native_password|MariaDB", txt, re.I)
            if m:
                cands.append(mk("oracle", "mysql", None, 0.70, "banner:mysql"))
            m = re.search(r"PostgreSQL", txt, re.I)
            if m:
                cands.append(mk("postgresql", "postgresql", None, 0.70, "banner:postgresql"))
            if "cluster_name" in txt.lower():
                cands.append(mk("elastic", "elasticsearch", None, 0.75, "elastic"))
            m = re.search(r"ProFTPD[/ ]([0-9.]+)", txt, re.I)
            if m:
                cands.append(mk("proftpd", "proftpd", m.group(1), 0.85, "ftp"))
            m = re.search(r"vsftpd[/ ]([0-9.]+)", txt, re.I)
            if m:
                cands.append(mk("beasts", "vsftpd", m.group(1), 0.85, "ftp"))
            m = re.search(r"Postfix", txt, re.I)
            if m:
                cands.append(mk("postfix", "postfix", None, 0.70, "smtp"))
            m = re.search(r"Exim[/ ]([0-9.]+)", txt, re.I)
            if m:
                cands.append(mk("exim", "exim", m.group(1), 0.85, "smtp"))

        # ── 3. From web technology detection ──────────────────────────────
        tech = ctx.get("fingerprint.webtech", []) or []
        for t in tech:
            name = (t.get("name") or "").lower()
            version = t.get("version")
            mapping = _TECH_TO_CPE.get(name)
            if mapping:
                vendor, product = mapping
                conf = 0.70 if version else 0.55
                cands.append(mk(vendor, product, version, conf, f"webtech:{t.get('type', '')}"))

        # ── 4. From deep fingerprinting (highest confidence) ──────────────
        deep = ctx.get("fingerprint.deep", []) or []
        for item in deep:
            name = (item.get("name") or "").lower()
            version = item.get("version")
            mapping = _DEEP_NAME_TO_CPE.get(name)
            if mapping:
                vendor, product = mapping
                conf = item.get("confidence", 0.90)
                cands.append(mk(vendor, product, version, conf, f"deep:{item.get('source', '')}"))

        # ── 5. Dedup: keep highest-confidence entry per (vendor, product, version)
        best = {}
        for c in cands:
            k = (c["vendor"], c["product"], c["version"])
            existing = best.get(k)
            if not existing or c["confidence"] > existing["confidence"]:
                best[k] = c
        uniq = list(best.values())

        return PluginResult(findings=[], artifacts={"cpe.candidates": uniq})

