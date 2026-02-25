import re

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult

META = PluginMeta(
    plugin_id="fingerprint.web.tech",
    name="Web Technology Detection",
    category="fingerprint",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["fingerprint.webtech"],
    enabled_by_default=True,
    timeout_seconds=10.0,
)

CMS_PATTERNS = [
    ("wordpress", r"wp-content|wp-includes|wordpress"),
    ("drupal", r'Drupal\.settings|drupal\.js|sites/default/files'),
    ("joomla", r"Joomla!|/components/com_"),
    ("magento", r"Mage\.Cookies|magento"),
]
FRAMEWORK_PATTERNS = [
    ("laravel", r"laravel_session|XSRF-TOKEN"),
    ("nextjs", r"__NEXT_DATA__|/_next/static"),
    ("react", r"data-reactroot|react-dom"),
    ("vue", r"__VUE__|data-v-app"),
    ("django", r"csrfmiddlewaretoken|django"),
]
HEADER_PATTERNS = [
    ("nginx", r"\bnginx\b", "server"),
    ("apache", r"\bapache\b", "server"),
    ("iis", r"\biis\b|microsoft-iis", "server"),
    ("php", r"\bphp\b", "x-powered-by"),
    ("asp.net", r"asp\.net", "x-powered-by"),
]


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        detected: list[dict] = []

        for item in http_items:
            url = item.get("url")
            if not url:
                continue

            # Header-based detection (no extra request needed)
            server = (item.get("server") or "").lower()
            powered_by = (item.get("powered_by") or "").lower()
            for name, pat, header_field in HEADER_PATTERNS:
                val = server if header_field == "server" else powered_by
                if re.search(pat, val, re.I):
                    detected.append(
                        {"type": "server", "name": name, "confidence": 0.85}
                    )

            # HTML-based detection
            try:
                async with httpx.AsyncClient(
                    timeout=min(ctx.policy.timeout_seconds, 8),
                    verify=False,
                    follow_redirects=True,
                    limits=httpx.Limits(max_connections=5),
                ) as client:
                    r = await client.get(url)
                    html = r.text or ""
                    headers_lower = {k.lower(): v for k, v in r.headers.items()}

                    for name, pat in CMS_PATTERNS:
                        if re.search(pat, html, re.I):
                            detected.append(
                                {"type": "cms", "name": name, "confidence": 0.9}
                            )

                    for name, pat in FRAMEWORK_PATTERNS:
                        if re.search(pat, html, re.I) or re.search(
                            pat, str(r.headers), re.I
                        ):
                            detected.append(
                                {"type": "framework", "name": name, "confidence": 0.75}
                            )

                    # Extra server headers from live response
                    srv = headers_lower.get("server", "").lower()
                    if srv:
                        for name, pat, _ in HEADER_PATTERNS:
                            if re.search(pat, srv, re.I):
                                detected.append(
                                    {"type": "server", "name": name, "confidence": 0.9}
                                )

            except Exception:
                pass

        # Deduplicate
        seen: set[tuple] = set()
        unique: list[dict] = []
        for d in detected:
            k = (d["type"], d["name"])
            if k not in seen:
                seen.add(k)
                unique.append(d)

        return PluginResult(
            findings=[],
            artifacts={"fingerprint.webtech": unique},
        )
