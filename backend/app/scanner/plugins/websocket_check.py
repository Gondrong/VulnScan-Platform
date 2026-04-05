"""
WebSocket Security Scanner
Tests for WebSocket hijacking, missing authentication, cross-origin issues,
and information disclosure via WebSocket connections.
"""
import asyncio
import base64
import hashlib
import os
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.websocket_check",
    name="WebSocket Security Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.websocket_findings"],
    enabled_by_default=True,
    timeout_seconds=25.0,
)

# Common WebSocket paths
_WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/", "/wss", "/api/ws", "/api/websocket",
    "/realtime", "/live", "/stream", "/events",
    "/graphql", "/subscriptions", "/cable", "/hub",
    "/signalr", "/signalr/negotiate", "/chat",
]

_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_key():
    """Generate a random WebSocket key."""
    return base64.b64encode(os.urandom(16)).decode()


def _ws_accept(key: str) -> str:
    """Calculate expected Sec-WebSocket-Accept value."""
    return base64.b64encode(
        hashlib.sha1((key + _WS_MAGIC).encode()).digest()
    ).decode()


async def _ws_upgrade(host: str, port: int, path: str, use_tls: bool,
                      origin: str = "", extra_headers: dict = None,
                      timeout: float = 5.0) -> tuple[int, dict, bytes]:
    """
    Send WebSocket upgrade request. Returns (status, headers, initial_data).
    Status 101 = upgrade successful.
    """
    try:
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

        key = _ws_key()
        headers = {
            "Host": host,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
            "User-Agent": "VulnScan/2.1",
        }
        if origin:
            headers["Origin"] = origin
        if extra_headers:
            headers.update(extra_headers)

        request = f"GET {path} HTTP/1.1\r\n"
        request += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        request += "\r\n"

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        header_block = text.split("\r\n\r\n", 1)[0]
        data = response[len(header_block.encode()) + 4:] if len(response) > len(header_block.encode()) + 4 else b""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        resp_headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return status, resp_headers, data
    except Exception:
        return 0, {}, b""


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        ws_results = []

        # Determine host/port
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000)]
                for p in web_ports[:2]:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.websocket_findings": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            # ── Step 1: Discover WebSocket endpoints ───────────────────
            discovered_ws = []
            for path in _WS_PATHS:
                status, headers, data = await _ws_upgrade(host, port, path, use_tls)

                if status == 101:
                    discovered_ws.append(path)
                    ws_results.append({"path": path, "status": 101})

            if not discovered_ws:
                continue

            # ── Step 2: Test each discovered endpoint ──────────────────
            for ws_path in discovered_ws:

                # Check 1: No authentication required
                status, headers, data = await _ws_upgrade(host, port, ws_path, use_tls)
                if status == 101:
                    fp = stable_fingerprint(target, META.plugin_id, "no_auth", ws_path)
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title=f"WebSocket endpoint accepts unauthenticated connections: {ws_path}",
                        description=(
                            f"The WebSocket endpoint at {ws_path} accepts connections without "
                            f"any authentication token or session cookie. Any client can connect "
                            f"and potentially receive or send data."
                        ),
                        evidence=f"url={base}{ws_path} status=101 auth=none",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.85,
                        remediation=(
                            f"[AFFECTED] Unauthenticated WebSocket at {ws_path}\n\n"
                            f"[FIX]\n"
                            f"1. Require authentication token in the initial HTTP upgrade request\n"
                            f"2. Validate session cookie or Authorization header before accepting\n"
                            f"3. Implement per-message authorization for sensitive operations\n\n"
                            f"[EXAMPLE]\n"
                            f"  // Verify token during upgrade\n"
                            f"  wss.on('connection', (ws, req) => {{\n"
                            f"    const token = req.headers['authorization'];\n"
                            f"    if (!verifyToken(token)) ws.close(1008, 'Unauthorized');\n"
                            f"  }});"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html"],
                    ))

                # Check 2: Cross-origin WebSocket hijacking
                evil_origin = "https://evil-attacker.com"
                status_cors, headers_cors, _ = await _ws_upgrade(
                    host, port, ws_path, use_tls, origin=evil_origin
                )

                if status_cors == 101:
                    fp = stable_fingerprint(target, META.plugin_id, "cors", ws_path)
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"Cross-origin WebSocket hijacking: {ws_path}",
                        description=(
                            f"The WebSocket endpoint at {ws_path} accepts connections from "
                            f"arbitrary origins (tested with {evil_origin}). A malicious website "
                            f"can open a WebSocket connection to this endpoint on behalf of a "
                            f"logged-in user and steal or manipulate data."
                        ),
                        evidence=f"url={base}{ws_path} evil_origin={evil_origin} status=101 (accepted)",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.90,
                        remediation=(
                            f"[HIGH] Cross-origin WebSocket hijacking at {ws_path}\n\n"
                            f"[FIX]\n"
                            f"1. Validate the Origin header during WebSocket upgrade\n"
                            f"2. Only accept connections from your own domain(s)\n"
                            f"3. Use CSRF tokens in the WebSocket handshake\n\n"
                            f"[EXAMPLE]\n"
                            f"  const allowedOrigins = ['https://yourapp.com'];\n"
                            f"  wss.on('upgrade', (req, socket) => {{\n"
                            f"    if (!allowedOrigins.includes(req.headers.origin)) {{\n"
                            f"      socket.destroy();\n"
                            f"    }}\n"
                            f"  }});"
                        ),
                        references=["https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"],
                    ))

                # Check 3: Information in initial data
                if data and len(data) > 10:
                    data_preview = data.decode("utf-8", errors="ignore")[:200]
                    fp = stable_fingerprint(target, META.plugin_id, "info_leak", ws_path)
                    findings.append(Finding(
                        severity="low",
                        plugin_id=META.plugin_id,
                        title=f"WebSocket sends data immediately on connect: {ws_path}",
                        description=(
                            f"The WebSocket endpoint at {ws_path} sends data immediately after "
                            f"connection without any client request. This may disclose information."
                        ),
                        evidence=f"url={base}{ws_path} initial_data_len={len(data)} preview={data_preview}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.70,
                        remediation="Review what data is sent on initial WebSocket connection. Avoid sending sensitive information before authentication.",
                    ))

        return PluginResult(findings=findings, artifacts={"web.websocket_findings": ws_results})
