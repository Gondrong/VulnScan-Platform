import asyncio
import socket
import ssl

import httpx

# Ports to check for port scan
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 445, 3306, 5432, 6379, 8080, 8443, 9200, 27017]


async def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def discover_open_ports(host: str, timeout: float) -> list[int]:
    # Run all TCP checks concurrently — cap per-port at 5s for external/slow targets
    per_port = min(timeout, 5.0)
    results = await asyncio.gather(
        *[tcp_open(host, p, per_port) for p in COMMON_PORTS],
        return_exceptions=True,
    )
    return [
        port
        for port, result in zip(COMMON_PORTS, results)
        if result is True
    ]


async def http_fingerprint(
    host: str, timeout: float, port: int, tls: bool
) -> dict:
    """
    Perform an HTTP fingerprint request.
    host can be a hostname, IP, or full URL.
    """
    import re

    # If host already looks like a full URL, use it directly
    if re.match(r"^https?://", host, re.I):
        url = host
    else:
        scheme = "https" if tls else "http"
        if port in (80, 443):
            url = f"{scheme}://{host}"
        else:
            url = f"{scheme}://{host}:{port}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:
            r = await client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Extract generator meta tag from HTML
            generator = ""
            ct = headers.get("content-type", "")
            if "html" in ct:
                import re as _re
                gen_match = _re.search(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                    r.text[:8192], _re.I,
                )
                if not gen_match:
                    gen_match = _re.search(
                        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                        r.text[:8192], _re.I,
                    )
                if gen_match:
                    generator = gen_match.group(1).strip()

            return {
                "url": str(r.url),
                "status": r.status_code,
                "server": headers.get("server", ""),
                "powered_by": headers.get("x-powered-by", ""),
                "aspnet_version": headers.get("x-aspnet-version", ""),
                "aspnetmvc_version": headers.get("x-aspnetmvc-version", ""),
                "generator": generator,
                "content_type": ct,
                "port": port,
                "tls": tls,
            }
    except httpx.ConnectError as e:
        raise ConnectionError(f"Cannot connect to {url}: {e}") from e
    except httpx.TimeoutException as e:
        raise TimeoutError(f"Timeout connecting to {url}") from e


def tls_handshake(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "subject": cert.get("subject", []) if cert else [],
                    "issuer": cert.get("issuer", []) if cert else [],
                    "not_after": cert.get("notAfter", "") if cert else "",
                }
    except ssl.SSLError as e:
        raise RuntimeError(f"TLS error: {e}") from e
    except (OSError, socket.timeout) as e:
        raise RuntimeError(f"Connection error: {e}") from e
