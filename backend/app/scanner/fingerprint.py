import asyncio, ssl, socket
import httpx

COMMON_PORTS = [21, 22, 25, 80, 443, 445, 5432, 6379, 8080, 8443, 9200]

async def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.close(); await w.wait_closed()
        return True
    except Exception:
        return False

async def discover_open_ports(host: str, timeout: float) -> list[int]:
    open_ports=[]
    for p in COMMON_PORTS:
        if await tcp_open(host, p, timeout):
            open_ports.append(p)
    return open_ports

async def http_fingerprint(host: str, timeout: float, port: int, tls: bool) -> dict:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}" if port not in (80,443) else f"{scheme}://{host}"
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        r = await client.get(url)
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {
            "url": str(r.url),
            "status": r.status_code,
            "server": headers.get("server",""),
            "powered_by": headers.get("x-powered-by",""),
            "content_type": headers.get("content-type",""),
        }

def tls_handshake(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return {"tls_version": ssock.version(), "cipher": ssock.cipher()}
