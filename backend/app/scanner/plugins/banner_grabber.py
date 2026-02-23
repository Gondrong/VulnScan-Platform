import asyncio, ssl, socket
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult

META = PluginMeta(
    plugin_id="fingerprint.banner.multi",
    name="Multi-Protocol Banner Grabber",
    category="fingerprint",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["fingerprint.banners"],
    enabled_by_default=True,
    timeout_seconds=5.0,
)

async def grab_tcp(host, port, payload=None, timeout=3.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if payload:
            w.write(payload); await w.drain()
        data = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close(); await w.wait_closed()
        return data.decode("utf-8", errors="ignore").strip()
    except:
        return ""

def tls_cert(host, port, timeout=3.0):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {"subject": ssock.getpeercert().get("subject", []), "version": ssock.version()}
    except:
        return None

class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        banners=[]
        tls=[]
        for p in ports:
            b=""
            if p==22: b = await grab_tcp(target, p)
            elif p==21: b = await grab_tcp(target, p)
            elif p==25: b = await grab_tcp(target, p)
            elif p==6379: b = await grab_tcp(target, p, b"INFO\r\n")
            elif p==9200: b = await grab_tcp(target, p, b"GET / HTTP/1.0\r\n\r\n")
            if b:
                banners.append({"port":p,"banner":b})
            if p in (443,8443):
                c = await asyncio.get_event_loop().run_in_executor(None, tls_cert, target, p)
                if c: tls.append({"port":p,"cert":c})
        return PluginResult(findings=[], artifacts={"fingerprint.banners": {"banners":banners, "tls_certs":tls}})
