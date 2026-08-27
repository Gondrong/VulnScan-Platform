"""
Client IP resolution behind reverse proxies.

`X-Forwarded-For` is attacker-controlled: any client can send it. Trusting it
blindly lets an attacker rotate the header to get a fresh rate-limit bucket per
request. Ignoring it entirely is just as wrong here — the bundled Vite dev-server
proxy sits between the browser and the backend, so *every* user would otherwise
share one bucket keyed on the proxy's container IP.

So: trust the header only when the request actually arrived from a configured
proxy, and walk the chain from the right, discarding trusted hops, to find the
first address the chain did not vouch for.
"""

import ipaddress
import logging

from fastapi import Request

from app.core.config import settings

logger = logging.getLogger("vulnscan.net")


def _networks() -> list:
    nets = []
    for entry in (settings.TRUSTED_PROXIES or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXIES entry: %r", entry)
    return nets


def _is_trusted(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def client_ip(request: Request) -> str:
    """Best-effort real client IP.

    Returns the socket peer unless that peer is a trusted proxy, in which case
    the rightmost non-trusted entry of X-Forwarded-For is used instead.
    """
    peer = request.client.host if request.client else ""
    if not peer:
        return "unknown"

    nets = _networks()
    if not nets or not _is_trusted(peer, nets):
        # Direct connection (or no proxies configured) — the header is untrusted.
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    hops = []
    for hop in forwarded.split(","):
        hop = hop.strip()
        if not hop:
            continue
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            # Garbage in the chain — a malformed entry must not become a
            # rate-limit bucket key of its own.
            logger.debug("Ignoring non-IP X-Forwarded-For entry: %r", hop)
            continue
        hops.append(hop)

    for hop in reversed(hops):
        if not _is_trusted(hop, nets):
            return hop

    # Every hop was a trusted proxy, or the header was absent/unusable.
    return hops[0] if hops else peer
