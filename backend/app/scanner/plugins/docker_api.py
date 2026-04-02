"""
Docker API Scanner — checks for exposed Docker daemon APIs.

Tests common Docker API ports (2375 TCP, 2376 TLS) for:
  - Unauthenticated Docker API access
  - Container listing and info exposure
  - Image listing
  - Privileged container creation capability
  - Docker Swarm token exposure

All tests are read-only — no containers are created or modified.
"""
import asyncio
import json
import logging
import re
import ssl

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.docker_api")

META = PluginMeta(
    plugin_id="infra.docker.api",
    name="Docker API Exposure Scanner",
    category="network",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["infra.docker.findings"],
    enabled_by_default=True,
    timeout_seconds=15.0,
)

_DOCKER_PORTS = {
    2375: "http",   # Docker API (unencrypted)
    2376: "https",  # Docker API (TLS)
    9323: "http",   # Docker metrics
    2377: "https",  # Docker Swarm
}


async def _http_get(host: str, port: int, path: str, scheme: str = "http",
                    timeout: float = 5.0) -> tuple[int, str]:
    """Send HTTP GET and return (status_code, body)."""
    try:
        if scheme == "https":
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

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VulnScan/2.1\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        writer.close()

        text = data.decode("utf-8", errors="ignore")
        header_block, _, body = text.partition("\r\n\r\n")

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        return status, body
    except Exception:
        return 0, ""


async def _check_docker_port(host: str, port: int, scheme: str,
                             findings: list[Finding]):
    """Check a single Docker API port."""
    # Step 1: Ping endpoint
    status, body = await _http_get(host, port, "/_ping", scheme)
    if status != 200 or body.strip() != "OK":
        # Try /version as alternative
        status, body = await _http_get(host, port, "/version", scheme)
        if status != 200:
            return

    # Docker API is accessible!
    docker_version = ""
    api_version = ""
    os_info = ""
    arch = ""

    # Step 2: Get version info
    ver_status, ver_body = await _http_get(host, port, "/version", scheme)
    if ver_status == 200:
        try:
            ver = json.loads(ver_body)
            docker_version = ver.get("Version", "")
            api_version = ver.get("ApiVersion", "")
            os_info = ver.get("Os", "")
            arch = ver.get("Arch", "")
        except (json.JSONDecodeError, ValueError):
            pass

    # Step 3: List containers
    containers = []
    ct_status, ct_body = await _http_get(host, port, "/containers/json?all=true", scheme)
    if ct_status == 200:
        try:
            containers = json.loads(ct_body)
        except (json.JSONDecodeError, ValueError):
            pass

    # Step 4: List images
    images = []
    img_status, img_body = await _http_get(host, port, "/images/json", scheme)
    if img_status == 200:
        try:
            images = json.loads(img_body)
        except (json.JSONDecodeError, ValueError):
            pass

    # Step 5: Check system info (may reveal Swarm tokens)
    swarm_active = False
    info_status, info_body = await _http_get(host, port, "/info", scheme)
    if info_status == 200:
        try:
            info = json.loads(info_body)
            swarm_info = info.get("Swarm", {})
            if swarm_info.get("LocalNodeState") == "active":
                swarm_active = True
        except (json.JSONDecodeError, ValueError):
            pass

    # Check for privileged containers
    privileged_containers = []
    for ct in (containers or [])[:10]:
        ct_id = ct.get("Id", "")[:12]
        ct_name = (ct.get("Names") or ["/unknown"])[0].lstrip("/")
        inspect_status, inspect_body = await _http_get(
            host, port, f"/containers/{ct_id}/json", scheme
        )
        if inspect_status == 200:
            try:
                ct_info = json.loads(inspect_body)
                host_config = ct_info.get("HostConfig", {})
                if host_config.get("Privileged"):
                    privileged_containers.append(ct_name)
            except (json.JSONDecodeError, ValueError):
                pass

    container_count = len(containers) if isinstance(containers, list) else 0
    image_count = len(images) if isinstance(images, list) else 0

    # Main finding: Docker API exposed
    fp = stable_fingerprint(host, META.plugin_id, "api_exposed", str(port))
    findings.append(Finding(
        severity="critical",
        plugin_id=META.plugin_id,
        title=(
            f"Docker API exposed on port {port} — "
            f"{container_count} containers, {image_count} images"
        ),
        description=(
            f"The Docker daemon API on {host}:{port} is accessible without "
            f"authentication. Docker {docker_version} (API {api_version}) running on "
            f"{os_info}/{arch}. An attacker can:\n"
            f"- Create privileged containers to escape to host\n"
            f"- Mount the host filesystem (/ → container)\n"
            f"- Read secrets and environment variables from all containers\n"
            f"- Execute commands in running containers\n"
            f"- Pull/push images, deploy crypto miners\n"
            f"- Access Docker Swarm cluster (if active)\n\n"
            f"Containers: {container_count}, Images: {image_count}. "
            f"{'Swarm mode ACTIVE — cluster compromise possible. ' if swarm_active else ''}"
            f"{'Privileged containers found: ' + ', '.join(privileged_containers) + '. ' if privileged_containers else ''}"
        ),
        evidence=(
            f"host={host} port={port} scheme={scheme} "
            f"docker_version={docker_version} api_version={api_version} "
            f"os={os_info} arch={arch} "
            f"containers={container_count} images={image_count} "
            f"swarm_active={swarm_active} "
            f"privileged_containers={privileged_containers}"
        ),
        affected=f"{host}:{port}",
        fingerprint=fp,
        confidence=0.98,
        remediation=(
            "[CRITICAL — Docker API Exposed — Full Host Compromise]\n\n"
            "The Docker socket/API is accessible over the network without auth.\n"
            "This is equivalent to root access on the host.\n\n"
            "Immediate remediation:\n"
            "1. NEVER expose Docker API on 0.0.0.0 — bind to 127.0.0.1:\n"
            '   dockerd -H unix:///var/run/docker.sock  (remove -H tcp://...)\n'
            "2. If remote access needed, enable TLS mutual authentication:\n"
            "   dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem "
            "--tlskey=server-key.pem -H=0.0.0.0:2376\n"
            "3. Use Docker contexts or SSH tunnels instead of exposing TCP:\n"
            "   docker context create remote --docker 'host=ssh://user@host'\n"
            "4. Firewall: block ports 2375/2376/2377/9323 from all external access\n"
            "5. Enable Docker Content Trust: export DOCKER_CONTENT_TRUST=1\n"
            "6. Use rootless Docker mode if possible\n"
            "7. Audit all running containers for crypto miners and backdoors\n\n"
            "Reference: https://docs.docker.com/engine/security/protect-access/"
        ),
        references=[
            "https://docs.docker.com/engine/security/protect-access/",
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker",
        ],
    ))

    # Extra finding for Swarm
    if swarm_active:
        fp2 = stable_fingerprint(host, META.plugin_id, "swarm_exposed", str(port))
        findings.append(Finding(
            severity="critical",
            plugin_id=META.plugin_id,
            title="Docker Swarm cluster exposed — full cluster compromise",
            description=(
                f"Docker Swarm is active on {host}:{port}. An attacker can "
                f"retrieve Swarm join tokens, add malicious nodes, deploy "
                f"services across the entire cluster, and access all Swarm secrets."
            ),
            evidence=f"host={host} port={port} swarm_active=true",
            affected=f"{host}:{port}",
            fingerprint=fp2,
            confidence=0.95,
            remediation=(
                "1. Rotate Swarm join tokens: docker swarm join-token --rotate worker\n"
                "2. Enable mutual TLS for Swarm communication\n"
                "3. Restrict Swarm management plane to trusted networks\n"
                "4. Audit cluster for unauthorized nodes"
            ),
        ))


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []

        # Check all Docker-related ports
        tasks = []
        for port, scheme in _DOCKER_PORTS.items():
            if port in open_ports:
                tasks.append(_check_docker_port(target, port, scheme, findings))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return PluginResult(
            findings=findings,
            artifacts={"infra.docker.findings": len(findings)},
        )
