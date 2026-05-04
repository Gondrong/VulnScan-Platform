"""
Kubernetes API Scanner
Detects exposed Kubernetes API servers, kubelet APIs, and etcd instances.
Tests for unauthenticated access to cluster resources.
"""
import asyncio
import json
import re
import ssl

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="infra.k8s.api",
    name="Kubernetes API Scanner",
    category="infra",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["infra.k8s_findings"],
    enabled_by_default=True,
    timeout_seconds=25.0,
)

# K8s-related ports
_K8S_PORTS = {
    6443: "K8s API Server (HTTPS)",
    8443: "K8s API Server (Alt HTTPS)",
    8080: "K8s API Server (HTTP/Insecure)",
    10250: "Kubelet API",
    10255: "Kubelet Read-Only",
    2379: "etcd Client",
    2380: "etcd Peer",
    30000: "NodePort Range Start",
}

# API endpoints to probe
_K8S_ENDPOINTS = [
    ("/api", "K8s API root"),
    ("/api/v1", "K8s API v1"),
    ("/api/v1/namespaces", "Namespace listing"),
    ("/api/v1/pods", "Pod listing"),
    ("/api/v1/secrets", "Secrets listing"),
    ("/api/v1/nodes", "Node listing"),
    ("/api/v1/services", "Service listing"),
    ("/api/v1/configmaps", "ConfigMap listing"),
    ("/apis", "API groups"),
    ("/version", "Version info"),
    ("/healthz", "Health check"),
    ("/metrics", "Prometheus metrics"),
]

_KUBELET_ENDPOINTS = [
    ("/pods", "Kubelet pod list"),
    ("/runningpods/", "Running pods"),
    ("/metrics", "Kubelet metrics"),
    ("/spec/", "Node spec"),
    ("/stats/summary", "Node stats"),
]

_ETCD_ENDPOINTS = [
    ("/version", "etcd version"),
    ("/v2/keys/", "etcd v2 keys"),
    ("/v3/kv/range", "etcd v3 range"),
    ("/health", "etcd health"),
]


async def _fetch(host: str, port: int, path: str, use_tls: bool = True,
                 timeout: float = 5.0) -> tuple[int, str, dict]:
    """Send HTTP GET, return (status, body, headers)."""
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

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VulnScan/2.1\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status, body, headers
    except Exception:
        return 0, "", {}


def _is_k8s_response(body: str) -> bool:
    """Check if response looks like a Kubernetes API response."""
    k8s_indicators = ["apiVersion", "kind", "metadata", "items", "selfLink", "resourceVersion"]
    return any(ind in body for ind in k8s_indicators)


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        findings = []
        k8s_results = []

        # Find K8s-related ports
        k8s_ports = [(p, _K8S_PORTS[p]) for p in ports if p in _K8S_PORTS]

        # Also probe common K8s ports that might not be in the port scan
        for p in [6443, 10250, 10255, 2379]:
            if p not in ports:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, p), timeout=3.0
                    )
                    writer.close()
                    k8s_ports.append((p, _K8S_PORTS.get(p, f"Port {p}")))
                except Exception:
                    pass

        if not k8s_ports:
            return PluginResult(artifacts={"infra.k8s_findings": []})

        for port, service_name in k8s_ports:
            use_tls = port in (6443, 8443, 2379)

            # ── K8s API Server (6443, 8443, 8080) ─────────────────────
            if port in (6443, 8443, 8080):
                for path, desc in _K8S_ENDPOINTS:
                    status, body, headers = await _fetch(target, port, path, use_tls)

                    if status == 200 and _is_k8s_response(body):
                        # Unauthenticated access to K8s API!
                        severity = "critical" if "secrets" in path or "pods" in path else "high"

                        # Try to extract useful info
                        try:
                            data = json.loads(body)
                            item_count = len(data.get("items", []))
                            kind = data.get("kind", "unknown")
                        except Exception:
                            item_count = 0
                            kind = "unknown"

                        fp = stable_fingerprint(target, META.plugin_id, "api", str(port), path)
                        findings.append(Finding(
                            severity=severity,
                            plugin_id=META.plugin_id,
                            title=f"K8s API exposed: {desc} ({port})",
                            description=(
                                f"The Kubernetes API server at {target}:{port} allows unauthenticated "
                                f"access to {path}. Returned {kind} with {item_count} item(s). "
                                f"An attacker can enumerate cluster resources, read secrets, "
                                f"and potentially deploy malicious containers."
                            ),
                            evidence=(
                                f"host={target} port={port} path={path} status={status} "
                                f"kind={kind} items={item_count} tls={use_tls} "
                                f"preview={body[:200]}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.95,
                            remediation=(
                                f"[{'CRITICAL' if severity == 'critical' else 'HIGH'}] K8s API exposed at port {port}\n\n"
                                f"[IMMEDIATE ACTION]\n"
                                f"1. Enable RBAC: --authorization-mode=RBAC\n"
                                f"2. Disable anonymous auth: --anonymous-auth=false\n"
                                f"3. Require client certificates\n"
                                f"4. Restrict network access to API server\n\n"
                                f"[ALSO]\n"
                                f"- Never expose port {port} to the internet\n"
                                f"- Use NetworkPolicies to segment cluster traffic\n"
                                f"- Audit RBAC bindings: kubectl get clusterrolebindings"
                            ),
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
                        ))
                        k8s_results.append({"port": port, "path": path, "type": "api_exposed"})

                    elif status == 403:
                        # API exists but auth is required (good)
                        k8s_results.append({"port": port, "path": path, "type": "auth_required"})
                        break  # Auth works, don't test more paths

                # Version disclosure
                status, body, _ = await _fetch(target, port, "/version", use_tls)
                if status == 200:
                    try:
                        ver = json.loads(body)
                        version = ver.get("gitVersion", "unknown")
                        fp = stable_fingerprint(target, META.plugin_id, "version", str(port))
                        findings.append(Finding(
                            severity="low",
                            plugin_id=META.plugin_id,
                            title=f"Kubernetes version disclosed: {version}",
                            evidence=f"host={target} port={port} version={version} platform={ver.get('platform', '')}",
                            affected=target,
                            fingerprint=fp,
                            confidence=1.0,
                            remediation=f"K8s version {version} is exposed. Check for known CVEs for this version.",
                        ))
                    except Exception:
                        pass

            # ── Kubelet API (10250, 10255) ─────────────────────────────
            elif port in (10250, 10255):
                kubelet_tls = port == 10250
                for path, desc in _KUBELET_ENDPOINTS:
                    status, body, _ = await _fetch(target, port, path, kubelet_tls)

                    if status == 200 and len(body) > 50:
                        fp = stable_fingerprint(target, META.plugin_id, "kubelet", str(port), path)
                        findings.append(Finding(
                            severity="high" if port == 10250 else "medium",
                            plugin_id=META.plugin_id,
                            title=f"Kubelet API exposed: {desc} ({port})",
                            description=(
                                f"The Kubelet API at {target}:{port}{path} is accessible without authentication. "
                                f"An attacker can list running pods, exec into containers, or extract environment variables."
                            ),
                            evidence=f"host={target} port={port} path={path} status={status} body_len={len(body)}",
                            affected=target,
                            fingerprint=fp,
                            confidence=0.90,
                            remediation=(
                                f"[HIGH] Kubelet API exposed on port {port}\n\n"
                                f"[FIX]\n"
                                f"1. Enable kubelet authentication: --authentication-token-webhook=true\n"
                                f"2. Enable authorization: --authorization-mode=Webhook\n"
                                f"3. Disable read-only port: --read-only-port=0\n"
                                f"4. Restrict network access to kubelet ports"
                            ),
                            references=["https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/"],
                        ))
                        k8s_results.append({"port": port, "path": path, "type": "kubelet_exposed"})
                        break

            # ── etcd (2379, 2380) ──────────────────────────────────────
            elif port in (2379, 2380):
                for path, desc in _ETCD_ENDPOINTS:
                    status, body, _ = await _fetch(target, port, path, use_tls)

                    if status == 200 and len(body) > 10:
                        fp = stable_fingerprint(target, META.plugin_id, "etcd", str(port), path)
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"etcd exposed: {desc} ({port})",
                            description=(
                                f"The etcd datastore at {target}:{port} is accessible. "
                                f"etcd stores all Kubernetes cluster state including secrets, "
                                f"service accounts, and configuration. Full cluster compromise is possible."
                            ),
                            evidence=f"host={target} port={port} path={path} status={status} preview={body[:200]}",
                            affected=target,
                            fingerprint=fp,
                            confidence=0.95,
                            remediation=(
                                f"[CRITICAL] etcd exposed on port {port}\n\n"
                                f"[IMMEDIATE ACTION]\n"
                                f"1. Enable client certificate authentication\n"
                                f"2. Restrict etcd access to API server only\n"
                                f"3. Encrypt etcd data at rest\n"
                                f"4. Never expose etcd ports to the network"
                            ),
                            references=["https://etcd.io/docs/latest/op-guide/security/"],
                        ))
                        k8s_results.append({"port": port, "path": path, "type": "etcd_exposed"})
                        break

        return PluginResult(findings=findings, artifacts={"infra.k8s_findings": k8s_results})
