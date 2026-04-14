"""
API Security Scanner — Orchestrator
Comprehensive API testing: ingests OpenAPI/Swagger/Postman specs,
dispatches to injection, config, and GraphQL sub-modules.

This plugin can run in two modes:
1. Engine mode: called by scan_target() as part of a normal scan
2. Standalone mode: called directly by the API scanner endpoint
"""
import asyncio
import json
import logging
import time
from typing import Any

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint, ScanContext

logger = logging.getLogger("vulnscan.api_scanner")

META = PluginMeta(
    plugin_id="api.scanner",
    name="API Security Scanner",
    category="api",
    depends_on=["fingerprint.http"],
    soft_depends_on=["owasp.web.scanner"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["api.scanner.findings", "api.scanner.endpoints"],
    enabled_by_default=False,  # Opt-in — requires spec upload or explicit enable
    timeout_seconds=120.0,
)

# Sub-check modules and their display names
_SUB_CHECKS = [
    ("config_checks", "API Configuration Checks"),
    ("spec_hygiene", "API Spec Hygiene"),
    ("sqli", "SQL Injection"),
    ("xss", "Cross-Site Scripting"),
    ("ssti", "Server-Side Template Injection"),
    ("cmdi", "OS Command Injection"),
    ("xxe", "XML External Entity"),
    ("ssrf", "Server-Side Request Forgery"),
    ("code_injection", "Code Injection"),
    ("graphql", "GraphQL Security"),
    ("jwt_checks", "JWT Security"),
    ("bola", "Broken Object-Level Authorization"),
    ("mass_assignment", "Mass Assignment / BOPLA"),
    ("excessive_data", "Excessive Data Exposure"),
    ("type_confusion", "Type Confusion / Parameter Pollution"),
]

# Common paths where OpenAPI/Swagger specs are exposed
_SPEC_DISCOVERY_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/api/openapi.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/docs/openapi.json", "/.well-known/openapi.json",
]


class Check(Plugin):
    """API Scanner orchestrator plugin."""

    async def run(self, target: str, ctx: ScanContext) -> PluginResult:
        """
        Engine mode: called by scan_target() during a normal scan.
        Attempts to auto-discover an API spec and run checks.
        """
        findings = []
        endpoints_data = []

        # Check if spec data was pre-loaded (from API scanner endpoint)
        spec_data = ctx.get("api.spec_data")
        api_config = ctx.get("api.scanner_config", {})

        if not spec_data:
            # Try to auto-discover API spec
            http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
            target_raw = ctx.get("target_raw", target)

            base_url = ""
            if target_raw.startswith("http"):
                base_url = target_raw.rstrip("/")
            elif http_data:
                base_url = http_data[0].get("url", "").rstrip("/")

            if not base_url:
                return PluginResult(
                    artifacts={"api.scanner.findings": 0, "api.scanner.endpoints": []},
                )

            # Try to fetch spec from common paths
            from .http_client import ApiHttpClient
            client = ApiHttpClient(base_url, max_concurrent=3, timeout=8.0)
            try:
                spec_data = await self._discover_spec(client, target, findings)
            finally:
                await client.close()

            if not spec_data:
                return PluginResult(
                    findings=findings,
                    artifacts={"api.scanner.findings": len(findings), "api.scanner.endpoints": []},
                )

            api_config = {"base_url": base_url, "checks": ["config_checks"]}

        # Run the full scan
        result = await self._execute_scan(spec_data, api_config, target, ctx)
        return result

    async def run_standalone(self, config: dict, progress_callback=None) -> list[Finding]:
        """
        Standalone mode: called directly from the API scanner endpoint.
        Full control over target, auth, checks.

        config: {
            "base_url": "https://api.target.com",
            "auth": {"type": "bearer", "token": "..."},
            "checks": ["sqli", "ssti", "config_checks", ...],
            "spec_data": {...},  # parsed spec or raw content
            "rate_limit_rps": 10,
            "graphql_endpoint": "/graphql",
        }
        """
        from .spec_parser import parse, ApiEndpoint
        from .http_client import ApiHttpClient

        base_url = config.get("base_url", "").rstrip("/")
        if not base_url:
            raise ValueError("base_url is required")

        # Parse spec if provided as raw content
        spec_data = config.get("spec_data")
        endpoints = []
        if spec_data:
            if isinstance(spec_data, str):
                endpoints = parse(spec_data)
            elif isinstance(spec_data, list):
                endpoints = spec_data  # Already parsed
            elif isinstance(spec_data, dict):
                endpoints = parse(json.dumps(spec_data))

        # Manual endpoints
        manual = config.get("manual_endpoints", [])
        for ep in manual:
            endpoints.append(ApiEndpoint(
                path=ep.get("path", "/"),
                method=ep.get("method", "GET").upper(),
                parameters=[],
                content_types=ep.get("content_types", ["application/json"]),
            ))

        if not endpoints:
            raise ValueError("No endpoints to scan — upload a spec or add manual endpoints")

        # Create HTTP client (with optional secondary identity for BOLA/BFLA)
        auth_config = config.get("auth", {})
        secondary_auth_config = config.get("secondary_auth") or None
        max_concurrent = min(config.get("max_concurrent", 5), 10)
        client = ApiHttpClient(
            base_url=base_url,
            auth_config=auth_config,
            max_concurrent=max_concurrent,
            timeout=config.get("timeout", 10.0),
            secondary_auth_config=secondary_auth_config,
        )

        target = base_url
        # Default to all known check IDs (fix prior bug iterating tuples wrong)
        selected_checks = set(config.get("checks", [cid for cid, _ in _SUB_CHECKS]))
        all_findings = []

        try:
            # Create a minimal context
            ctx = ScanContext()
            ctx.set("target_raw", target)
            ctx.set("target_host", target)
            ctx.set("scan_type", "api")
            # Pass raw spec for spec_hygiene's passive analysis
            if spec_data is not None:
                ctx.set("api.spec_raw", spec_data)

            total_checks = len([c for c, _ in _SUB_CHECKS if c in selected_checks])
            step = 0

            for check_module, check_name in _SUB_CHECKS:
                if check_module not in selected_checks:
                    continue

                step += 1
                if progress_callback:
                    try:
                        _r = progress_callback(step, total_checks, f"api.scanner.{check_module}", check_name, "running")
                        if asyncio.iscoroutine(_r):
                            await _r
                    except Exception:
                        pass

                logger.info("API Scanner: running %s (%d/%d)", check_name, step, total_checks)

                try:
                    module = _import_subcheck(check_module)
                    if module and hasattr(module, "check"):
                        check_findings = await asyncio.wait_for(
                            module.check(client, endpoints, ctx),
                            timeout=60.0,
                        )
                        all_findings.extend(check_findings)
                        logger.info("  %s: %d findings", check_name, len(check_findings))
                except asyncio.TimeoutError:
                    logger.warning("  %s: timed out", check_name)
                    all_findings.append(Finding(
                        severity="info",
                        plugin_id=f"api.scanner.{check_module}",
                        title=f"API check timed out: {check_name}",
                        evidence=f"check={check_module} timeout=60s",
                        affected=target,
                        fingerprint=stable_fingerprint(target, "api.scanner", check_module, "timeout"),
                    ))
                except Exception as e:
                    logger.error("  %s: error — %s", check_name, e)

                if progress_callback:
                    try:
                        _r = progress_callback(step, total_checks, f"api.scanner.{check_module}", check_name, "done")
                        if asyncio.iscoroutine(_r):
                            await _r
                    except Exception:
                        pass

        finally:
            await client.close()

        # Set target on all findings
        for f in all_findings:
            if not f.affected:
                f.affected = target

        return all_findings

    async def _execute_scan(
        self, spec_data: Any, config: dict, target: str, ctx: ScanContext,
    ) -> PluginResult:
        """Execute the scan with parsed spec data and config."""
        from .spec_parser import parse, ApiEndpoint
        from .http_client import ApiHttpClient

        base_url = config.get("base_url", "").rstrip("/")
        if not base_url:
            # Try to derive from target
            if target.startswith("http"):
                base_url = target.rstrip("/")
            else:
                base_url = f"http://{target}"

        # Parse endpoints
        endpoints = []
        if isinstance(spec_data, str):
            try:
                endpoints = parse(spec_data)
            except Exception as e:
                logger.warning("Failed to parse API spec: %s", e)
        elif isinstance(spec_data, list):
            endpoints = spec_data

        if not endpoints:
            return PluginResult(
                artifacts={"api.scanner.findings": 0, "api.scanner.endpoints": []},
            )

        # Create client
        auth_config = config.get("auth", {})
        secondary_auth_config = config.get("secondary_auth") or None
        client = ApiHttpClient(
            base_url=base_url,
            auth_config=auth_config,
            secondary_auth_config=secondary_auth_config,
        )
        all_findings = []

        # Make raw spec available to passive sub-checks (spec_hygiene)
        if spec_data is not None:
            ctx.set("api.spec_raw", spec_data)

        try:
            selected = set(config.get("checks", ["config_checks"]))

            for check_module, check_name in _SUB_CHECKS:
                if check_module not in selected:
                    continue

                try:
                    module = _import_subcheck(check_module)
                    if module and hasattr(module, "check"):
                        check_findings = await asyncio.wait_for(
                            module.check(client, endpoints, ctx),
                            timeout=60.0,
                        )
                        all_findings.extend(check_findings)
                except asyncio.TimeoutError:
                    logger.warning("API check %s timed out", check_module)
                except Exception as e:
                    logger.error("API check %s failed: %s", check_module, e)

        finally:
            await client.close()

        # Set target
        for f in all_findings:
            if not f.affected:
                f.affected = target

        return PluginResult(
            findings=all_findings,
            artifacts={
                "api.scanner.findings": len(all_findings),
                "api.scanner.endpoints": [
                    {"path": ep.path, "method": ep.method}
                    for ep in endpoints[:50]
                ],
            },
        )

    async def _discover_spec(self, client, target: str, findings: list) -> str | None:
        """Try to auto-discover an API spec from common paths."""
        for path in _SPEC_DISCOVERY_PATHS:
            try:
                resp = await client.request("GET", path)
                if resp.status == 200 and resp.body_length > 100:
                    # Check if it looks like a spec
                    body = resp.body
                    if any(kw in body[:500] for kw in ['"openapi"', '"swagger"', '"paths"', '"info"']):
                        findings.append(Finding(
                            severity="info",
                            plugin_id=META.plugin_id,
                            title=f"API specification discovered at {path}",
                            description=f"An OpenAPI/Swagger specification was found at {path}.",
                            evidence=f"path={path} size={resp.body_length} status={resp.status}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "spec_discovery", path),
                            remediation=(
                                f"[INFO] API spec exposed at {path}\n\n"
                                f"[RECOMMENDATION] If this is a production environment, consider "
                                f"restricting access to the API specification endpoint."
                            ),
                        ))
                        return body
            except Exception:
                continue

        return None


def _import_subcheck(name: str):
    """Lazily import a sub-check module."""
    try:
        import importlib
        return importlib.import_module(f".{name}", package="app.scanner.plugins.api_scanner")
    except ImportError as e:
        logger.warning("Could not import API scanner sub-check '%s': %s", name, e)
        return None
