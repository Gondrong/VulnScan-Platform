"""
Shared HTTP Client for API Scanner
Provides a configured async HTTP client with:
- Semaphore-controlled concurrency (max 5 concurrent)
- Auth header injection (Bearer, API key, Basic)
- Payload injection into specific parameters
- Response comparison utilities for blind detection
"""
import asyncio
import base64
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("vulnscan.api_scanner.http")


@dataclass
class ApiResponse:
    """Standardized API response."""
    status: int
    body: str
    headers: dict[str, str]
    elapsed: float          # seconds
    content_type: str = ""
    body_length: int = 0

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type or self.body.strip().startswith(("{", "["))

    @property
    def is_xml(self) -> bool:
        return "xml" in self.content_type or self.body.strip().startswith("<?xml")

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or "<html" in self.body.lower()[:200]


class ApiHttpClient:
    """
    Async HTTP client for API security testing.
    Thread-safe with semaphore-based concurrency control.
    """

    def __init__(
        self,
        base_url: str,
        auth_config: dict | None = None,
        max_concurrent: int = 5,
        timeout: float = 10.0,
        verify_ssl: bool = False,
        secondary_auth_config: dict | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_config = auth_config or {}
        self.secondary_auth_config = secondary_auth_config or {}
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Build auth headers (primary + optional secondary identity)
        self._auth_headers = self._build_auth_headers(self.auth_config)
        self._secondary_auth_headers = (
            self._build_auth_headers(self.secondary_auth_config)
            if self.secondary_auth_config else {}
        )

        # SSL context
        self._ssl_context = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

        # Shared client (created lazily)
        self._client: httpx.AsyncClient | None = None

    @property
    def has_secondary_auth(self) -> bool:
        """True if a secondary identity has been configured."""
        return bool(self._secondary_auth_headers)

    def _build_auth_headers(self, cfg: dict) -> dict[str, str]:
        """Build authentication headers from a given auth config dict."""
        headers = {}
        if not cfg:
            return headers
        auth_type = cfg.get("type", "").lower()

        if auth_type == "bearer":
            token = cfg.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif auth_type == "apikey":
            key_name = cfg.get("key_name", "X-API-Key")
            key_value = cfg.get("key_value", "")
            key_in = cfg.get("key_in", "header")
            if key_value and key_in == "header":
                headers[key_name] = key_value

        elif auth_type == "basic":
            username = cfg.get("username", "")
            password = cfg.get("password", "")
            if username:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"

        # Custom headers
        custom = cfg.get("custom_headers", {})
        if isinstance(custom, dict):
            headers.update(custom)

        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the shared httpx client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=False,
                headers={
                    "User-Agent": "VulnScan-APIScanner/2.1",
                    "Accept": "application/json, text/html, */*",
                    **self._auth_headers,
                },
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        body: Any = None,
        headers: dict | None = None,
        content_type: str = "application/json",
    ) -> ApiResponse:
        """
        Send an HTTP request with concurrency control.
        Returns an ApiResponse with status, body, headers, timing.
        """
        async with self.semaphore:
            start = time.monotonic()
            try:
                client = await self._get_client()

                req_headers = {}
                if headers:
                    req_headers.update(headers)

                if method.upper() in ("POST", "PUT", "PATCH") and body is not None:
                    if content_type == "application/json":
                        import json
                        if isinstance(body, (dict, list)):
                            body_str = json.dumps(body)
                        else:
                            body_str = str(body)
                        req_headers["Content-Type"] = "application/json"
                        resp = await client.request(
                            method, path, params=params,
                            content=body_str.encode(),
                            headers=req_headers,
                        )
                    elif content_type == "application/xml":
                        req_headers["Content-Type"] = "application/xml"
                        resp = await client.request(
                            method, path, params=params,
                            content=str(body).encode(),
                            headers=req_headers,
                        )
                    elif content_type == "application/x-www-form-urlencoded":
                        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                        if isinstance(body, dict):
                            resp = await client.request(
                                method, path, params=params,
                                data=body,
                                headers=req_headers,
                            )
                        else:
                            resp = await client.request(
                                method, path, params=params,
                                content=str(body).encode(),
                                headers=req_headers,
                            )
                    else:
                        req_headers["Content-Type"] = content_type
                        resp = await client.request(
                            method, path, params=params,
                            content=str(body).encode(),
                            headers=req_headers,
                        )
                else:
                    resp = await client.request(
                        method, path, params=params,
                        headers=req_headers,
                    )

                elapsed = time.monotonic() - start
                body_text = resp.text[:100000]  # Cap at 100KB
                ct = resp.headers.get("content-type", "")

                return ApiResponse(
                    status=resp.status_code,
                    body=body_text,
                    headers=dict(resp.headers),
                    elapsed=elapsed,
                    content_type=ct,
                    body_length=len(body_text),
                )

            except httpx.TimeoutException:
                return ApiResponse(
                    status=0, body="", headers={},
                    elapsed=time.monotonic() - start,
                    content_type="", body_length=0,
                )
            except Exception as e:
                logger.debug("HTTP request failed: %s %s — %s", method, path, e)
                return ApiResponse(
                    status=0, body=str(e)[:200], headers={},
                    elapsed=time.monotonic() - start,
                    content_type="", body_length=0,
                )

    async def request_as(
        self,
        identity: str,
        method: str,
        path: str,
        params: dict | None = None,
        body: Any = None,
        headers: dict | None = None,
        content_type: str = "application/json",
    ) -> ApiResponse:
        """
        Send a request using a specific identity ("primary" or "secondary").
        For "secondary", the request swaps in the secondary auth headers
        (Authorization, API key, custom headers) for that single request.
        Falls back to a normal request when identity == "primary" or no
        secondary auth is configured.
        """
        if identity != "secondary" or not self._secondary_auth_headers:
            return await self.request(method, path, params=params, body=body,
                                      headers=headers, content_type=content_type)

        # Per-request headers override the httpx client's default headers
        # for matching names, so passing the secondary auth headers here
        # supplants the primary Authorization / API key for this call only.
        override = dict(headers) if headers else {}
        override.update(self._secondary_auth_headers)
        return await self.request(method, path, params=params, body=body,
                                  headers=override, content_type=content_type)

    async def send_payload(
        self,
        endpoint: Any,  # ApiEndpoint
        param_name: str,
        payload: str,
        inject_location: str = "auto",
    ) -> ApiResponse:
        """
        Inject a payload into a specific parameter of an endpoint.
        Auto-detects injection point based on parameter location.
        """
        from .spec_parser import ApiEndpoint

        method = endpoint.method
        path = endpoint.path

        # Find the parameter
        param = None
        for p in endpoint.parameters:
            if p.name == param_name:
                param = p
                break

        location = inject_location if inject_location != "auto" else (param.location if param else "query")

        if location == "query":
            # Inject into query parameter
            params = {param_name: payload}
            return await self.request(method, path, params=params)

        elif location == "path":
            # Replace path parameter
            injected_path = path.replace(f"{{{param_name}}}", payload)
            return await self.request(method, injected_path)

        elif location == "body":
            # Inject into JSON body
            import json
            body = {}
            for p in endpoint.parameters:
                if p.location == "body":
                    if p.name == param_name:
                        body[p.name] = payload
                    else:
                        body[p.name] = p.example or "test"
            return await self.request(method, path, body=body)

        elif location == "header":
            # Inject into header
            return await self.request(
                method, path,
                headers={param_name: payload},
            )

        else:
            # Default: query param
            return await self.request(method, path, params={param_name: payload})

    async def send_raw(
        self,
        method: str,
        path: str,
        body: str | dict | None = None,
        content_type: str = "application/json",
        extra_headers: dict | None = None,
    ) -> ApiResponse:
        """Send a raw request (no parameter injection, just direct)."""
        return await self.request(
            method, path, body=body,
            headers=extra_headers,
            content_type=content_type,
        )

    async def baseline_request(self, endpoint: Any) -> ApiResponse:
        """Send a normal request to establish baseline response."""
        from .spec_parser import ApiEndpoint

        # Build a request with example values
        params = {}
        body = {}
        for p in endpoint.parameters:
            val = p.example or ("1" if p.param_type == "integer" else "test")
            if p.location == "query":
                params[p.name] = val
            elif p.location == "body":
                body[p.name] = val

        if body and endpoint.method in ("POST", "PUT", "PATCH"):
            return await self.request(endpoint.method, endpoint.path, params=params or None, body=body)
        else:
            return await self.request(endpoint.method, endpoint.path, params=params or None)
