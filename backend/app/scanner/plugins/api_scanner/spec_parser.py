"""
API Specification Parser
Parses OpenAPI 3.x, Swagger 2.0, and Postman Collection v2.1 into
a normalized list of API endpoints for security testing.
"""
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("vulnscan.api_scanner.parser")

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class ApiParam:
    """A single API parameter."""
    name: str
    location: str       # query | path | header | cookie | body
    param_type: str     # string | integer | boolean | array | object
    required: bool = False
    example: str | None = None
    description: str = ""


@dataclass
class ApiEndpoint:
    """A normalized API endpoint ready for security testing."""
    path: str                           # /api/users/{id}
    method: str                         # GET, POST, PUT, DELETE, PATCH
    parameters: list[ApiParam] = field(default_factory=list)
    request_body: dict | None = None    # Schema for POST/PUT body
    content_types: list[str] = field(default_factory=list)  # application/json, application/xml
    auth_schemes: list[str] = field(default_factory=list)   # bearer, apiKey, basic
    tags: list[str] = field(default_factory=list)
    operation_id: str = ""
    summary: str = ""


def parse(raw: str | bytes, format_hint: str = "auto") -> list[ApiEndpoint]:
    """
    Parse an API spec into normalized endpoints.

    Args:
        raw: File content (JSON string, YAML string, or bytes)
        format_hint: "openapi3", "swagger2", "postman", or "auto"

    Returns:
        List of ApiEndpoint objects
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")

    raw = raw.strip()

    # Try JSON first
    data = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try YAML if JSON failed
    if data is None and HAS_YAML:
        try:
            data = yaml.safe_load(raw)
        except Exception:
            pass

    if data is None:
        raise ValueError("Could not parse spec as JSON or YAML")

    if not isinstance(data, dict):
        raise ValueError("Spec must be a JSON/YAML object")

    # Auto-detect format
    fmt = format_hint
    if fmt == "auto":
        fmt = _detect_format(data)

    if fmt == "openapi3":
        return _parse_openapi3(data)
    elif fmt == "swagger2":
        return _parse_swagger2(data)
    elif fmt == "postman":
        return _parse_postman_v21(data)
    else:
        raise ValueError(f"Unknown spec format: {fmt}")


def _detect_format(data: dict) -> str:
    """Auto-detect spec format from content."""
    if data.get("openapi", "").startswith("3."):
        return "openapi3"
    if data.get("swagger", "").startswith("2."):
        return "swagger2"
    if data.get("info", {}).get("schema", "").startswith("https://schema.getpostman.com"):
        return "postman"
    if "item" in data and "info" in data:
        return "postman"
    # Default to OpenAPI 3 if has paths
    if "paths" in data:
        return "openapi3"
    raise ValueError("Could not detect spec format. Use format_hint parameter.")


# ── OpenAPI 3.x Parser ────────────────────────────────────────────────

def _parse_openapi3(spec: dict) -> list[ApiEndpoint]:
    """Parse OpenAPI 3.x specification."""
    endpoints = []
    paths = spec.get("paths", {})

    # Extract global security schemes
    security_schemes = spec.get("components", {}).get("securitySchemes", {})
    global_auth = _extract_auth_schemes(security_schemes)

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Path-level parameters
        path_params = _parse_oa3_params(path_item.get("parameters", []))

        for method in ["get", "post", "put", "delete", "patch", "head", "options"]:
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            # Operation-level parameters (merge with path params)
            op_params = _parse_oa3_params(operation.get("parameters", []))
            all_params = {p.name: p for p in path_params}
            all_params.update({p.name: p for p in op_params})

            # Request body
            request_body = None
            content_types = []
            rb = operation.get("requestBody", {})
            if rb and isinstance(rb, dict):
                content = rb.get("content", {})
                content_types = list(content.keys())
                # Extract schema from first content type
                for ct, ct_data in content.items():
                    if isinstance(ct_data, dict) and "schema" in ct_data:
                        request_body = ct_data["schema"]
                        # Extract body params from schema properties
                        props = request_body.get("properties", {})
                        required_fields = request_body.get("required", [])
                        for prop_name, prop_schema in props.items():
                            all_params[prop_name] = ApiParam(
                                name=prop_name,
                                location="body",
                                param_type=prop_schema.get("type", "string"),
                                required=prop_name in required_fields,
                                example=str(prop_schema.get("example", "")) if prop_schema.get("example") else None,
                                description=prop_schema.get("description", ""),
                            )
                        break

            # Operation auth
            op_auth = global_auth.copy()
            op_security = operation.get("security", [])
            if op_security:
                for sec in op_security:
                    if isinstance(sec, dict):
                        for scheme_name in sec:
                            if scheme_name in security_schemes:
                                scheme = security_schemes[scheme_name]
                                auth_type = scheme.get("type", "").lower()
                                if auth_type == "http":
                                    op_auth.append(scheme.get("scheme", "bearer"))
                                elif auth_type == "apikey":
                                    op_auth.append("apiKey")
                                elif auth_type == "oauth2":
                                    op_auth.append("oauth2")

            endpoints.append(ApiEndpoint(
                path=path,
                method=method.upper(),
                parameters=list(all_params.values()),
                request_body=request_body,
                content_types=content_types or ["application/json"],
                auth_schemes=list(set(op_auth)),
                tags=operation.get("tags", []),
                operation_id=operation.get("operationId", ""),
                summary=operation.get("summary", ""),
            ))

    logger.info("Parsed OpenAPI 3.x spec: %d endpoints", len(endpoints))
    return endpoints


def _parse_oa3_params(params: list) -> list[ApiParam]:
    """Parse OpenAPI 3.x parameter list."""
    result = []
    for p in params:
        if not isinstance(p, dict):
            continue
        schema = p.get("schema", {})
        result.append(ApiParam(
            name=p.get("name", ""),
            location=p.get("in", "query"),
            param_type=schema.get("type", "string") if isinstance(schema, dict) else "string",
            required=p.get("required", False),
            example=str(p.get("example", "")) if p.get("example") else None,
            description=p.get("description", ""),
        ))
    return result


# ── Swagger 2.0 Parser ────────────────────────────────────────────────

def _parse_swagger2(spec: dict) -> list[ApiEndpoint]:
    """Parse Swagger 2.0 specification (convert to OpenAPI 3 pattern)."""
    endpoints = []
    base_path = spec.get("basePath", "")
    paths = spec.get("paths", {})

    # Security definitions
    security_defs = spec.get("securityDefinitions", {})
    global_auth = []
    for name, defn in security_defs.items():
        auth_type = defn.get("type", "").lower()
        if auth_type == "apikey":
            global_auth.append("apiKey")
        elif auth_type == "basic":
            global_auth.append("basic")
        elif auth_type == "oauth2":
            global_auth.append("oauth2")

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        full_path = base_path.rstrip("/") + path if base_path else path

        for method in ["get", "post", "put", "delete", "patch", "head", "options"]:
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            params = []
            content_types = operation.get("consumes", spec.get("consumes", ["application/json"]))
            request_body = None

            for p in operation.get("parameters", []):
                if not isinstance(p, dict):
                    continue
                location = p.get("in", "query")
                if location == "body":
                    request_body = p.get("schema", {})
                    # Extract body schema properties
                    props = request_body.get("properties", {}) if isinstance(request_body, dict) else {}
                    for prop_name, prop_schema in props.items():
                        params.append(ApiParam(
                            name=prop_name,
                            location="body",
                            param_type=prop_schema.get("type", "string"),
                            required=prop_name in request_body.get("required", []),
                            example=str(prop_schema.get("example", "")) if prop_schema.get("example") else None,
                        ))
                else:
                    params.append(ApiParam(
                        name=p.get("name", ""),
                        location=location,
                        param_type=p.get("type", "string"),
                        required=p.get("required", False),
                        example=str(p.get("default", "")) if p.get("default") else None,
                        description=p.get("description", ""),
                    ))

            endpoints.append(ApiEndpoint(
                path=full_path,
                method=method.upper(),
                parameters=params,
                request_body=request_body,
                content_types=content_types,
                auth_schemes=global_auth,
                tags=operation.get("tags", []),
                operation_id=operation.get("operationId", ""),
                summary=operation.get("summary", ""),
            ))

    logger.info("Parsed Swagger 2.0 spec: %d endpoints", len(endpoints))
    return endpoints


# ── Postman Collection v2.1 Parser ─────────────────────────────────────

def _parse_postman_v21(collection: dict) -> list[ApiEndpoint]:
    """Parse Postman Collection v2.1 format."""
    endpoints = []
    items = collection.get("item", [])
    _parse_postman_items(items, endpoints, tags=[])
    logger.info("Parsed Postman Collection: %d endpoints", len(endpoints))
    return endpoints


def _parse_postman_items(items: list, endpoints: list, tags: list):
    """Recursively parse Postman items (can be nested folders)."""
    for item in items:
        if not isinstance(item, dict):
            continue

        # Folder (has sub-items)
        if "item" in item:
            folder_name = item.get("name", "")
            _parse_postman_items(item["item"], endpoints, tags + [folder_name])
            continue

        # Request item
        request = item.get("request")
        if not request or not isinstance(request, dict):
            continue

        method = request.get("method", "GET").upper()

        # Parse URL
        url = request.get("url", {})
        if isinstance(url, str):
            path = _extract_path_from_url(url)
        elif isinstance(url, dict):
            raw = url.get("raw", "")
            path_parts = url.get("path", [])
            if path_parts:
                path = "/" + "/".join(str(p) for p in path_parts)
                # Replace Postman variables with path params
                path = re.sub(r":(\w+)", r"{\1}", path)
            else:
                path = _extract_path_from_url(raw)
        else:
            continue

        # Parse query params
        params = []
        if isinstance(url, dict):
            for q in url.get("query", []):
                if isinstance(q, dict):
                    params.append(ApiParam(
                        name=q.get("key", ""),
                        location="query",
                        param_type="string",
                        required=not q.get("disabled", False),
                        example=q.get("value"),
                    ))

            # Path variables
            for v in url.get("variable", []):
                if isinstance(v, dict):
                    params.append(ApiParam(
                        name=v.get("key", ""),
                        location="path",
                        param_type="string",
                        required=True,
                        example=v.get("value"),
                    ))

        # Parse headers
        for h in request.get("header", []):
            if isinstance(h, dict) and not h.get("disabled"):
                params.append(ApiParam(
                    name=h.get("key", ""),
                    location="header",
                    param_type="string",
                    required=False,
                    example=h.get("value"),
                ))

        # Parse body
        request_body = None
        content_types = ["application/json"]
        body = request.get("body", {})
        if isinstance(body, dict):
            mode = body.get("mode", "")
            if mode == "raw":
                raw_body = body.get("raw", "")
                try:
                    request_body = json.loads(raw_body)
                    if isinstance(request_body, dict):
                        for k, v in request_body.items():
                            params.append(ApiParam(
                                name=k,
                                location="body",
                                param_type=type(v).__name__ if v is not None else "string",
                                required=True,
                                example=str(v) if v is not None else None,
                            ))
                except json.JSONDecodeError:
                    request_body = {"raw": raw_body}

                # Check language option for content type
                options = body.get("options", {}).get("raw", {})
                lang = options.get("language", "json")
                if lang == "xml":
                    content_types = ["application/xml"]
                elif lang == "text":
                    content_types = ["text/plain"]

            elif mode == "formdata":
                content_types = ["multipart/form-data"]
                for fd in body.get("formdata", []):
                    if isinstance(fd, dict):
                        params.append(ApiParam(
                            name=fd.get("key", ""),
                            location="body",
                            param_type="string" if fd.get("type") != "file" else "file",
                            required=not fd.get("disabled", False),
                            example=fd.get("value"),
                        ))

            elif mode == "urlencoded":
                content_types = ["application/x-www-form-urlencoded"]
                for ue in body.get("urlencoded", []):
                    if isinstance(ue, dict):
                        params.append(ApiParam(
                            name=ue.get("key", ""),
                            location="body",
                            param_type="string",
                            required=not ue.get("disabled", False),
                            example=ue.get("value"),
                        ))

        # Auth
        auth_schemes = []
        auth = request.get("auth", {})
        if isinstance(auth, dict):
            auth_type = auth.get("type", "").lower()
            if auth_type in ("bearer", "basic", "apikey", "oauth2"):
                auth_schemes.append(auth_type)

        endpoints.append(ApiEndpoint(
            path=path,
            method=method,
            parameters=params,
            request_body=request_body,
            content_types=content_types,
            auth_schemes=auth_schemes,
            tags=tags,
            operation_id=item.get("name", ""),
            summary=item.get("name", ""),
        ))


# ── Helpers ────────────────────────────────────────────────────────────

def _extract_path_from_url(url: str) -> str:
    """Extract path from a full URL."""
    # Remove protocol + host
    url = re.sub(r"^https?://[^/]+", "", url)
    # Remove query string
    url = url.split("?")[0]
    # Replace Postman variables {{var}} with path params {var}
    url = re.sub(r"\{\{(\w+)\}\}", r"{\1}", url)
    return url or "/"


def _extract_auth_schemes(security_schemes: dict) -> list[str]:
    """Extract auth scheme types from OpenAPI securitySchemes."""
    schemes = []
    for name, defn in security_schemes.items():
        if not isinstance(defn, dict):
            continue
        auth_type = defn.get("type", "").lower()
        if auth_type == "http":
            schemes.append(defn.get("scheme", "bearer"))
        elif auth_type == "apikey":
            schemes.append("apiKey")
        elif auth_type == "oauth2":
            schemes.append("oauth2")
    return schemes


def endpoints_summary(endpoints: list[ApiEndpoint]) -> dict:
    """Generate a summary of parsed endpoints for display."""
    methods = {}
    tags = set()
    params_count = 0
    auth_types = set()

    for ep in endpoints:
        methods[ep.method] = methods.get(ep.method, 0) + 1
        tags.update(ep.tags)
        params_count += len(ep.parameters)
        auth_types.update(ep.auth_schemes)

    return {
        "total_endpoints": len(endpoints),
        "methods": methods,
        "tags": sorted(tags),
        "total_parameters": params_count,
        "auth_types": sorted(auth_types),
    }
