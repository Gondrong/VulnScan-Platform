"""
Authentication session helper for authenticated web scanning.

Establishes a session via one of:
  • form login (with optional CSRF token harvest)
  • bearer token
  • static cookies
  • static request headers
  • HTTP basic auth

Returns an AuthSession whose `cookies` and `headers` dicts can be passed
straight into httpx.AsyncClient(...) by downstream HTTP plugins.
"""
import logging
import re
from urllib.parse import urljoin

import httpx

logger = logging.getLogger("vulnscan.auth_session")

_CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']*(?:csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken)[^"\']*)["\']'
    r'[^>]*value=["\']([^"\']*)["\']',
    re.I,
)
_CSRF_INPUT_RE_REV = re.compile(
    r'<input[^>]+value=["\']([^"\']*)["\'][^>]*name=["\']'
    r'([^"\']*(?:csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken)[^"\']*)["\']',
    re.I,
)


class AuthSession:
    """Result of an authentication attempt."""

    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.method: str = ""
        self.success: bool = False
        self.evidence: str = ""
        self.error: str = ""

    def to_dict(self) -> dict:
        return {
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
            "method": self.method,
            "success": self.success,
            "evidence": self.evidence,
            "error": self.error,
        }


async def establish_session(
    config: dict, base_url: str = "", timeout: float = 15.0,
) -> AuthSession:
    """
    Establish an authenticated session based on the provided config.

    config shapes:
      {"type": "form", "login_url": "...", "username": "...", "password": "...",
       "username_field": "username", "password_field": "password",
       "extra_form_fields": {...}, "success_indicator": "Logout",
       "failure_indicator": "Invalid credentials"}

      {"type": "bearer", "token": "..."}
      {"type": "cookie", "cookies": {"sessionid": "..."}}
      {"type": "header", "headers": {"X-API-Key": "..."}}
      {"type": "basic",  "username": "...", "password": "..."}
    """
    session = AuthSession()
    auth_type = ((config or {}).get("type") or "").lower()
    if not auth_type:
        session.error = "No auth type specified"
        return session
    session.method = auth_type

    try:
        if auth_type == "bearer":
            token = (config.get("token") or "").strip()
            if not token:
                session.error = "bearer auth requires 'token'"
                return session
            session.headers["Authorization"] = f"Bearer {token}"
            session.success = True
            session.evidence = f"Bearer token applied (len={len(token)})"
            return session

        if auth_type == "basic":
            import base64
            user = config.get("username", "")
            pwd = config.get("password", "")
            if not user:
                session.error = "basic auth requires 'username'"
                return session
            creds = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
            session.headers["Authorization"] = f"Basic {creds}"
            session.success = True
            session.evidence = f"Basic auth applied for user={user}"
            return session

        if auth_type == "cookie":
            cookies = config.get("cookies") or {}
            if not isinstance(cookies, dict) or not cookies:
                session.error = "cookie auth requires non-empty 'cookies' dict"
                return session
            session.cookies = {str(k): str(v) for k, v in cookies.items()}
            session.success = True
            session.evidence = f"Static cookies applied ({len(session.cookies)})"
            return session

        if auth_type == "header":
            headers = config.get("headers") or {}
            if not isinstance(headers, dict) or not headers:
                session.error = "header auth requires non-empty 'headers' dict"
                return session
            session.headers = {str(k): str(v) for k, v in headers.items()}
            session.success = True
            session.evidence = f"Static headers applied ({len(session.headers)})"
            return session

        if auth_type == "form":
            return await _form_login(config, base_url, timeout, session)

        session.error = f"Unsupported auth type: {auth_type}"
        return session

    except Exception as e:
        session.error = f"Auth session error: {e}"
        return session


async def _form_login(
    config: dict, base_url: str, timeout: float, session: AuthSession,
) -> AuthSession:
    login_url = (config.get("login_url") or "").strip()
    if not login_url:
        session.error = "form auth requires 'login_url'"
        return session
    if not login_url.startswith("http") and base_url:
        login_url = urljoin(base_url, login_url)

    # action_url: where to POST credentials. Set by the form inspector to the
    # form's actual <form action="…"> URL. Falls back to login_url for legacy
    # configs and for forms that POST to themselves.
    action_url = (config.get("action_url") or "").strip()
    if action_url and not action_url.startswith("http"):
        action_url = urljoin(login_url, action_url)
    if not action_url:
        action_url = login_url

    username = config.get("username", "")
    password = config.get("password", "")
    username_field = config.get("username_field", "username")
    password_field = config.get("password_field", "password")
    extra = config.get("extra_form_fields", {}) or {}
    success_pattern = config.get("success_indicator", "")
    failure_pattern = config.get("failure_indicator", "")

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True,
    ) as client:
        # Step 1 — fetch the login page to capture any CSRF tokens
        csrf_fields: dict[str, str] = {}
        try:
            r = await client.get(login_url)
            for m in _CSRF_INPUT_RE.finditer(r.text or ""):
                csrf_fields[m.group(1)] = m.group(2)
            for m in _CSRF_INPUT_RE_REV.finditer(r.text or ""):
                csrf_fields[m.group(2)] = m.group(1)
        except Exception as e:
            session.error = f"Could not load login page: {e}"
            return session

        # Step 2 — submit credentials
        form_data = {username_field: username, password_field: password}
        form_data.update(csrf_fields)
        form_data.update(extra)

        try:
            r = await client.post(action_url, data=form_data)
        except Exception as e:
            session.error = f"Login POST failed: {e}"
            return session

        # Step 3 — collect resulting cookies
        for cookie in client.cookies.jar:
            session.cookies[cookie.name] = cookie.value

        body = r.text or ""
        login_failed = bool(failure_pattern and failure_pattern in body)

        if success_pattern:
            if success_pattern in body and not login_failed:
                session.success = True
                session.evidence = f"Form login OK; success_indicator matched on {action_url}"
            else:
                # Maybe redirected — retry on base_url with the session cookies
                check_url = base_url or login_url
                try:
                    r2 = await client.get(check_url)
                    if success_pattern in (r2.text or ""):
                        session.success = True
                        session.evidence = f"Form login OK; success_indicator matched on {check_url}"
                    else:
                        session.error = f"success_indicator '{success_pattern}' not found"
                except Exception as e:
                    session.error = f"success_indicator check failed: {e}"
        else:
            if session.cookies and not login_failed:
                session.success = True
                session.evidence = (
                    f"Form login OK; got {len(session.cookies)} cookies "
                    "(no success_indicator configured)"
                )
            elif login_failed:
                session.error = f"failure_indicator '{failure_pattern}' matched"
            else:
                session.error = "No cookies set after login POST and no success_indicator configured"

    return session
