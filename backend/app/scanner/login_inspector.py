"""
Login-page inspector.

Fetches a login page, parses the HTML forms, and returns a structured
description so the UI can pre-fill username/password field names instead
of asking the user to guess.

Pure stdlib + httpx + regex — no headless browser. Will not see forms
that are rendered exclusively in JavaScript (SPAs); the result includes
heuristic warnings when the page looks JS-heavy.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("vulnscan.login_inspector")

_MAX_BYTES = 1 * 1024 * 1024  # 1 MB cap on login-page HTML
_DEFAULT_TIMEOUT = 10.0

# ─── Regex patterns (mirror auth_session / owasp_scanner) ───────────────────

_FORM_BLOCK_RE = re.compile(r"<form([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_TAG_RE = re.compile(r"<(?:input|select|textarea)\b([^>]*)/?>", re.I)
_ATTR_RE = re.compile(r'(\w[\w:-]*)\s*=\s*"([^"]*)"', re.I)
_ATTR_RE_SQ = re.compile(r"(\w[\w:-]*)\s*=\s*'([^']*)'", re.I)
_REQUIRED_FLAG_RE = re.compile(r"\brequired\b", re.I)

_CSRF_NAME_RE = re.compile(
    r"(?:csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|nonce|csrfmiddlewaretoken)",
    re.I,
)

# Warning detectors
_RECAPTCHA_RE = re.compile(r'(class="[^"]*g-recaptcha|google\.com/recaptcha)', re.I)
_HCAPTCHA_RE = re.compile(r'(class="[^"]*h-captcha|hcaptcha\.com)', re.I)
_TURNSTILE_RE = re.compile(r'(cf-turnstile|challenges\.cloudflare\.com)', re.I)
_BUNDLED_JS_RE = re.compile(r'<script[^>]*src=', re.I)


# ─── Data classes ───────────────────────────────────────────────────────────

@dataclass
class InspectField:
    name: str
    type: str = "text"
    required: bool = False
    value: str = ""
    is_csrf: bool = False


@dataclass
class InspectForm:
    action: str
    method: str
    fields: list[InspectField] = field(default_factory=list)
    username_candidates: list[str] = field(default_factory=list)
    password_candidates: list[str] = field(default_factory=list)
    csrf_candidates: list[str] = field(default_factory=list)
    score: float = 0.0


@dataclass
class InspectResult:
    login_url: str
    final_url: str
    fetched_status: int
    forms: list[InspectForm] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "login_url": self.login_url,
            "final_url": self.final_url,
            "fetched_status": self.fetched_status,
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "fields": [
                        {
                            "name": x.name, "type": x.type,
                            "required": x.required, "value": x.value,
                            "is_csrf": x.is_csrf,
                        }
                        for x in f.fields
                    ],
                    "username_candidates": f.username_candidates,
                    "password_candidates": f.password_candidates,
                    "csrf_candidates": f.csrf_candidates,
                    "score": round(f.score, 2),
                }
                for f in self.forms
            ],
            "warnings": self.warnings,
            "error": self.error,
        }


# ─── Parsing helpers ────────────────────────────────────────────────────────

def _attrs(tag_attrs: str) -> dict[str, str]:
    """Pull key=value attributes out of a raw tag-attribute string."""
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag_attrs):
        out[m.group(1).lower()] = m.group(2)
    for m in _ATTR_RE_SQ.finditer(tag_attrs):
        # double-quoted attrs win if both forms present (rare)
        out.setdefault(m.group(1).lower(), m.group(2))
    return out


def _parse_form(form_attrs: str, form_body: str, base_url: str) -> InspectForm:
    fa = _attrs(form_attrs)
    action_raw = fa.get("action", "") or base_url
    method = (fa.get("method") or "GET").upper()

    # Resolve relative action against the page URL
    action = urljoin(base_url, action_raw) if action_raw else base_url

    fields: list[InspectField] = []
    for m in _INPUT_TAG_RE.finditer(form_body):
        attrs = _attrs(m.group(1))
        name = attrs.get("name", "")
        if not name:
            continue
        ftype = (attrs.get("type") or "text").lower()
        is_required = bool(_REQUIRED_FLAG_RE.search(m.group(1) or ""))
        value = attrs.get("value", "")
        is_csrf = bool(_CSRF_NAME_RE.search(name))
        fields.append(InspectField(
            name=name, type=ftype, required=is_required,
            value=value if not is_csrf else value[:24] + "…" if len(value) > 24 else value,
            is_csrf=is_csrf,
        ))

    user_candidates = [
        f.name for f in fields
        if f.type in ("text", "email", "tel", "")
        and not f.is_csrf
        and f.type != "password"
    ]
    pass_candidates = [f.name for f in fields if f.type == "password"]
    csrf_candidates = [f.name for f in fields if f.is_csrf]

    # Rank: prefer names containing user/email/login keywords
    user_candidates.sort(
        key=lambda n: (
            0 if re.search(r"user|email|login|account|signin|userid", n, re.I) else 1,
            len(n),
        )
    )

    score = 0.0
    if pass_candidates:
        score += 0.5
    if user_candidates:
        score += 0.3
    if any(kw in (action or "").lower() for kw in ("login", "signin", "auth", "session")):
        score += 0.2
    if csrf_candidates:
        score += 0.1

    return InspectForm(
        action=action,
        method=method,
        fields=fields,
        username_candidates=user_candidates,
        password_candidates=pass_candidates,
        csrf_candidates=csrf_candidates,
        score=score,
    )


def _detect_warnings(html: str, forms: list[InspectForm]) -> list[str]:
    warns: list[str] = []
    if _RECAPTCHA_RE.search(html):
        warns.append("Page contains Google reCAPTCHA — automated login may fail. Use bearer/cookie auth if available.")
    if _HCAPTCHA_RE.search(html):
        warns.append("Page contains hCaptcha — automated login may fail. Use bearer/cookie auth if available.")
    if _TURNSTILE_RE.search(html):
        warns.append("Page contains Cloudflare Turnstile — automated login may fail.")

    script_count = len(_BUNDLED_JS_RE.findall(html))
    total_inputs = sum(len(f.fields) for f in forms)
    if len(html) > 200 * 1024 and total_inputs < 4 and script_count >= 3:
        warns.append(
            "Page is JavaScript-heavy and contains few static form inputs — login is likely "
            "rendered by JS (SPA). The static-HTML inspector cannot see SPA forms. "
            "Consider using bearer/cookie auth instead, or supply field names manually."
        )

    if forms and forms[0].score < 0.5:
        warns.append(
            "Highest-scoring form does not look like a login form (no password field detected, "
            "or form action doesn't match login keywords). Verify before saving."
        )
    return warns


# ─── Main entry point ───────────────────────────────────────────────────────

async def inspect_login_page(
    url: str,
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = _MAX_BYTES,
) -> InspectResult:
    """
    Fetch the login page and return a parsed InspectResult.

    SSRF blocking is the caller's responsibility — pass a vetted URL only.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return InspectResult(
            login_url=url, final_url=url, fetched_status=0,
            error="login_url must use http or https",
        )

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "VulnScan/2.1 LoginInspector"})
    except httpx.TimeoutException:
        return InspectResult(login_url=url, final_url=url, fetched_status=0,
                             error=f"Timed out fetching {url} after {timeout}s")
    except Exception as e:
        return InspectResult(login_url=url, final_url=url, fetched_status=0,
                             error=f"Could not fetch {url}: {e}")

    final_url = str(resp.url)

    # Cap body
    body = resp.text or ""
    if len(body) > max_bytes:
        body = body[:max_bytes]

    forms: list[InspectForm] = []
    for m in _FORM_BLOCK_RE.finditer(body):
        try:
            forms.append(_parse_form(m.group(1), m.group(2), final_url))
        except Exception as e:
            logger.warning("Failed to parse a form block: %s", e)

    # Sort by score descending so the best login candidate is at index 0
    forms.sort(key=lambda f: f.score, reverse=True)

    warnings = _detect_warnings(body, forms)

    return InspectResult(
        login_url=url,
        final_url=final_url,
        fetched_status=resp.status_code,
        forms=forms,
        warnings=warnings,
    )
