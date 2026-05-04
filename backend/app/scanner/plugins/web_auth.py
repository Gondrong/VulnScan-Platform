"""
Web Authentication plugin — establishes an authenticated session for
downstream web scanners (OWASP, dir crawl, injection plugins) to consume.

Reads auth config from profile options under 'web_auth':
  {
    "type": "form" | "bearer" | "basic" | "cookie" | "header",
    "credential_id": 5,        // optional — resolves to username/password
                                //            (or token, for bearer) at scan time
                                //            so secrets never live in options_json
    ...                         // per-type fields, see auth_session.py
  }

Writes the resulting session to ScanContext artifact 'web.auth_session'.
Plugins that perform HTTP requests can read this artifact and apply the
cookies/headers to their httpx.AsyncClient.

Disabled by default — opt-in by adding 'web.auth' to the profile selection
and providing a 'web_auth' block in profile options.
"""
import logging

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint
from app.scanner.auth_session import establish_session
from app.core.crypto import decrypt_str
from app.db.session import SessionLocal
from app.db import models

logger = logging.getLogger("vulnscan.plugin.web_auth")

META = PluginMeta(
    plugin_id="web.auth",
    name="Web Authentication Session",
    category="web_auth",
    provides=["web.auth_session"],
    enabled_by_default=False,
    timeout_seconds=20.0,
)


def _resolve_credential(auth_config: dict, ws_id: int | None) -> tuple[dict, str]:
    """
    If auth_config carries a credential_id, look up the credential in the
    workspace, decrypt it, and merge username/password (or token, for bearer)
    into a copy of the config. Returns (resolved_config, error_or_empty).
    Caller-provided fields take precedence — credential is a default.
    """
    cred_id = auth_config.get("credential_id")
    if not cred_id:
        return auth_config, ""

    if not ws_id:
        return auth_config, "credential_id set but no workspace_id in scan context"

    db = SessionLocal()
    try:
        cred = (
            db.query(models.Credential)
            .filter(
                models.Credential.id == int(cred_id),
                models.Credential.workspace_id == ws_id,
            )
            .first()
        )
        if not cred:
            return auth_config, f"credential #{cred_id} not found in workspace"

        try:
            secret = decrypt_str(cred.secret_enc or "")
        except Exception as e:
            return auth_config, f"could not decrypt credential #{cred_id}: {e}"

        merged = dict(auth_config)
        merged.pop("credential_id", None)

        atype = (merged.get("type") or "").lower()
        if atype == "bearer":
            merged.setdefault("token", secret)
        else:
            # form / basic / cookie / header all accept a username+password
            merged.setdefault("username", cred.username or "")
            merged.setdefault("password", secret)

        return merged, ""
    finally:
        try:
            db.close()
        except Exception:
            pass


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        options = ctx.get("profile_options", {}) or {}
        auth_config = options.get("web_auth") or {}

        if not auth_config or not auth_config.get("type"):
            # No-op when no auth is configured — keeps the artifact slot empty
            return PluginResult(
                findings=[],
                artifacts={"web.auth_session": None},
            )

        # Resolve credential reference (if any) before establishing session.
        # We intentionally do NOT inject the password directly into options_json
        # — secrets are kept in the encrypted Credentials table and only
        # materialized in-memory here.
        ws_id = ctx.get("workspace_id")
        auth_config, cred_err = _resolve_credential(auth_config, ws_id)
        if cred_err:
            logger.warning("web.auth credential resolution: %s", cred_err)
            return PluginResult(
                findings=[
                    Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title="Authenticated scan failed — credential not resolvable",
                        description=(
                            "The web_auth config references a credential that could not be "
                            "loaded from the credentials store. Web plugins will run "
                            "unauthenticated."
                        ),
                        evidence=f"credential_resolution_error={cred_err}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "cred_err"),
                        remediation=(
                            "Verify the credential still exists in Configuration → "
                            "Credentials and that SECRET_KEY hasn't changed since it was "
                            "saved. Re-save the credential if SECRET_KEY rotated."
                        ),
                    )
                ],
                artifacts={"web.auth_session": None},
            )

        # Resolve base_url for relative login_url
        if isinstance(target_raw, str) and target_raw.startswith("http"):
            base_url = target_raw
        else:
            scheme = ctx.get("target_scheme", "http")
            scheme = scheme if scheme in ("http", "https") else "http"
            base_url = f"{scheme}://{target}"

        sess = await establish_session(auth_config, base_url=base_url, timeout=15.0)
        artifact = sess.to_dict()

        if sess.success:
            finding = Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Authenticated session established ({sess.method})",
                evidence=(
                    f"method={sess.method} cookies={len(sess.cookies)} "
                    f"headers={len(sess.headers)} note={sess.evidence}"
                ),
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "ok", sess.method),
                remediation=(
                    "Authenticated scanning session is active. Subsequent web plugins "
                    "(OWASP scanner, directory crawl, injection plugins) will reuse "
                    "these credentials for higher coverage."
                ),
            )
            return PluginResult(
                findings=[finding],
                artifacts={"web.auth_session": artifact},
            )

        finding = Finding(
            severity="medium",
            plugin_id=META.plugin_id,
            title=f"Authenticated scan failed — falling back to unauthenticated ({sess.method or 'unknown'})",
            description=(
                "The configured authentication failed. Web plugins will continue "
                "without an authenticated session, which limits coverage of "
                "post-login functionality."
            ),
            evidence=f"method={sess.method} error={sess.error}",
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "fail", sess.method or "unknown"),
            remediation=(
                "Verify login_url, credentials, success_indicator, and form field names. "
                "For bearer/cookie auth, confirm the token/cookie is current and accepted "
                "by the target. Test the credentials manually with a browser/curl before "
                "rerunning the scan."
            ),
        )
        return PluginResult(
            findings=[finding],
            artifacts={"web.auth_session": artifact},
        )
