"""
GitHub Secret Scan Plugin
Searches GitHub's code search API for leaked credentials, secrets, and
configuration files associated with the target domain.

This plugin is opt-in (enabled_by_default=False) because it requires internet
access and is subject to GitHub's unauthenticated API rate limits.

No external tool dependencies — uses httpx for HTTP requests.
"""
import asyncio
import logging
import re
import urllib.parse

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.github_secrets")

META = PluginMeta(
    plugin_id="recon.github_secrets",
    name="GitHub Secret Scan",
    category="recon",
    depends_on=["fingerprint.http"],
    provides=["recon.github_secrets"],
    enabled_by_default=False,
    timeout_seconds=30.0,
)

# GitHub code search API (unauthenticated — very limited rate)
_GITHUB_SEARCH_API = "https://api.github.com/search/code"

# Search queries to run (domain is substituted at runtime)
# Each tuple: (query_suffix, description, severity_if_found)
_SEARCH_QUERIES: list[tuple[str, str, str]] = [
    (
        "password OR secret OR api_key",
        "credentials (password/secret/api_key)",
        "high",
    ),
    (
        "filename:.env",
        ".env configuration files",
        "high",
    ),
    (
        "filename:config.json OR filename:credentials.json",
        "configuration/credentials JSON files",
        "high",
    ),
    (
        "private_key OR PRIVATE KEY",
        "private key material",
        "critical",
    ),
    (
        "AWS_SECRET_ACCESS_KEY OR aws_access_key_id",
        "AWS credentials",
        "critical",
    ),
]

# Maximum total requests to GitHub API (unauthenticated rate limiting)
_MAX_REQUESTS = 5


def _extract_domain(target: str, target_raw: str) -> str:
    """Extract base domain from target."""
    raw = target_raw or target
    if re.match(r"^https?://", raw, re.I):
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or target
    else:
        host = target

    host = host.split(":")[0].strip().lower()

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return ""

    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _mask_snippet(text: str, max_length: int = 200) -> str:
    """Mask potentially sensitive values in text snippets."""
    # Mask anything that looks like a key/token value
    masked = re.sub(
        r"""((?:password|secret|key|token|credential|private)\s*[:=]\s*['"]?)([A-Za-z0-9+/=_\-]{8,})""",
        r"\1[REDACTED]",
        text,
        flags=re.I,
    )
    if len(masked) > max_length:
        masked = masked[:max_length] + "..."
    return masked


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []
        secrets_found: list[dict] = []

        domain = _extract_domain(target, target_raw)
        if not domain:
            return PluginResult(artifacts={"recon.github_secrets": []})

        # Rate-limit tracking
        requests_made = 0
        total_results = 0

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
            headers={
                "User-Agent": "VulnScan/2.1",
                "Accept": "application/vnd.github.v3.text-match+json",
            },
        ) as client:
            for query_suffix, description, severity in _SEARCH_QUERIES:
                if requests_made >= _MAX_REQUESTS:
                    break

                query = f"{domain} {query_suffix}"
                params = {
                    "q": query,
                    "per_page": 10,
                }

                try:
                    requests_made += 1
                    resp = await client.get(
                        _GITHUB_SEARCH_API,
                        params=params,
                    )

                    # Handle rate limiting
                    if resp.status_code == 403:
                        remaining = resp.headers.get("X-RateLimit-Remaining", "0")
                        logger.debug(
                            "GitHub API rate limited (remaining=%s)", remaining
                        )
                        findings.append(Finding(
                            severity="info",
                            plugin_id=META.plugin_id,
                            title="GitHub API rate limit reached",
                            evidence=f"status=403 remaining={remaining}",
                            affected=target,
                            fingerprint=stable_fingerprint(
                                target, META.plugin_id, "ratelimit"
                            ),
                            remediation=(
                                "GitHub API rate limit was reached. To get more results, "
                                "consider using an authenticated GitHub token or retrying later."
                            ),
                        ))
                        break

                    if resp.status_code == 422:
                        # Validation error — query may be too broad
                        logger.debug("GitHub search returned 422 for query: %s", query)
                        continue

                    if resp.status_code != 200:
                        logger.debug(
                            "GitHub search returned %d for query: %s",
                            resp.status_code,
                            query,
                        )
                        continue

                    data = resp.json()
                    items = data.get("items", [])
                    result_count = data.get("total_count", 0)
                    total_results += result_count

                    if not items:
                        continue

                    # Process results
                    repo_files: list[dict] = []
                    for item in items[:10]:
                        repo_name = item.get("repository", {}).get("full_name", "unknown")
                        file_path = item.get("path", "unknown")
                        html_url = item.get("html_url", "")

                        # Extract text match snippets
                        snippets: list[str] = []
                        for tm in item.get("text_matches", []):
                            fragment = tm.get("fragment", "")
                            if fragment:
                                snippets.append(_mask_snippet(fragment))

                        repo_files.append({
                            "repo": repo_name,
                            "path": file_path,
                            "url": html_url,
                            "snippets": snippets[:3],
                        })

                        secrets_found.append({
                            "query": description,
                            "repo": repo_name,
                            "path": file_path,
                            "url": html_url,
                            "severity": severity,
                        })

                    # Generate finding for this query
                    if repo_files:
                        evidence_items = []
                        for rf in repo_files[:5]:
                            evidence_items.append(
                                f"repo={rf['repo']} path={rf['path']}"
                            )
                            for snip in rf.get("snippets", [])[:1]:
                                evidence_items.append(f"  snippet: {snip}")

                        fp = stable_fingerprint(
                            target, META.plugin_id, description, str(result_count)
                        )

                        findings.append(Finding(
                            severity=severity,
                            plugin_id=META.plugin_id,
                            title=(
                                f"GitHub code search: {description} referencing "
                                f"{domain} ({result_count} result(s))"
                            ),
                            description=(
                                f"GitHub code search found {result_count} file(s) containing "
                                f"{description} that reference the domain {domain}. "
                                f"These may contain leaked credentials, API keys, or "
                                f"sensitive configuration exposed in public repositories."
                            ),
                            evidence=(
                                f"domain={domain} query={query_suffix} "
                                f"total_results={result_count}\n"
                                + "\n".join(evidence_items)
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.65,
                            remediation=(
                                f"[POTENTIAL SECRET LEAK — GitHub]\n"
                                f"Query: {domain} {query_suffix}\n"
                                f"Results: {result_count}\n\n"
                                f"[IMMEDIATE ACTION]\n"
                                f"1. Review each result to confirm if real credentials "
                                f"are exposed\n"
                                f"2. If credentials are confirmed, rotate them immediately\n"
                                f"3. Remove or remediate the repository content\n"
                                f"4. Check git history — secrets may persist in older commits\n\n"
                                f"[PREVENTION]\n"
                                f"- Enable GitHub secret scanning on all org repositories\n"
                                f"- Use pre-commit hooks (git-secrets, trufflehog) to prevent "
                                f"committing secrets\n"
                                f"- Store secrets in a vault (AWS Secrets Manager, HashiCorp "
                                f"Vault)\n"
                                f"- Add .env, config.json, credentials.* to .gitignore\n\n"
                                f"[FILES FOUND]\n"
                                + "\n".join(
                                    f"  - {rf['repo']}/{rf['path']} ({rf.get('url', '')})"
                                    for rf in repo_files[:10]
                                )
                            ),
                            references=[
                                "https://docs.github.com/en/code-security/secret-scanning",
                                "https://owasp.org/www-project-web-security-testing-guide/",
                            ],
                        ))

                    # Respect rate limiting — small delay between requests
                    await asyncio.sleep(1.0)

                except httpx.TimeoutException:
                    logger.debug("GitHub search timed out for query: %s", query)
                    continue
                except Exception as e:
                    logger.debug("GitHub search error for query %s: %s", query, e)
                    continue

        # Summary finding
        if secrets_found:
            fp_summary = stable_fingerprint(
                target, META.plugin_id, "summary", str(len(secrets_found))
            )
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=(
                    f"GitHub secret scan: {len(secrets_found)} potential leak(s) "
                    f"for {domain}"
                ),
                description=(
                    f"Searched GitHub for publicly accessible code referencing {domain} "
                    f"with credential-related keywords. Found {len(secrets_found)} "
                    f"file(s) across {len(set(s['repo'] for s in secrets_found))} "
                    f"repository(ies) that warrant manual review."
                ),
                evidence=(
                    f"domain={domain} requests_made={requests_made} "
                    f"total_results={total_results} files_found={len(secrets_found)}"
                ),
                affected=target,
                fingerprint=fp_summary,
                confidence=0.80,
                remediation=(
                    "Review all flagged GitHub results. Not all matches are confirmed "
                    "leaks — some may be example code, documentation, or test fixtures. "
                    "However, any real credential exposure must be treated as a security "
                    "incident requiring immediate credential rotation."
                ),
            ))
        else:
            fp_clean = stable_fingerprint(target, META.plugin_id, "clean")
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"GitHub secret scan: no leaks found for {domain}",
                description=(
                    f"Searched GitHub for publicly accessible code referencing {domain} "
                    f"with credential-related keywords. No results were found."
                ),
                evidence=(
                    f"domain={domain} requests_made={requests_made} total_results=0"
                ),
                affected=target,
                fingerprint=fp_clean,
                confidence=1.0,
            ))

        return PluginResult(
            findings=findings,
            artifacts={"recon.github_secrets": secrets_found},
        )
