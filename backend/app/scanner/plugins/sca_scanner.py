"""
Software Composition Analysis (SCA) Scanner Plugin
Probes for exposed dependency manifest files and checks for known
critically vulnerable package versions.

Safety: All probes are GET-only and read-only. No modifications are made
to the target system.
"""
import asyncio
import re
import json

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.sca_scanner",
    name="Software Composition Analysis",
    category="web",
    depends_on=["fingerprint.http"],
    soft_depends_on=["recon.directory.crawl", "ext.ffuf"],
    consumes=["fingerprint.http", "recon.directories"],
    provides=["web.sca"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)

# ── Dependency manifest files to probe ────────────────────────────────
_MANIFEST_FILES = [
    ("/package.json", "nodejs", "npm"),
    ("/package-lock.json", "nodejs", "npm"),
    ("/yarn.lock", "nodejs", "yarn"),
    ("/composer.json", "php", "composer"),
    ("/composer.lock", "php", "composer"),
    ("/requirements.txt", "python", "pip"),
    ("/Pipfile.lock", "python", "pipenv"),
    ("/Gemfile.lock", "ruby", "bundler"),
    ("/pom.xml", "java", "maven"),
    ("/go.sum", "go", "gomod"),
]

# ── Known critically vulnerable packages ──────────────────────────────
# Format: (ecosystem, package_name, vulnerable_below, cve, severity, description)
_KNOWN_VULNS = [
    # Java / Maven
    ("java", "log4j-core", "2.17.0", "CVE-2021-44228", "critical",
     "Log4Shell - Remote code execution via JNDI lookup injection"),
    ("java", "log4j-api", "2.17.0", "CVE-2021-44228", "critical",
     "Log4Shell - Remote code execution via JNDI lookup injection"),
    ("java", "spring-core", "5.3.18", "CVE-2022-22965", "critical",
     "Spring4Shell - Remote code execution via data binding"),
    ("java", "commons-collections", "3.2.2", "CVE-2015-7501", "critical",
     "Apache Commons Collections deserialization RCE"),
    ("java", "struts2-core", "2.5.33", "CVE-2023-50164", "critical",
     "Apache Struts path traversal leading to RCE"),
    # Node.js / npm
    ("nodejs", "lodash", "4.17.21", "CVE-2021-23337", "high",
     "Prototype pollution and command injection in lodash"),
    ("nodejs", "minimist", "1.2.6", "CVE-2021-44906", "critical",
     "Prototype pollution in minimist argument parser"),
    ("nodejs", "node-fetch", "2.6.7", "CVE-2022-0235", "high",
     "Exposure of sensitive information to an unauthorized actor"),
    ("nodejs", "express", "4.17.3", "CVE-2022-24999", "high",
     "Open redirect in express via qs prototype pollution"),
    ("nodejs", "json5", "2.2.2", "CVE-2022-46175", "high",
     "Prototype pollution in JSON5 parser"),
    ("nodejs", "jsonwebtoken", "9.0.0", "CVE-2022-23529", "high",
     "Insecure key retrieval in jsonwebtoken"),
    ("nodejs", "axios", "0.21.2", "CVE-2021-3749", "high",
     "Server-side request forgery in axios"),
    ("nodejs", "glob-parent", "5.1.2", "CVE-2020-28469", "high",
     "Regular expression denial of service"),
    ("nodejs", "tar", "6.1.9", "CVE-2021-37713", "high",
     "Arbitrary file creation/overwrite via symlink"),
    ("nodejs", "path-parse", "1.0.7", "CVE-2021-23343", "medium",
     "ReDoS in path-parse"),
    ("nodejs", "underscore", "1.13.2", "CVE-2021-23358", "high",
     "Arbitrary code execution via template function"),
    ("nodejs", "shell-quote", "1.7.3", "CVE-2021-42740", "critical",
     "Command injection in shell-quote"),
    ("nodejs", "moment", "2.29.4", "CVE-2022-31129", "high",
     "ReDoS in moment.js date parsing"),
    ("nodejs", "decode-uri-component", "0.2.1", "CVE-2022-38900", "high",
     "Improper input validation leading to DoS"),
    # Python / pip
    ("python", "django", "4.0.6", "CVE-2022-34265", "high",
     "SQL injection in Trunc/Extract database functions"),
    ("python", "flask", "2.2.5", "CVE-2023-30861", "high",
     "Cookie confusion vulnerability in Flask"),
    ("python", "urllib3", "1.26.5", "CVE-2021-33503", "high",
     "ReDoS when parsing URL authority with many @ characters"),
    ("python", "requests", "2.31.0", "CVE-2023-32681", "medium",
     "Unintended leak of Proxy-Authorization header"),
    ("python", "pillow", "9.3.0", "CVE-2022-45198", "high",
     "Buffer overflow in Pillow image processing"),
    ("python", "setuptools", "65.5.1", "CVE-2022-40897", "high",
     "ReDoS in package_index.py"),
    ("python", "certifi", "2022.12.7", "CVE-2022-23491", "high",
     "Removal of TrustCor root certificates"),
    # PHP / Composer
    ("php", "guzzlehttp/guzzle", "7.4.5", "CVE-2022-31090", "high",
     "CURLOPT_HTTPAUTH leak on redirect"),
    ("php", "symfony/http-kernel", "5.4.20", "CVE-2022-24894", "high",
     "HTTP cache poisoning via headers"),
    ("php", "laravel/framework", "9.32.0", "CVE-2022-40482", "high",
     "File validation bypass in Laravel"),
    # Ruby / Bundler
    ("ruby", "rails", "7.0.4", "CVE-2023-22795", "high",
     "ReDoS vulnerability in Action Dispatch"),
    ("ruby", "nokogiri", "1.13.6", "CVE-2022-29181", "high",
     "Out-of-bounds write in libxml2 via Nokogiri"),
    ("ruby", "rack", "2.2.6.2", "CVE-2023-27530", "high",
     "Denial of service via multipart parsing"),
]


def _version_tuple(ver_str: str) -> tuple:
    """Convert version string to tuple for comparison."""
    parts = []
    for p in ver_str.split("."):
        try:
            parts.append(int(re.match(r"(\d+)", p).group(1)))
        except (AttributeError, ValueError):
            parts.append(0)
    return tuple(parts)


def _is_vulnerable(version: str, fixed_version: str) -> bool:
    """Check if version is below the fixed version."""
    try:
        return _version_tuple(version) < _version_tuple(fixed_version)
    except Exception:
        return False


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    """Parse package.json and extract dependencies with versions."""
    packages = []
    try:
        data = json.loads(text)
        for dep_key in ["dependencies", "devDependencies"]:
            deps = data.get(dep_key, {})
            if isinstance(deps, dict):
                for name, ver in deps.items():
                    # Strip version prefixes like ^, ~, >=
                    clean_ver = re.sub(r"^[^0-9]*", "", str(ver))
                    if clean_ver:
                        packages.append((name, clean_ver))
    except Exception:
        pass
    return packages


def _parse_package_lock(text: str) -> list[tuple[str, str]]:
    """Parse package-lock.json and extract packages with versions."""
    packages = []
    try:
        data = json.loads(text)
        # v2/v3 format
        pkgs = data.get("packages", {})
        if pkgs:
            for path, info in pkgs.items():
                name = info.get("name") or path.split("node_modules/")[-1]
                ver = info.get("version", "")
                if name and ver:
                    packages.append((name, ver))
        else:
            # v1 format
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                ver = info.get("version", "")
                if ver:
                    packages.append((name, ver))
    except Exception:
        pass
    return packages


def _parse_composer_json(text: str) -> list[tuple[str, str]]:
    """Parse composer.json for PHP dependencies."""
    packages = []
    try:
        data = json.loads(text)
        for dep_key in ["require", "require-dev"]:
            deps = data.get(dep_key, {})
            if isinstance(deps, dict):
                for name, ver in deps.items():
                    if name == "php":
                        continue
                    clean_ver = re.sub(r"^[^0-9]*", "", str(ver))
                    if clean_ver:
                        packages.append((name, clean_ver))
    except Exception:
        pass
    return packages


def _parse_composer_lock(text: str) -> list[tuple[str, str]]:
    """Parse composer.lock for PHP dependencies with exact versions."""
    packages = []
    try:
        data = json.loads(text)
        for pkg_list in [data.get("packages", []), data.get("packages-dev", [])]:
            for pkg in pkg_list:
                name = pkg.get("name", "")
                ver = re.sub(r"^v", "", pkg.get("version", ""))
                if name and ver:
                    packages.append((name, ver))
    except Exception:
        pass
    return packages


def _parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    """Parse Python requirements.txt."""
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match patterns like: package==1.2.3 or package>=1.2.3
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*[=><~!]+\s*([0-9][0-9.]*)", line)
        if m:
            packages.append((m.group(1).lower(), m.group(2)))
    return packages


def _parse_pipfile_lock(text: str) -> list[tuple[str, str]]:
    """Parse Pipfile.lock for Python dependencies."""
    packages = []
    try:
        data = json.loads(text)
        for section in ["default", "develop"]:
            deps = data.get(section, {})
            for name, info in deps.items():
                ver = info.get("version", "")
                clean_ver = re.sub(r"^[=]*", "", ver)
                if clean_ver:
                    packages.append((name.lower(), clean_ver))
    except Exception:
        pass
    return packages


def _parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    """Parse Ruby Gemfile.lock."""
    packages = []
    in_specs = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not stripped or (not line.startswith(" ") and stripped != ""):
                in_specs = False
                continue
            m = re.match(r"^([a-zA-Z0-9_-]+)\s+\(([0-9][0-9.]*)\)", stripped)
            if m:
                packages.append((m.group(1), m.group(2)))
    return packages


def _parse_pom_xml(text: str) -> list[tuple[str, str]]:
    """Parse Java pom.xml for dependencies."""
    packages = []
    # Simple regex-based extraction (not full XML parsing)
    deps = re.findall(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]+)</version>)?",
        text,
        re.DOTALL,
    )
    for group_id, artifact_id, version in deps:
        if version and not version.startswith("$"):
            packages.append((artifact_id.strip(), version.strip()))
    return packages


def _parse_go_sum(text: str) -> list[tuple[str, str]]:
    """Parse Go go.sum file."""
    packages = []
    seen = set()
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            name = parts[0]
            ver = re.sub(r"^v", "", parts[1].split("/")[0])
            key = (name, ver)
            if key not in seen:
                seen.add(key)
                # Use just the last part of the module path as name
                short_name = name.split("/")[-1]
                packages.append((short_name, ver))
    return packages


# Map file paths to their parsers and ecosystems
_PARSERS = {
    "/package.json": ("nodejs", _parse_package_json),
    "/package-lock.json": ("nodejs", _parse_package_lock),
    "/composer.json": ("php", _parse_composer_json),
    "/composer.lock": ("php", _parse_composer_lock),
    "/requirements.txt": ("python", _parse_requirements_txt),
    "/Pipfile.lock": ("python", _parse_pipfile_lock),
    "/Gemfile.lock": ("ruby", _parse_gemfile_lock),
    "/pom.xml": ("java", _parse_pom_xml),
    "/go.sum": ("go", _parse_go_sum),
    "/yarn.lock": ("nodejs", None),  # yarn.lock has complex format, skip parsing
}


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []
        sca_results: list[dict] = []

        # Determine base URLs
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                web_ports = [
                    p for p in ports
                    if p in (80, 443, 8080, 8443, 3000, 5000, 8000)
                ]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.sca": []})

        try:
            async with httpx.AsyncClient(
                timeout=min(ctx.policy.timeout_seconds, 8),
                verify=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=8),
            ) as client:
                for base_url in base_urls[:2]:
                    # Probe for all manifest files
                    tasks = []
                    for path, ecosystem, mgr in _MANIFEST_FILES:
                        url = f"{base_url}{path}"
                        tasks.append((path, ecosystem, mgr, client.get(url)))

                    results = await asyncio.gather(
                        *[t for _, _, _, t in tasks], return_exceptions=True
                    )

                    for (path, ecosystem, mgr, _), result in zip(tasks, results):
                        if isinstance(result, Exception):
                            continue
                        if result.status_code != 200:
                            continue
                        if len(result.text) < 10:
                            continue

                        # Validate this looks like a real manifest
                        # (not a custom 404 page)
                        if not self._looks_like_manifest(path, result.text):
                            continue

                        full_url = f"{base_url}{path}"

                        # Finding: exposed manifest file
                        fp = stable_fingerprint(
                            target, META.plugin_id, "exposed_manifest",
                            base_url, path
                        )
                        findings.append(Finding(
                            severity="high",
                            plugin_id=META.plugin_id,
                            title=f"Exposed dependency manifest: {path}",
                            description=(
                                f"The dependency manifest file {path} is publicly "
                                f"accessible at {full_url}. This reveals the "
                                f"application's {ecosystem} dependencies and their "
                                "versions, enabling attackers to identify known "
                                "vulnerable components."
                            ),
                            evidence=f"url={full_url} ecosystem={ecosystem} manager={mgr} size={len(result.text)}",
                            affected=target,
                            fingerprint=fp,
                            confidence=0.95,
                            remediation=(
                                f"[AFFECTED] Exposed {ecosystem} dependency manifest\n\n"
                                "[IMMEDIATE ACTION]\n"
                                f"1. Block access to {path} in your web server config:\n"
                                f"  Nginx: location = {path} {{ deny all; return 404; }}\n"
                                f"  Apache: <Files \"{path.lstrip('/')}\">"
                                " Require all denied </Files>\n\n"
                                "[PREVENTION]\n"
                                "- Keep dependency files outside the web root\n"
                                "- Use .htaccess or nginx rules to block all manifest files\n"
                                "- Review your deployment pipeline to exclude dev files"
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/"
                            ],
                        ))

                        sca_results.append({
                            "file": path,
                            "ecosystem": ecosystem,
                            "url": full_url,
                        })

                        # Parse and check for vulnerable packages
                        parser_info = _PARSERS.get(path)
                        if parser_info and parser_info[1] is not None:
                            eco, parse_fn = parser_info
                            packages = parse_fn(result.text)

                            for pkg_name, pkg_version in packages:
                                self._check_package_vulns(
                                    findings, target, eco, pkg_name,
                                    pkg_version, full_url
                                )

        except Exception:
            pass

        return PluginResult(
            findings=findings,
            artifacts={"web.sca": sca_results},
        )

    def _looks_like_manifest(self, path: str, text: str) -> bool:
        """Validate that the response looks like a real manifest file."""
        try:
            if path in ("/package.json", "/package-lock.json",
                        "/composer.json", "/composer.lock",
                        "/Pipfile.lock"):
                # Should be valid JSON
                json.loads(text)
                return True

            if path == "/requirements.txt":
                # Should have package==version patterns
                lines = text.strip().splitlines()
                pkg_lines = sum(
                    1 for l in lines[:20]
                    if re.match(r"^[A-Za-z0-9_.-]+\s*[=><~!]", l.strip())
                    or l.strip().startswith("#")
                    or l.strip().startswith("-")
                    or l.strip() == ""
                )
                return pkg_lines >= 2

            if path == "/Gemfile.lock":
                return "GEM" in text or "specs:" in text

            if path == "/pom.xml":
                return "<project" in text and "<dependency" in text

            if path == "/go.sum":
                # Lines with module paths and hashes
                return "h1:" in text

            if path == "/yarn.lock":
                return "# yarn lockfile" in text or "resolved" in text

            return len(text) > 20
        except Exception:
            return False

    def _check_package_vulns(
        self,
        findings: list[Finding],
        target: str,
        ecosystem: str,
        pkg_name: str,
        pkg_version: str,
        source_url: str,
    ) -> None:
        """Check a package against known vulnerable versions."""
        pkg_lower = pkg_name.lower().split("/")[-1]  # Handle scoped packages

        for eco, vuln_pkg, fixed_ver, cve, severity, description in _KNOWN_VULNS:
            if eco != ecosystem:
                continue
            if vuln_pkg.lower() != pkg_lower:
                continue
            if not _is_vulnerable(pkg_version, fixed_ver):
                continue

            fp = stable_fingerprint(
                target, META.plugin_id, "vuln_pkg", pkg_name,
                pkg_version, cve
            )
            findings.append(Finding(
                severity=severity,
                plugin_id=META.plugin_id,
                title=f"Vulnerable {ecosystem} package: {pkg_name} {pkg_version} ({cve})",
                description=(
                    f"{description}. Package '{pkg_name}' version {pkg_version} "
                    f"is vulnerable (fixed in {fixed_ver}). "
                    f"Found in {source_url}."
                ),
                evidence=f"package={pkg_name} version={pkg_version} fixed={fixed_ver} cve={cve} source={source_url}",
                affected=target,
                fingerprint=fp,
                confidence=0.90,
                cve=cve,
                remediation=(
                    f"[AFFECTED] {pkg_name} {pkg_version}\n"
                    f"[CVE] {cve}\n"
                    f"[FIXED IN] {fixed_ver}\n\n"
                    f"[ACTION] Update {pkg_name} to version {fixed_ver} or later:\n"
                    f"  npm:      npm install {pkg_name}@latest\n"
                    f"  pip:      pip install --upgrade {pkg_name}\n"
                    f"  composer: composer require {pkg_name}\n\n"
                    f"[DETAILS] https://nvd.nist.gov/vuln/detail/{cve}\n\n"
                    "[PREVENTION]\n"
                    "- Run dependency audits regularly (npm audit, pip-audit, etc.)\n"
                    "- Enable automated dependency updates (Dependabot, Renovate)\n"
                    "- Use a Software Bill of Materials (SBOM) for tracking"
                ),
                references=[
                    f"https://nvd.nist.gov/vuln/detail/{cve}",
                ],
            ))
