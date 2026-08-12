"""
Server-side Software Composition Analysis (SCA) via SSH.

SSHs into the target server and audits:
  1. OS packages (dpkg/rpm) against known vulnerable versions
  2. Language-specific dependency files (package.json, requirements.txt, pom.xml, etc.)
  3. Installed runtimes and their versions (Node.js, Python, Java, PHP, Ruby, Go)

Requires SSH credentials configured in the scan profile.
Opt-in (enabled_by_default=False).
"""
import io
import json
import logging
import re

import paramiko

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.sca_server")

META = PluginMeta(
    plugin_id="audit.sca_server",
    name="Server-side SCA (Dependency Audit)",
    category="audit",
    depends_on=["net.port.discovery.v2"],
    soft_depends_on=["auth.ssh.inventory"],
    consumes=["net.open_ports", "inventory.ssh"],
    provides=["audit.sca_server"],
    enabled_by_default=False,
    timeout_seconds=90.0,
)

# ── Known vulnerable packages (OS-level) ─────────────────────────────────
# Format: (package_name_pattern, vulnerable_version_regex, fixed_version, cve, severity, description)
_OS_VULN_PACKAGES = [
    ("openssl", r"1\.[01]\.", "3.0+", "CVE-2022-0778", "high", "OpenSSL < 3.0 has multiple known vulnerabilities"),
    ("libssl", r"1\.[01]\.", "3.0+", "CVE-2022-0778", "high", "OpenSSL libssl < 3.0 vulnerable"),
    ("log4j", r"2\.(0|1[0-6])\.", "2.17.1+", "CVE-2021-44228", "critical", "Log4Shell — remote code execution"),
    ("sudo", r"1\.[89]\.[0-9]", "1.9.13+", "CVE-2023-22809", "high", "Sudo privilege escalation"),
    ("curl", r"7\.[0-7][0-9]\.", "8.0+", "CVE-2023-38545", "high", "curl SOCKS5 heap buffer overflow"),
    ("polkit", r"0\.(1[0-1][0-9]|10[0-5])", "0.120+", "CVE-2021-4034", "critical", "PwnKit — local privilege escalation"),
    ("apache2", r"2\.4\.(([0-4][0-9])|(5[0-5]))\b", "2.4.56+", "CVE-2023-25690", "high", "Apache HTTP request smuggling"),
    ("nginx", r"1\.(([0-1][0-9])|(2[0-3]))\.", "1.24+", "CVE-2022-41741", "medium", "Nginx mp4 module vulnerability"),
    ("openssh-server", r"[0-8]\.", "9.0+", "CVE-2023-38408", "medium", "OpenSSH pre-9.0 multiple vulnerabilities"),
    ("git", r"2\.([0-3][0-9])\.", "2.40+", "CVE-2023-22490", "medium", "Git arbitrary file read"),
    ("python3", r"3\.[0-9]\.", "3.10+", None, "low", "Python < 3.10 approaching end of life"),
    ("php", r"[0-7]\.", "8.1+", None, "medium", "PHP < 8.1 end of life"),
]

# ── Known vulnerable language packages ───────────────────────────────────
_LANG_VULN_PACKAGES = {
    # Node.js (from package.json / package-lock.json)
    "node": [
        ("lodash", r"^[0-3]\.|^4\.(0|1[0-6])\.", "4.17.21", "CVE-2021-23337", "high", "Prototype pollution"),
        ("minimist", r"^[0-1]\.[0-1]\.", "1.2.6", "CVE-2021-44906", "critical", "Prototype pollution"),
        ("node-forge", r"^[0-1]\.[01]\.", "1.3.0", "CVE-2022-24771", "high", "Signature verification bypass"),
        ("express", r"^[0-3]\.", "4.18.2", "CVE-2022-24999", "high", "Open redirect"),
        ("axios", r"^0\.(1[0-9]|2[0-1])\.", "0.21.2", "CVE-2021-3749", "high", "ReDoS"),
        ("jsonwebtoken", r"^[0-8]\.", "9.0.0", "CVE-2022-23529", "high", "JWT verification bypass"),
        ("tar", r"^[0-5]\.", "6.1.9", "CVE-2021-37712", "high", "Arbitrary file overwrite"),
        ("glob-parent", r"^[0-4]\.", "5.1.2", "CVE-2020-28469", "high", "ReDoS"),
        ("ua-parser-js", r"^0\.", "1.0.33", "CVE-2022-25927", "high", "ReDoS"),
    ],
    # Python (from requirements.txt / Pipfile)
    "python": [
        ("django", r"^[0-2]\.|^3\.[01]\.", "3.2.18", "CVE-2023-23969", "high", "Potential DoS"),
        ("flask", r"^[01]\.", "2.3.2", "CVE-2023-30861", "high", "Cookie session vulnerability"),
        ("jinja2", r"^[0-2]\.", "3.1.2", "CVE-2024-22195", "medium", "XSS in template rendering"),
        ("requests", r"^2\.(0|1[0-9]|2[0-7])\.", "2.28.0", "CVE-2023-32681", "medium", "Proxy credential leak"),
        ("urllib3", r"^1\.(2[0-5])\.", "1.26.5", "CVE-2021-33503", "medium", "ReDoS"),
        ("pillow", r"^[0-8]\.", "9.3.0", "CVE-2022-45199", "high", "Buffer overflow"),
        ("cryptography", r"^(3[0-8]|[0-2])\.", "39.0.0", "CVE-2023-23931", "medium", "Memory corruption"),
        ("pyyaml", r"^[0-5]\.[0-3]", "6.0", "CVE-2020-14343", "critical", "Arbitrary code execution"),
        ("paramiko", r"^[0-2]\.", "3.1.0", "CVE-2023-48795", "medium", "Terrapin SSH prefix truncation"),
    ],
    # PHP (from composer.json / composer.lock)
    "php": [
        ("laravel/framework", r"^[0-8]\.", "9.0", None, "medium", "Laravel < 9 end of life"),
        ("guzzlehttp/guzzle", r"^[0-6]\.", "7.4.5", "CVE-2022-31090", "high", "Cookie header leak on redirect"),
        ("symfony/http-kernel", r"^[0-5]\.", "6.0", "CVE-2022-24894", "high", "Session fixation"),
        ("phpmailer/phpmailer", r"^[0-5]\.", "6.6.0", "CVE-2021-3603", "critical", "Object injection"),
        ("phpunit/phpunit", r"^[0-8]\.", "9.5.0", "CVE-2017-9841", "critical", "Remote code execution via eval-stdin.php"),
    ],
    # Ruby (from Gemfile.lock)
    "ruby": [
        ("rails", r"^[0-5]\.|^6\.[01]\.", "6.1.7", "CVE-2023-22795", "high", "ReDoS in Action Dispatch"),
        ("nokogiri", r"^1\.(1[0-2])\.", "1.13.10", "CVE-2022-24836", "high", "Uncontrolled resource consumption"),
        ("rack", r"^[0-2]\.[0-2]\.", "2.2.6", "CVE-2022-44570", "high", "ReDoS"),
    ],
    # Java (from pom.xml — extract groupId:artifactId)
    "java": [
        ("log4j-core", r"^2\.(0|1[0-6])\.", "2.17.1", "CVE-2021-44228", "critical", "Log4Shell RCE"),
        ("spring-core", r"^5\.[0-2]\.", "5.3.18", "CVE-2022-22965", "critical", "Spring4Shell RCE"),
        ("jackson-databind", r"^2\.[0-9]\.|^2\.1[0-2]\.", "2.13.4", "CVE-2022-42003", "high", "Deserialization vulnerability"),
        ("commons-text", r"^1\.[0-9]\.", "1.10.0", "CVE-2022-42889", "critical", "Text4Shell RCE"),
        ("gson", r"^2\.[0-7]\.", "2.8.9", "CVE-2022-25647", "high", "Deserialization DoS"),
    ],
}

# ── Dependency file locations to search ──────────────────────────────────
_DEP_FILE_SEARCH = [
    # (find command, language, parser_type)
    ("find /opt /srv /var/www /home /app /root -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null | head -20", "node", "package_json"),
    ("find /opt /srv /var/www /home /app /root -maxdepth 4 -name 'requirements.txt' 2>/dev/null | head -20", "python", "requirements_txt"),
    ("find /opt /srv /var/www /home /app /root -maxdepth 4 -name 'composer.json' -not -path '*/vendor/*' 2>/dev/null | head -10", "php", "composer_json"),
    ("find /opt /srv /var/www /home /app /root -maxdepth 4 -name 'Gemfile.lock' 2>/dev/null | head -10", "ruby", "gemfile_lock"),
    ("find /opt /srv /var/www /home /app /root -maxdepth 4 -name 'pom.xml' 2>/dev/null | head -10", "java", "pom_xml"),
    ("find /opt /srv /var/www /home /app /root -maxdepth 4 -name 'go.sum' 2>/dev/null | head -10", "go", "go_sum"),
]


def _parse_version(version_str: str) -> str:
    """Extract clean version number from various formats."""
    m = re.search(r"(\d+\.\d+[\.\d]*)", version_str)
    return m.group(1) if m else ""


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    """Parse package.json, return list of (name, version)."""
    try:
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        return [(k, v.lstrip("^~>=<")) for k, v in deps.items()]
    except Exception:
        return []


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse requirements.txt, return list of (name, version)."""
    results = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([a-zA-Z0-9_.-]+)\s*[=><!]+\s*([0-9][0-9.]*)", line)
        if m:
            results.append((m.group(1).lower(), m.group(2)))
    return results


def _parse_composer_json(content: str) -> list[tuple[str, str]]:
    """Parse composer.json, return list of (name, version)."""
    try:
        data = json.loads(content)
        deps = data.get("require", {})
        return [(k, v.lstrip("^~>=<")) for k, v in deps.items() if "/" in k]
    except Exception:
        return []


def _parse_gemfile_lock(content: str) -> list[tuple[str, str]]:
    """Parse Gemfile.lock, return list of (name, version)."""
    results = []
    for m in re.finditer(r"^\s+([a-zA-Z0-9_-]+)\s+\((\d+\.\d+[\.\d]*)\)", content, re.M):
        results.append((m.group(1).lower(), m.group(2)))
    return results


def _parse_pom_xml(content: str) -> list[tuple[str, str]]:
    """Parse pom.xml for dependencies, return list of (artifactId, version)."""
    results = []
    for m in re.finditer(
        r"<artifactId>([^<]+)</artifactId>\s*<version>([^<$]+)</version>",
        content,
    ):
        results.append((m.group(1).lower(), m.group(2)))
    return results


_PARSERS = {
    "package_json": _parse_package_json,
    "requirements_txt": _parse_requirements_txt,
    "composer_json": _parse_composer_json,
    "gemfile_lock": _parse_gemfile_lock,
    "pom_xml": _parse_pom_xml,
}


class Check(Plugin):
    async def run(self, target, ctx):
        open_ports = ctx.get("net.open_ports", []) or []
        if 22 not in open_ports:
            return PluginResult()

        # ── Get SSH credentials (same pattern as cis_benchmark) ──────
        ssh_data = ctx.get("inventory.ssh", {}) or {}
        ssh_host = ssh_data.get("host") or target
        ssh_port = int(ssh_data.get("port", 22))
        ssh_user = ssh_data.get("username")
        ssh_password = ssh_data.get("password")
        ssh_key_text = ssh_data.get("key_text")

        if not ssh_user:
            profile_opts = ctx.get("profile_options", {}) or {}
            auth = profile_opts.get("ssh_auth") or profile_opts.get("auth") or {}
            cred_id = auth.get("ssh_credential_id")
            if cred_id:
                try:
                    from app.db.session import SessionLocal
                    from app.db import models
                    from app.core.crypto import decrypt_str
                    db = SessionLocal()
                    cred = db.query(models.Credential).filter(models.Credential.id == cred_id).first()
                    if cred:
                        ssh_user = cred.username
                        ssh_password = decrypt_str(cred.secret_enc) if cred.secret_type == "password" else None
                        ssh_key_text = decrypt_str(cred.secret_enc) if cred.secret_type == "ssh_key" else None
                    db.close()
                except Exception as e:
                    logger.warning("SCA Server: failed to load SSH credential: %s", e)

        if not ssh_user:
            return PluginResult(findings=[Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title="Server SCA requires SSH credentials",
                description="Configure SSH credentials in the scan profile to enable server-side dependency auditing.",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "no_creds"),
            )])

        findings = []
        sca_results = []

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": ssh_host, "port": ssh_port, "username": ssh_user,
                "timeout": 15, "banner_timeout": 15, "auth_timeout": 15,
                "look_for_keys": False, "allow_agent": False,
            }
            if ssh_key_text:
                for cls in [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey]:
                    try:
                        connect_kwargs["pkey"] = cls.from_private_key(io.StringIO(ssh_key_text))
                        break
                    except Exception:
                        continue
            elif ssh_password:
                connect_kwargs["password"] = ssh_password

            client.connect(**connect_kwargs)

            def _exec(cmd, timeout=15):
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
                    return stdout.read().decode("utf-8", errors="ignore")
                except Exception:
                    return ""

            # ── Phase 1: OS Package Audit ─────────────────────────────
            logger.info("SCA Server: scanning OS packages on %s", target)
            os_packages = _exec("dpkg -l 2>/dev/null || rpm -qa --queryformat '%{NAME} %{VERSION}\\n' 2>/dev/null")

            vuln_os_count = 0
            for pkg_name, vuln_pattern, fix_ver, cve, severity, desc in _OS_VULN_PACKAGES:
                for line in os_packages.split("\n"):
                    if pkg_name in line.lower():
                        version = _parse_version(line)
                        if version and re.search(vuln_pattern, version):
                            vuln_os_count += 1
                            fp = stable_fingerprint(target, META.plugin_id, "os", pkg_name, version)
                            findings.append(Finding(
                                severity=severity,
                                plugin_id=META.plugin_id,
                                title=f"Vulnerable OS package: {pkg_name} {version}",
                                description=f"{desc}. Installed: {version}, fix: upgrade to {fix_ver}.",
                                evidence=f"package={pkg_name} version={version} fix={fix_ver} cve={cve or 'N/A'}",
                                affected=target,
                                fingerprint=fp,
                                cve=cve,
                                confidence=0.80,
                                remediation=(
                                    f"Upgrade {pkg_name} to {fix_ver} or later.\n"
                                    f"  Debian/Ubuntu: apt update && apt upgrade {pkg_name}\n"
                                    f"  RHEL/CentOS: yum update {pkg_name}\n"
                                    + (f"  CVE: https://nvd.nist.gov/vuln/detail/{cve}" if cve else "")
                                ),
                            ))
                            sca_results.append({"type": "os", "package": pkg_name, "version": version, "severity": severity})
                            break

            # ── Phase 2: Runtime Versions ─────────────────────────────
            logger.info("SCA Server: checking runtime versions on %s", target)
            runtimes = {
                "node": _exec("node --version 2>/dev/null"),
                "python": _exec("python3 --version 2>/dev/null"),
                "java": _exec("java -version 2>&1 | head -1"),
                "php": _exec("php --version 2>/dev/null | head -1"),
                "ruby": _exec("ruby --version 2>/dev/null"),
                "go": _exec("go version 2>/dev/null"),
            }

            for runtime, output in runtimes.items():
                version = _parse_version(output)
                if version:
                    sca_results.append({"type": "runtime", "name": runtime, "version": version})

            # ── Phase 3: Dependency File Scan ─────────────────────────
            logger.info("SCA Server: scanning dependency files on %s", target)
            vuln_dep_count = 0

            for find_cmd, lang, parser_type in _DEP_FILE_SEARCH:
                file_list = _exec(find_cmd).strip()
                if not file_list:
                    continue

                parser = _PARSERS.get(parser_type)
                if not parser:
                    continue

                vuln_db = _LANG_VULN_PACKAGES.get(lang, [])
                if not vuln_db:
                    continue

                for dep_file in file_list.split("\n")[:10]:
                    dep_file = dep_file.strip()
                    if not dep_file:
                        continue

                    content = _exec(f"cat '{dep_file}' 2>/dev/null", timeout=5)
                    if not content or content.startswith("ERROR"):
                        continue

                    packages = parser(content)

                    for pkg_name, pkg_version in packages:
                        for vuln_name, vuln_pattern, fix_ver, cve, severity, desc in vuln_db:
                            if vuln_name.lower() in pkg_name.lower():
                                if re.search(vuln_pattern, pkg_version):
                                    vuln_dep_count += 1
                                    fp = stable_fingerprint(target, META.plugin_id, "dep", pkg_name, pkg_version, dep_file)
                                    findings.append(Finding(
                                        severity=severity,
                                        plugin_id=META.plugin_id,
                                        title=f"Vulnerable dependency: {pkg_name} {pkg_version} ({lang})",
                                        description=(
                                            f"{desc}. Found in {dep_file}. "
                                            f"Installed: {pkg_version}, fix: upgrade to {fix_ver}."
                                        ),
                                        evidence=f"package={pkg_name} version={pkg_version} file={dep_file} fix={fix_ver} cve={cve or 'N/A'}",
                                        affected=target,
                                        fingerprint=fp,
                                        cve=cve,
                                        confidence=0.85,
                                        remediation=(
                                            f"Upgrade {pkg_name} to {fix_ver} or later.\n"
                                            f"File: {dep_file}\n"
                                            + (f"CVE: https://nvd.nist.gov/vuln/detail/{cve}\n" if cve else "")
                                        ),
                                    ))
                                    sca_results.append({
                                        "type": "dependency", "package": pkg_name,
                                        "version": pkg_version, "file": dep_file,
                                        "language": lang, "severity": severity,
                                    })
                                    break

            client.close()

            # ── Summary Finding ───────────────────────────────────────
            total_vulns = vuln_os_count + vuln_dep_count
            runtime_list = ", ".join(f"{r}={v}" for r, v in [(k, _parse_version(v)) for k, v in runtimes.items()] if v)

            findings.append(Finding(
                severity="critical" if total_vulns > 10 else "high" if total_vulns > 5 else "medium" if total_vulns > 0 else "info",
                plugin_id=META.plugin_id,
                title=f"Server SCA: {total_vulns} vulnerable packages found",
                description=(
                    f"Server-side SCA audit found {vuln_os_count} vulnerable OS packages "
                    f"and {vuln_dep_count} vulnerable dependencies.\n"
                    f"Runtimes detected: {runtime_list or 'none'}"
                ),
                evidence=f"os_vulns={vuln_os_count} dep_vulns={vuln_dep_count} runtimes={runtime_list}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
                confidence=0.90,
                remediation=(
                    f"Total vulnerable packages: {total_vulns}\n"
                    f"  OS packages: {vuln_os_count}\n"
                    f"  Dependencies: {vuln_dep_count}\n\n"
                    f"Run 'apt update && apt upgrade' (Debian/Ubuntu) or 'yum update' (RHEL) "
                    f"to update OS packages. Update language dependencies using their "
                    f"respective package managers (npm, pip, composer, gem, mvn)."
                ),
            ))

            logger.info(
                "SCA Server on %s: %d OS vulns, %d dep vulns, runtimes: %s",
                target, vuln_os_count, vuln_dep_count, runtime_list,
            )

        except Exception as e:
            logger.warning("SCA Server SSH error on %s: %s", target, e)
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Server SCA: SSH connection failed",
                description=f"Could not connect via SSH to {target}: {str(e)[:200]}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "ssh_error"),
            ))

        return PluginResult(findings=findings, artifacts={"audit.sca_server": sca_results})
