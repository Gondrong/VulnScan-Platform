"""
Linux Local Security Checks.
Matches installed packages against distro-specific advisories with release-aware fixed versions.
"""
import re

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="local.security.checks",
    name="Linux Local Security Checks",
    category="authenticated",
    depends_on=["auth.ssh.inventory"],
    consumes=["inventory.os", "inventory.packages"],
    provides=["local.security.findings"],
    enabled_by_default=True,
    timeout_seconds=15.0,
)

UBUNTU_ADVISORIES = [
    {
        "id": "USN-6560-2",
        "cve": "CVE-2023-6546",
        "package": "linux-image-generic",
        "fixed_version": "6.5.0-15",
        "severity": "high",
        "title": "Linux kernel use-after-free privilege escalation",
        "description": "Race condition in GSM multiplexing driver may allow local privilege escalation.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-6560-2",
        "releases": ["noble", "24.04", "jammy", "22.04"],
    },
    {
        "id": "USN-6885-3",
        "cve": "CVE-2024-6387",
        "package": "openssh-server",
        "requires_any_port": [22],
        "fixed_by_release": {
            "noble": "1:9.6p1-3ubuntu13.5",
            "24.04": "1:9.6p1-3ubuntu13.5",
            "jammy": "1:8.9p1-3ubuntu0.10",
            "22.04": "1:8.9p1-3ubuntu0.10",
        },
        "severity": "critical",
        "title": "OpenSSH regreSSHion remote code execution",
        "description": "Signal handler race condition in sshd may allow unauthenticated remote code execution.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-6885-3",
    },
    {
        "id": "USN-6862-1",
        "cve": "CVE-2024-2961",
        "package": "libc6",
        "fixed_by_release": {
            "noble": "2.39-0ubuntu8.2",
            "24.04": "2.39-0ubuntu8.2",
            "jammy": "2.35-0ubuntu3.8",
            "22.04": "2.35-0ubuntu3.8",
        },
        "severity": "high",
        "title": "glibc iconv buffer overflow",
        "description": "Out-of-bounds write in glibc iconv for ISO-2022-CN-EXT encoding.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-6862-1",
    },
    {
        "id": "USN-7060-1",
        "cve": "CVE-2024-47076",
        "package": "cups-browsed",
        "requires_any_port": [631],
        "fixed_by_release": {
            "noble": "2.0.0-0ubuntu10.1",
            "24.04": "2.0.0-0ubuntu10.1",
        },
        "severity": "critical",
        "title": "CUPS remote code execution via IPP",
        "description": "Unauthenticated remote code execution via CUPS browsed service.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-7060-1",
    },
    {
        "id": "USN-6951-1",
        "cve": "CVE-2024-6409",
        "package": "openssh-server",
        "fixed_by_release": {
            "noble": "1:9.6p1-3ubuntu13.4",
            "24.04": "1:9.6p1-3ubuntu13.4",
            "jammy": "1:8.9p1-3ubuntu0.9",
            "22.04": "1:8.9p1-3ubuntu0.9",
        },
        "severity": "high",
        "title": "OpenSSH signal handler race condition",
        "description": "Secondary signal handler race condition in OpenSSH privsep child.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-6951-1",
    },
    {
        "id": "USN-6564-1",
        "cve": "CVE-2023-44487",
        "package": "nginx",
        "requires_any_port": [80, 443],
        "fixed_version": "1.24.0-2ubuntu1",
        "severity": "high",
        "title": "HTTP/2 rapid reset DoS",
        "description": "HTTP/2 rapid reset attack can lead to denial-of-service.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-6564-1",
        "releases": ["noble", "24.04", "jammy", "22.04"],
    },
    {
        "id": "USN-7166-1",
        "cve": "CVE-2024-10963",
        "package": "libpam-modules",
        "fixed_version": "1.5.3-5ubuntu5.2",
        "severity": "high",
        "title": "PAM pam_access bypass",
        "description": "pam_access can be bypassed when hostname-based rules are used.",
        "advisory_url": "https://ubuntu.com/security/notices/USN-7166-1",
        "releases": ["noble", "24.04"],
    },
]

AMAZON_LINUX_ADVISORIES = [
    {
        "id": "ALAS-2024-2502",
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "requires_any_port": [22],
        "fixed_version": "8.7p1-8.amzn2023.0.11",
        "severity": "critical",
        "title": "OpenSSH regreSSHion remote code execution",
        "advisory_url": "https://explore.alas.aws.amazon.com/CVE-2024-6387.html",
        "releases": ["2023"],
    },
    {
        "id": "ALAS-2024-2601",
        "cve": "CVE-2024-2961",
        "package": "glibc",
        "fixed_version": "2.34-52.amzn2023.0.12",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
        "advisory_url": "https://explore.alas.aws.amazon.com/CVE-2024-2961.html",
        "releases": ["2023"],
    },
    {
        "id": "ALAS-2024-2437",
        "cve": "CVE-2023-44487",
        "package": "nginx",
        "requires_any_port": [80, 443],
        "fixed_version": "1.24.0-1.amzn2023.0.2",
        "severity": "high",
        "title": "HTTP/2 rapid reset DoS",
        "advisory_url": "https://explore.alas.aws.amazon.com/CVE-2023-44487.html",
        "releases": ["2023"],
    },
]

RHEL_ADVISORIES = [
    # ── RHEL 9 / CentOS Stream 9 / Rocky 9 / Alma 9 ──────────────────
    {
        "id": "RHSA-2024:4312",
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "requires_any_port": [22],
        "fixed_version": "8.7p1-38.el9_4.1",
        "severity": "critical",
        "title": "OpenSSH regreSSHion remote code execution",
        "description": "Signal handler race condition in sshd may allow unauthenticated remote code execution.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:4312",
        "releases": ["9", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:3588",
        "cve": "CVE-2024-2961",
        "package": "glibc",
        "fixed_version": "2.34-83.el9_4.1",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
        "description": "Out-of-bounds write in glibc iconv for ISO-2022-CN-EXT encoding.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:3588",
        "releases": ["9", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:4726",
        "cve": "CVE-2024-6409",
        "package": "openssh",
        "requires_any_port": [22],
        "fixed_version": "8.7p1-38.el9_4.4",
        "severity": "high",
        "title": "OpenSSH signal handler race condition (privsep)",
        "description": "Secondary signal handler race condition in OpenSSH privsep child process.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:4726",
        "releases": ["9", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:0897",
        "cve": "CVE-2023-44487",
        "package": "nginx",
        "requires_any_port": [80, 443],
        "fixed_version": "1.22.1-4.module+el9.3.0+21136+41bc9de1.1",
        "severity": "high",
        "title": "HTTP/2 rapid reset DoS",
        "description": "HTTP/2 rapid reset attack can lead to denial-of-service in nginx.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:0897",
        "releases": ["9", "9.3", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:2988",
        "cve": "CVE-2024-0567",
        "package": "gnutls",
        "fixed_version": "3.7.6-23.el9_4",
        "severity": "high",
        "title": "GnuTLS certificate verification bypass",
        "description": "Cockpit certificate verification bypass via crafted certtool certificates.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:2988",
        "releases": ["9", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:3233",
        "cve": "CVE-2023-6531",
        "package": "kernel",
        "fixed_version": "5.14.0-427.18.1.el9_4",
        "severity": "high",
        "title": "Kernel use-after-free in Unix GC",
        "description": "Use-after-free in Linux kernel Unix socket garbage collection.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:3233",
        "releases": ["9", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:3043",
        "cve": "CVE-2024-1086",
        "package": "kernel",
        "fixed_version": "5.14.0-427.16.1.el9_4",
        "severity": "high",
        "title": "Kernel nf_tables use-after-free privilege escalation",
        "description": "Use-after-free in nf_tables allows local privilege escalation.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:3043",
        "releases": ["9", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:1607",
        "cve": "CVE-2023-46218",
        "package": "curl",
        "fixed_version": "8.0.1-4.el9_3.2",
        "severity": "medium",
        "title": "curl cookie injection via HTTP redirect",
        "description": "HTTP redirect could inject cookies for other origins via mixed case domain names.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:1607",
        "releases": ["9", "9.3", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:0256",
        "cve": "CVE-2023-7104",
        "package": "sqlite",
        "fixed_version": "3.34.1-7.el9_3.1",
        "severity": "medium",
        "title": "SQLite heap buffer overflow",
        "description": "Heap buffer overflow in SQLite via crafted JSON input.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:0256",
        "releases": ["9", "9.3", "9.4", "el9"],
    },
    {
        "id": "RHSA-2024:5312",
        "cve": "CVE-2024-5564",
        "package": "libndp",
        "fixed_version": "1.8-6.el9_4",
        "severity": "high",
        "title": "libndp buffer overflow",
        "description": "Buffer overflow in libndp Neighbor Discovery Protocol library.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:5312",
        "releases": ["9", "9.4", "el9"],
    },
    # ── RHEL 8 / CentOS 8 / Rocky 8 / Alma 8 ─────────────────────────
    {
        "id": "RHSA-2024:4352",
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "requires_any_port": [22],
        "fixed_version": "8.0p1-24.el8_10",
        "severity": "critical",
        "title": "OpenSSH regreSSHion remote code execution",
        "description": "Signal handler race condition in sshd may allow unauthenticated remote code execution.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:4352",
        "releases": ["8", "8.10", "el8"],
    },
    {
        "id": "RHSA-2024:3588",
        "cve": "CVE-2024-2961",
        "package": "glibc",
        "fixed_version": "2.28-236.el8_10",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
        "description": "Out-of-bounds write in glibc iconv for ISO-2022-CN-EXT encoding.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:3588",
        "releases": ["8", "8.9", "8.10", "el8"],
    },
    {
        "id": "RHSA-2024:3138",
        "cve": "CVE-2024-1086",
        "package": "kernel",
        "fixed_version": "4.18.0-553.5.1.el8_10",
        "severity": "high",
        "title": "Kernel nf_tables use-after-free privilege escalation",
        "description": "Use-after-free in nf_tables allows local privilege escalation.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:3138",
        "releases": ["8", "8.10", "el8"],
    },
    {
        "id": "RHSA-2024:0790",
        "cve": "CVE-2023-44487",
        "package": "nginx",
        "requires_any_port": [80, 443],
        "fixed_version": "1.22.1-1.module+el8.8.0+21211+e82e6b5e.2",
        "severity": "high",
        "title": "HTTP/2 rapid reset DoS",
        "description": "HTTP/2 rapid reset attack can lead to denial-of-service in nginx.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:0790",
        "releases": ["8", "8.8", "8.9", "8.10", "el8"],
    },
    # ── CentOS 7 / RHEL 7 (extended lifecycle) ────────────────────────
    {
        "id": "RHSA-2024:4389",
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "requires_any_port": [22],
        "fixed_version": "7.4p1-23.el7_9.3",
        "severity": "critical",
        "title": "OpenSSH regreSSHion remote code execution",
        "description": "Signal handler race condition in sshd may allow unauthenticated remote code execution.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:4389",
        "releases": ["7", "7.9", "el7"],
    },
    {
        "id": "RHSA-2024:3269",
        "cve": "CVE-2024-2961",
        "package": "glibc",
        "fixed_version": "2.17-326.el7_9.3",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
        "description": "Out-of-bounds write in glibc iconv for ISO-2022-CN-EXT encoding.",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:3269",
        "releases": ["7", "7.9", "el7"],
    },
]

# CentOS-specific aliases — CentOS advisories use CESA IDs but map to
# the same RHEL errata. The _detect_distro function already maps
# centos/rocky/alma → "rhel", so they share the same advisory list.


def _parse_version(v: str) -> list:
    v = (v or "").strip()
    v = v.split(":")[-1] if ":" in v else v
    parts = re.findall(r"(\d+|[a-zA-Z]+)", v)
    out = []
    for part in parts:
        if part.isdigit():
            out.append(int(part))
        else:
            out.append(part.lower())
    return out


def _version_lt(installed: str, fixed: str) -> bool:
    try:
        return _parse_version(installed) < _parse_version(fixed)
    except Exception:
        return False


def _detect_distro(os_release: dict) -> str:
    os_id = (os_release.get("ID") or "").lower()
    id_like = (os_release.get("ID_LIKE") or "").lower()

    if "ubuntu" in os_id:
        return "ubuntu"
    if "debian" in os_id or "debian" in id_like:
        return "debian"
    if "amzn" in os_id or "amazon" in os_id:
        return "amazon"
    # RHEL family: RHEL, CentOS (Stream), Rocky Linux, AlmaLinux, Oracle Linux
    if any(d in os_id for d in ("rhel", "centos", "rocky", "almalinux", "ol")):
        return "rhel"
    if any(d in id_like for d in ("rhel", "centos", "fedora")):
        return "rhel"
    if "alpine" in os_id:
        return "alpine"
    return "unknown"


def _release_tokens(os_release: dict) -> set[str]:
    tokens = set()
    for key in ["VERSION_CODENAME", "UBUNTU_CODENAME", "DEBIAN_CODENAME", "VERSION_ID"]:
        raw = (os_release.get(key) or "").strip().lower()
        if not raw:
            continue
        tokens.add(raw)
        if "." in raw:
            tokens.add(raw.split(".", 1)[0])
    platform_id = (os_release.get("PLATFORM_ID") or "").strip().lower()
    if platform_id:
        # Example: platform:el9
        tokens.add(platform_id)
        if "el" in platform_id:
            m = re.search(r"el\d+", platform_id)
            if m:
                tokens.add(m.group(0))
    return tokens


def _advisory_fixed_version(adv: dict, host_release_tokens: set[str]) -> str:
    by_release = adv.get("fixed_by_release") or {}
    if by_release:
        normalized = {str(k).strip().lower(): v for k, v in by_release.items()}
        for token in host_release_tokens:
            if token in normalized:
                return normalized[token]
        return ""
    return adv.get("fixed_version", "")


def _advisory_applies_release(adv: dict, host_release_tokens: set[str]) -> bool:
    rels = adv.get("releases")
    if rels:
        allowed = {str(x).strip().lower() for x in rels if str(x).strip()}
        return bool(allowed & host_release_tokens)
    if adv.get("fixed_by_release"):
        mapped = {str(x).strip().lower() for x in adv.get("fixed_by_release", {}).keys()}
        return bool(mapped & host_release_tokens)
    return True


def _is_installed_package(pkg: dict) -> bool:
    ecosystem = (pkg.get("ecosystem") or "").lower()
    if ecosystem == "deb":
        status = (pkg.get("status") or "").lower()
        if status:
            return status == "ii"
    return bool(pkg.get("installed", True))


def _build_pkg_index(pkgs: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for p in pkgs:
        if not _is_installed_package(p):
            continue
        name = (p.get("name") or "").strip().lower()
        ver = (p.get("version") or "").strip()
        if not name or not ver:
            continue
        idx.setdefault(name, []).append(p)
        base = name.split("-")[0]
        if base and base != name:
            idx.setdefault(base, []).append(p)
    return idx


def _find_package(pkg_name: str, pkg_index: dict[str, list[dict]]) -> dict | None:
    exact = pkg_index.get(pkg_name)
    if exact:
        return exact[0]

    for name, entries in pkg_index.items():
        if pkg_name in name or name in pkg_name:
            return entries[0]
    return None


def _get_advisories(distro: str) -> list:
    if distro in ("ubuntu", "debian"):
        return UBUNTU_ADVISORIES
    if distro == "amazon":
        return AMAZON_LINUX_ADVISORIES
    if distro == "rhel":
        return RHEL_ADVISORIES
    return []


def _exposure_matches(adv: dict, open_ports: list[int]) -> tuple[bool, str]:
    required = adv.get("requires_any_port") or []
    if not required:
        return True, "package_state"

    open_set = {int(p) for p in open_ports if isinstance(p, int) or str(p).isdigit()}
    matched = [str(p) for p in required if int(p) in open_set]
    if matched:
        return True, f"port_open:{','.join(matched)}"
    return False, f"missing_required_port:{','.join(str(p) for p in required)}"


class Check(Plugin):
    async def run(self, target, ctx):
        os_info = ctx.get("inventory.os", {}) or {}
        pkgs = ctx.get("inventory.packages", []) or []
        if not pkgs:
            return PluginResult()
        open_ports = ctx.get("net.open_ports", []) or []

        os_release = os_info.get("os_release", {}) or {}
        distro = _detect_distro(os_release)
        os_name = os_release.get("PRETTY_NAME", distro)
        release_tokens = _release_tokens(os_release)
        release_label = (
            os_release.get("VERSION_CODENAME")
            or os_release.get("UBUNTU_CODENAME")
            or os_release.get("DEBIAN_CODENAME")
            or os_release.get("VERSION_ID")
            or "unknown"
        )

        advisories = _get_advisories(distro)
        pkg_index = _build_pkg_index(pkgs)
        installed_count = sum(1 for p in pkgs if _is_installed_package(p))

        inventory_ts = os_info.get("inventory_timestamp") or ""
        host_identifier = os_info.get("host_identifier") or target
        scan_ts = os_info.get("scan_timestamp") or ctx.get("scan.started_at") or ""

        findings = []
        matched_advisories = 0

        for adv in advisories:
            pkg_name = (adv.get("package") or "").lower().strip()
            if not pkg_name:
                continue

            if not _advisory_applies_release(adv, release_tokens):
                continue

            fixed = _advisory_fixed_version(adv, release_tokens)
            if not fixed:
                continue

            installed_pkg = _find_package(pkg_name, pkg_index)
            if not installed_pkg:
                continue

            installed_version = installed_pkg.get("version", "")
            installed_status = installed_pkg.get("status", "")
            if not installed_version:
                continue

            exposure_ok, exposure_reason = _exposure_matches(adv, open_ports)
            if not exposure_ok:
                continue

            if _version_lt(installed_version, fixed):
                matched_advisories += 1
                cve = adv.get("cve", "")
                adv_id = adv.get("id", "")
                sev = adv.get("severity", "medium")
                advisory_url = adv.get("advisory_url", "")

                refs = [
                    f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
                    advisory_url,
                    "https://ubuntu.com/security/notices" if distro in ("ubuntu", "debian") else "",
                    "https://www.debian.org/security/" if distro == "debian" else "",
                    "https://explore.alas.aws.amazon.com/" if distro == "amazon" else "",
                    "https://alas.aws.amazon.com/alas2.html" if distro == "amazon" else "",
                    "https://access.redhat.com/security/security-updates/security-advisories" if distro == "rhel" else "",
                ]

                findings.append(
                    Finding(
                        severity=sev,
                        plugin_id=META.plugin_id,
                        title=f"[{adv_id}] {adv.get('title', cve)}",
                        description=(
                            f"{adv.get('description', '')}\n\n"
                            f"Distro: {os_name} (release: {release_label})\n"
                            f"Package: {pkg_name} (installed: {installed_version}, fixed: {fixed}, status: {installed_status or 'installed'})\n"
                            f"Advisory: {adv_id}\n"
                            f"Validation: vendor distro advisory matched the installed package and release"
                        ),
                        evidence=(
                            f"advisory={adv_id} cve={cve} package={pkg_name} "
                            f"installed={installed_version} status={installed_status or 'installed'} fixed={fixed} "
                            f"distro={distro} release={release_label} "
                            f"validation_state=validated validation_method=distro_advisory "
                            f"exposure_check={exposure_reason} "
                            f"scan_ts={scan_ts} inventory_ts={inventory_ts} host_id={host_identifier}"
                        ),
                        affected=target,
                        fingerprint=stable_fingerprint(
                            target,
                            META.plugin_id,
                            adv_id,
                            pkg_name,
                            release_label,
                            fixed,
                        ),
                        cve=cve if cve.startswith("CVE-") else None,
                        confidence=0.9,
                        remediation=(
                            f"[{distro.upper()} SECURITY UPDATE]\n"
                            f"Advisory: {adv_id}\n"
                            f"Release: {release_label}\n"
                            f"Validation: matched release-specific vendor advisory ({exposure_reason}).\n"
                            f"Update {pkg_name} to {fixed} or later.\n"
                            "Ubuntu/Debian: sudo apt update && sudo apt upgrade <package>\n"
                            "Amazon/RHEL:   sudo yum update <package>\n"
                            "Alpine:        sudo apk upgrade <package>\n\n"
                            "Verification (Ubuntu/Debian): dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n' <package>"
                        ),
                        references=[r for r in refs if r],
                    )
                )

        findings.append(
            Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=(
                    "Local security check summary: "
                    f"{distro} release={release_label} installed_packages={installed_count} matches={matched_advisories}"
                ),
                evidence=(
                    f"distro={distro} os={os_name} release={release_label} "
                    f"packages_total={len(pkgs)} packages_installed={installed_count} "
                    f"advisories_checked={len(advisories)} hits={matched_advisories} "
                    f"scan_ts={scan_ts} inventory_ts={inventory_ts} host_id={host_identifier}"
                ),
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary", release_label, host_identifier),
                remediation=(
                    "Validate package state before remediation to reduce false positives:\n"
                    "Ubuntu/Debian: dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\\n'\n"
                    "Amazon/RHEL: rpm -qa\n"
                    "Alpine: apk info -v"
                ),
            )
        )

        return PluginResult(
            findings=findings,
            artifacts={"local.security.findings": matched_advisories},
        )
