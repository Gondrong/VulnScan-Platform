"""
Linux Local Security Checks — matches installed packages against
OS-specific security advisories.

Supported distros:
  - Ubuntu/Debian (USN advisories via dpkg)
  - Amazon Linux (ALAS advisories via rpm)
  - RHEL/CentOS/Rocky (RHSA advisories via rpm)
  - Alpine (via apk)

This plugin runs AFTER ssh_inventory collects package lists and
os_release info via SSH. It checks each installed package version
against known-vulnerable version ranges for the detected distro.

Differs from cve.match.packages in that it checks distro-specific
patched versions rather than upstream CPE matching. A package might
have a CVE patched via a distro backport (e.g., openssh 1:8.9p1-3ubuntu0.10)
that NVD/CPE matching wouldn't catch.
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

# ── Known vulnerable package versions by distro ──────────────────────────────
# In production, this would be loaded from downloaded advisory databases
# (USN, ALAS, RHSA feeds). Here we include high-profile CVEs as examples
# and the framework for matching.

UBUNTU_ADVISORIES = [
    {
        "id": "USN-6560-2",
        "cve": "CVE-2023-6546",
        "package": "linux-image-generic",
        "fixed_version": "6.5.0-15",
        "severity": "high",
        "title": "Linux kernel (GSM) use-after-free privilege escalation",
        "description": "A race condition in the GSM multiplexing driver allows local privilege escalation.",
    },
    {
        "id": "USN-6885-3",
        "cve": "CVE-2024-6387",
        "package": "openssh-server",
        "fixed_version": "1:9.6p1-3ubuntu13.5",
        "severity": "critical",
        "title": "OpenSSH regreSSHion — remote code execution",
        "description": "Signal handler race condition in sshd allows unauthenticated remote code execution.",
    },
    {
        "id": "USN-6862-1",
        "cve": "CVE-2024-2961",
        "package": "libc6",
        "fixed_version": "2.39-0ubuntu8.2",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
        "description": "Out-of-bounds write in glibc iconv function for ISO-2022-CN-EXT encoding.",
    },
    {
        "id": "USN-7060-1",
        "cve": "CVE-2024-47076",
        "package": "cups-browsed",
        "fixed_version": "2.0.0-0ubuntu10.1",
        "severity": "critical",
        "title": "CUPS remote code execution via IPP",
        "description": "Unauthenticated remote code execution via CUPS browsed service.",
    },
    {
        "id": "USN-6951-1",
        "cve": "CVE-2024-6409",
        "package": "openssh-server",
        "fixed_version": "1:9.6p1-3ubuntu13.4",
        "severity": "high",
        "title": "OpenSSH signal handler race condition",
        "description": "Secondary signal handler race condition in OpenSSH's privsep child.",
    },
    {
        "id": "USN-6564-1",
        "cve": "CVE-2023-44487",
        "package": "nginx",
        "fixed_version": "1.24.0-2ubuntu1",
        "severity": "high",
        "title": "HTTP/2 Rapid Reset DDoS vulnerability",
        "description": "HTTP/2 rapid reset attack allows denial of service.",
    },
    {
        "id": "USN-7166-1",
        "cve": "CVE-2024-10963",
        "package": "libpam-modules",
        "fixed_version": "1.5.3-5ubuntu5.2",
        "severity": "high",
        "title": "PAM pam_access bypass with hostname-based rules",
        "description": "PAM access control can be bypassed when hostname-based rules are used.",
    },
]

AMAZON_LINUX_ADVISORIES = [
    {
        "id": "ALAS-2024-2502",
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "fixed_version": "8.7p1-8.amzn2023.0.11",
        "severity": "critical",
        "title": "OpenSSH regreSSHion — remote code execution",
    },
    {
        "id": "ALAS-2024-2601",
        "cve": "CVE-2024-2961",
        "package": "glibc",
        "fixed_version": "2.34-52.amzn2023.0.12",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
    },
    {
        "id": "ALAS-2024-2437",
        "cve": "CVE-2023-44487",
        "package": "nginx",
        "fixed_version": "1.24.0-1.amzn2023.0.2",
        "severity": "high",
        "title": "HTTP/2 Rapid Reset DDoS vulnerability",
    },
    {
        "id": "ALAS-2024-689",
        "cve": "CVE-2024-47076",
        "package": "cups",
        "fixed_version": "2.3.3op2-18.amzn2023.0.9",
        "severity": "critical",
        "title": "CUPS remote code execution",
    },
]

RHEL_ADVISORIES = [
    {
        "id": "RHSA-2024:4312",
        "cve": "CVE-2024-6387",
        "package": "openssh",
        "fixed_version": "8.7p1-38.el9_4.1",
        "severity": "critical",
        "title": "OpenSSH regreSSHion",
    },
    {
        "id": "RHSA-2024:3588",
        "cve": "CVE-2024-2961",
        "package": "glibc",
        "fixed_version": "2.34-83.el9_4.1",
        "severity": "high",
        "title": "glibc iconv buffer overflow",
    },
]


def _parse_version(v: str) -> list:
    """Parse a version string into comparable parts."""
    # Remove epoch (1:xxx) and deb/rpm suffixes
    v = v.split(":")[-1] if ":" in v else v
    # Extract numeric/string segments
    parts = re.findall(r"(\d+|[a-zA-Z]+)", v)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(p)
    return result


def _version_lt(installed: str, fixed: str) -> bool:
    """Check if installed version is less than fixed version."""
    try:
        vi = _parse_version(installed)
        vf = _parse_version(fixed)
        return vi < vf
    except Exception:
        return False


def _detect_distro(os_info: dict) -> str:
    """Detect the Linux distribution from os-release data."""
    os_id = (os_info.get("ID") or "").lower()
    id_like = (os_info.get("ID_LIKE") or "").lower()

    if "ubuntu" in os_id:
        return "ubuntu"
    if "debian" in os_id or "debian" in id_like:
        return "debian"
    if "amzn" in os_id or "amazon" in os_id:
        return "amazon"
    if "rhel" in os_id or "centos" in os_id or "rocky" in os_id or "fedora" in id_like:
        return "rhel"
    if "alpine" in os_id:
        return "alpine"
    return "unknown"


def _get_advisories(distro: str) -> list:
    """Return advisories for the detected distro."""
    if distro in ("ubuntu", "debian"):
        return UBUNTU_ADVISORIES
    if distro == "amazon":
        return AMAZON_LINUX_ADVISORIES
    if distro in ("rhel", "centos", "rocky"):
        return RHEL_ADVISORIES
    return UBUNTU_ADVISORIES + AMAZON_LINUX_ADVISORIES + RHEL_ADVISORIES


class Check(Plugin):
    async def run(self, target, ctx):
        os_info = ctx.get("inventory.os", {}) or {}
        pkgs = ctx.get("inventory.packages", []) or []
        if not pkgs:
            return PluginResult()

        os_release = os_info.get("os_release", {})
        distro = _detect_distro(os_release)
        os_name = os_release.get("PRETTY_NAME", distro)
        advisories = _get_advisories(distro)

        # Build package index: name -> version
        pkg_index = {}
        for p in pkgs:
            name = p.get("name", "").lower().strip()
            ver = p.get("version", "")
            if name and ver:
                pkg_index[name] = ver
                # Also index without version suffix (e.g., "openssh-server" -> "openssh")
                base = name.split("-")[0]
                if base not in pkg_index:
                    pkg_index[base] = ver

        findings = []
        matched_advisories = 0

        for adv in advisories:
            pkg_name = adv["package"].lower()
            installed = pkg_index.get(pkg_name)
            if not installed:
                # Try partial match
                for pname, pver in pkg_index.items():
                    if pkg_name in pname or pname in pkg_name:
                        installed = pver
                        break

            if not installed:
                continue

            fixed = adv.get("fixed_version", "")
            if fixed and _version_lt(installed, fixed):
                matched_advisories += 1
                cve = adv.get("cve", "")
                adv_id = adv.get("id", "")
                sev = adv.get("severity", "medium")

                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title=f"[{adv_id}] {adv.get('title', cve)}",
                    description=(
                        f"{adv.get('description', '')}\n\n"
                        f"Distro: {os_name}\n"
                        f"Package: {pkg_name} (installed: {installed}, fixed: {fixed})\n"
                        f"Advisory: {adv_id}"
                    ),
                    evidence=(
                        f"advisory={adv_id} cve={cve} package={pkg_name} "
                        f"installed={installed} fixed={fixed} distro={distro}"
                    ),
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, adv_id, pkg_name),
                    cve=cve if cve.startswith("CVE-") else None,
                    confidence=0.85,
                    remediation=(
                        f"[{distro.upper()} SECURITY UPDATE]\n"
                        f"Advisory: {adv_id}\n"
                        f"Update {pkg_name} to version {fixed} or later:\n"
                        f"  Ubuntu/Debian: sudo apt update && sudo apt upgrade {pkg_name}\n"
                        f"  Amazon/RHEL:   sudo yum update {pkg_name}\n"
                        f"  Alpine:        sudo apk upgrade {pkg_name}\n\n"
                        f"Verify: dpkg -l {pkg_name} (Debian) or rpm -q {pkg_name} (RPM)"
                    ),
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
                        f"https://ubuntu.com/security/notices/{adv_id}" if "USN" in adv_id else "",
                        f"https://alas.aws.amazon.com/{adv_id}.html" if "ALAS" in adv_id else "",
                        f"https://access.redhat.com/errata/{adv_id}" if "RHSA" in adv_id else "",
                    ],
                ))

        # Summary finding
        if pkgs:
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Local security check: {distro} — {len(pkgs)} packages, {matched_advisories} advisories matched",
                evidence=f"distro={distro} os={os_name} packages={len(pkgs)} advisories_checked={len(advisories)} hits={matched_advisories}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
                remediation=(
                    f"Run full system update:\n"
                    f"  Ubuntu/Debian: sudo apt update && sudo apt upgrade -y\n"
                    f"  Amazon/RHEL:   sudo yum update -y\n"
                    f"  Alpine:        sudo apk upgrade"
                ),
            ))

        return PluginResult(
            findings=findings,
            artifacts={"local.security.findings": matched_advisories},
        )