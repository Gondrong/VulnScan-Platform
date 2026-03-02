"""
CVE Matching (Packages) — matches installed packages from SSH inventory
against vulnerability datasets.

Supports two matching modes:
1. OSV format: ecosystem/package/version range matching
2. NVD format: converts deb/rpm package names to CPE and matches against nvd_cpe_cve.json

This plugin bridges the gap between authenticated inventory and CVE detection.
"""
import re
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.cve.version_cmp import parse, match_expr
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.packages",
    name="CVE Matching (Packages)",
    category="cve",
    depends_on=["auth.ssh.inventory"],
    consumes=["inventory.packages"],
    provides=["cve.package_hits"],
    enabled_by_default=False,
    timeout_seconds=15.0,
)


# ── Common deb/rpm package → CPE (vendor, product) mapping ──────────────────
# This maps well-known package names to their NVD CPE vendor:product pairs.
# Without this, "openssh-server" (deb) can't match "openbsd:openssh" (CPE).
PKG_TO_CPE = {
    # SSH
    "openssh-server":   ("openbsd", "openssh"),
    "openssh-client":   ("openbsd", "openssh"),
    "openssh":          ("openbsd", "openssh"),
    # Web servers
    "nginx":            ("f5", "nginx"),
    "nginx-common":     ("f5", "nginx"),
    "nginx-core":       ("f5", "nginx"),
    "apache2":          ("apache", "http_server"),
    "apache2-bin":      ("apache", "http_server"),
    "httpd":            ("apache", "http_server"),
    # Languages / runtimes
    "python3":          ("python", "python"),
    "python3.11":       ("python", "python"),
    "python3.12":       ("python", "python"),
    "nodejs":           ("nodejs", "node.js"),
    "php":              ("php", "php"),
    "php8.1-cli":       ("php", "php"),
    "php8.2-cli":       ("php", "php"),
    "php8.3-cli":       ("php", "php"),
    "ruby":             ("ruby-lang", "ruby"),
    "perl":             ("perl", "perl"),
    "openjdk-17-jre":   ("oracle", "openjdk"),
    "openjdk-21-jre":   ("oracle", "openjdk"),
    # Databases
    "postgresql":       ("postgresql", "postgresql"),
    "postgresql-16":    ("postgresql", "postgresql"),
    "postgresql-15":    ("postgresql", "postgresql"),
    "postgresql-14":    ("postgresql", "postgresql"),
    "mysql-server":     ("oracle", "mysql"),
    "mariadb-server":   ("mariadb", "mariadb"),
    "redis-server":     ("redis", "redis"),
    "redis":            ("redis", "redis"),
    "mongodb-server":   ("mongodb", "mongodb"),
    "sqlite3":          ("sqlite", "sqlite"),
    # SSL/TLS
    "openssl":          ("openssl", "openssl"),
    "libssl3":          ("openssl", "openssl"),
    "libssl1.1":        ("openssl", "openssl"),
    "gnutls-bin":       ("gnu", "gnutls"),
    "libgnutls30":      ("gnu", "gnutls"),
    # Networking
    "curl":             ("haxx", "curl"),
    "libcurl4":         ("haxx", "curl"),
    "wget":             ("gnu", "wget"),
    "bind9":            ("isc", "bind"),
    "dnsmasq":          ("thekelleys", "dnsmasq"),
    "ntp":              ("ntp", "ntp"),
    "chrony":           ("tuxfamily", "chrony"),
    # System
    "sudo":             ("sudo_project", "sudo"),
    "bash":             ("gnu", "bash"),
    "glibc":            ("gnu", "glibc"),
    "libc6":            ("gnu", "glibc"),
    "systemd":          ("systemd_project", "systemd"),
    "coreutils":        ("gnu", "coreutils"),
    "util-linux":       ("kernel", "util-linux"),
    "linux-image-generic": ("linux", "linux_kernel"),
    "dbus":             ("freedesktop", "dbus"),
    "polkit":           ("polkit_project", "polkit"),
    "policykit-1":      ("polkit_project", "polkit"),
    # Containers
    "docker.io":        ("docker", "docker"),
    "docker-ce":        ("docker", "docker"),
    "containerd":       ("linuxfoundation", "containerd"),
    "runc":             ("linuxfoundation", "runc"),
    "podman":           ("podman_project", "podman"),
    # Mail
    "postfix":          ("postfix", "postfix"),
    "exim4":            ("exim", "exim"),
    "dovecot-core":     ("dovecot", "dovecot"),
    # Misc
    "git":              ("git-scm", "git"),
    "vim":              ("vim", "vim"),
    "screen":           ("gnu", "screen"),
    "tmux":             ("tmux_project", "tmux"),
    "rsync":            ("samba", "rsync"),
    "samba":            ("samba", "samba"),
    "nfs-common":       ("linux", "nfs-utils"),
    "imagemagick":      ("imagemagick", "imagemagick"),
    "ghostscript":      ("artifex", "ghostscript"),
    "ffmpeg":           ("ffmpeg", "ffmpeg"),
    "libxml2":          ("xmlsoft", "libxml2"),
    "libxslt1.1":       ("xmlsoft", "libxslt"),
    "zlib1g":           ("zlib", "zlib"),
    "expat":            ("libexpat_project", "libexpat"),
    "tar":              ("gnu", "tar"),
    "gzip":             ("gnu", "gzip"),
    "unzip":            ("info-zip", "unzip"),
}

# Patterns for dynamic matching (linux kernel packages, etc.)
PKG_PATTERNS = [
    (r"^linux-image-(\d+\.\d+)", "linux", "linux_kernel"),
    (r"^linux-headers-(\d+\.\d+)", "linux", "linux_kernel"),
    (r"^php(\d+\.\d+)", "php", "php"),
    (r"^python(\d+\.\d+)", "python", "python"),
    (r"^postgresql-(\d+)", "postgresql", "postgresql"),
    (r"^openjdk-(\d+)", "oracle", "openjdk"),
    (r"^nginx", "f5", "nginx"),
    (r"^apache2", "apache", "http_server"),
    (r"^libssl", "openssl", "openssl"),
    (r"^libcurl", "haxx", "curl"),
]


def pkg_to_cpe(name: str, version: str) -> list[dict]:
    """Convert a package name to CPE candidates."""
    name_lower = name.lower().strip()
    results = []

    # Direct mapping
    if name_lower in PKG_TO_CPE:
        vendor, product = PKG_TO_CPE[name_lower]
        # Clean version: remove epoch (1:2.3.4-5) and deb revision (-5ubuntu1)
        clean_ver = version.split(":")[-1] if ":" in version else version
        clean_ver = re.sub(r"[-+~].*$", "", clean_ver)  # strip deb/rpm suffix
        results.append({
            "cpe23": f"cpe:2.3:a:{vendor}:{product}:{clean_ver}:*:*:*:*:*:*:*",
            "vendor": vendor,
            "product": product,
            "version": clean_ver,
            "package": name,
        })

    # Pattern matching for dynamic names
    for pattern, vendor, product in PKG_PATTERNS:
        if re.match(pattern, name_lower):
            clean_ver = version.split(":")[-1] if ":" in version else version
            clean_ver = re.sub(r"[-+~].*$", "", clean_ver)
            key = (vendor, product)
            if not any((r["vendor"], r["product"]) == key for r in results):
                results.append({
                    "cpe23": f"cpe:2.3:a:{vendor}:{product}:{clean_ver}:*:*:*:*:*:*:*",
                    "vendor": vendor,
                    "product": product,
                    "version": clean_ver,
                    "package": name,
                })

    return results


def same_family(a: str, b: str) -> bool:
    """Check if two CPE strings belong to the same vendor:product."""
    pa = (a or "").split(":")
    pb = (b or "").split(":")
    if len(pa) < 6 or len(pb) < 6:
        return False
    return pa[3] == pb[3] and pa[4] == pb[4]


def range_ok(installed: str | None, m: dict) -> bool:
    """Check if installed version falls in the vulnerable range."""
    vsi = m.get("versionStartIncluding")
    vse = m.get("versionStartExcluding")
    vei = m.get("versionEndIncluding")
    vee = m.get("versionEndExcluding")

    if not vsi and not vse and not vei and not vee:
        return True  # no range specified = all versions affected
    if not installed:
        return False

    v = parse(installed)
    if not v:
        return False

    if vsi:
        x = parse(vsi)
        if x and v < x:
            return False
    if vse:
        x = parse(vse)
        if x and v <= x:
            return False
    if vei:
        x = parse(vei)
        if x and v > x:
            return False
    if vee:
        x = parse(vee)
        if x and v >= x:
            return False
    return True


def match_osv(pkgs, db_data):
    """Match packages against OSV-format dataset."""
    hits = []
    idx = {}
    for p in pkgs:
        idx.setdefault((p["ecosystem"], p["name"]), []).append(p["version"])

    for item in db_data or []:
        eco = item.get("ecosystem")
        name = item.get("package")
        versions = idx.get((eco, name), [])
        for ver in versions:
            for r in item.get("ranges", []) or []:
                if r.get("type") == "introduced_fixed":
                    introduced = r.get("introduced", "0")
                    fixed = r.get("fixed")
                    if fixed and match_expr(ver, f">= {introduced} < {fixed}"):
                        hits.append({
                            "id": item.get("id"),
                            "cve": item.get("cve"),
                            "package": name,
                            "ecosystem": eco,
                            "installed": ver,
                            "severity": item.get("severity", "medium"),
                            "refs": item.get("refs", []),
                            "summary": item.get("summary", ""),
                        })
                        break
    return hits


def match_nvd(pkgs, nvd_data):
    """
    Match packages against NVD CPE dataset.
    Converts package names to CPE candidates and checks version ranges.
    """
    # Build CPE candidates from all packages
    cpe_candidates = []
    for p in pkgs:
        cpes = pkg_to_cpe(p["name"], p["version"])
        cpe_candidates.extend(cpes)

    if not cpe_candidates:
        return []

    hits = []
    seen_cves = set()

    for item in nvd_data or []:
        cve_id = item.get("cve", "")
        if not cve_id.startswith("CVE-"):
            continue

        for m in item.get("matches", []) or []:
            cpe_db = m.get("cpe23")
            if not cpe_db:
                continue

            for c in cpe_candidates:
                if same_family(cpe_db, c["cpe23"]) and range_ok(c.get("version"), m):
                    hit_key = (cve_id, c["package"])
                    if hit_key not in seen_cves:
                        seen_cves.add(hit_key)
                        hits.append({
                            "cve": cve_id,
                            "package": c["package"],
                            "ecosystem": "nvd",
                            "installed": c["version"],
                            "severity": item.get("severity", "medium"),
                            "cvss": item.get("cvss"),
                            "refs": item.get("refs", []),
                            "summary": item.get("summary", ""),
                            "matched_cpe": cpe_db,
                        })
                    break

    return hits


class Check(Plugin):
    async def run(self, target, ctx):
        pkgs = ctx.get("inventory.packages", []) or []
        if not pkgs:
            return PluginResult()

        ws_id = ctx.get("workspace_id")
        db = SessionLocal()
        all_hits = []

        try:
            # Mode 1: Match against OSV datasets (ecosystem-based)
            osv_dsets = (
                db.query(models.CveDataset)
                .filter(
                    models.CveDataset.workspace_id == ws_id,
                    models.CveDataset.kind == "osv",
                    models.CveDataset.enabled == True,
                )
                .all()
            )
            for ds in osv_dsets:
                all_hits += match_osv(pkgs, load_json(ds.path))

            # Mode 2: Match against NVD datasets (CPE-based)
            nvd_dsets = (
                db.query(models.CveDataset)
                .filter(
                    models.CveDataset.workspace_id == ws_id,
                    models.CveDataset.kind == "nvd_cpe_cve",
                    models.CveDataset.enabled == True,
                )
                .all()
            )
            for ds in nvd_dsets:
                all_hits += match_nvd(pkgs, load_json(ds.path))

        finally:
            db.close()

        # Build findings
        findings = []
        for h in all_hits[:3000]:
            cve = h.get("cve") or h.get("id") or "UNKNOWN"
            fp = stable_fingerprint(
                target, META.plugin_id, cve, h.get("package", ""), h.get("installed", "")
            )
            findings.append(
                Finding(
                    severity=h.get("severity", "medium"),
                    plugin_id=META.plugin_id,
                    title=f"{cve}: {h.get('package', '?')} {h.get('installed', '')}",
                    description=h.get("summary", ""),
                    references=h.get("refs", []),
                    evidence=(
                        f"package={h.get('package')} installed={h.get('installed')} "
                        f"ecosystem={h.get('ecosystem', '')} "
                        f"matched_cpe={h.get('matched_cpe', '')}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    cve=cve if cve.startswith("CVE-") else None,
                    cvss=h.get("cvss"),
                    confidence=0.9,
                )
            )

        return PluginResult(
            findings=findings, artifacts={"cve.package_hits": all_hits}
        )
