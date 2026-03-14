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
from app.cve.version_cmp import parse, match_expr, is_likely_patched
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.packages",
    name="CVE Matching (Packages)",
    category="cve",
    depends_on=["auth.ssh.inventory"],
    consumes=["inventory.packages", "inventory.os"],
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
    # Proxy / Load balancers
    "haproxy":          ("haproxy", "haproxy"),
    "squid":            ("squid-cache", "squid"),
    "squid3":           ("squid-cache", "squid"),
    "varnish":          ("varnish-cache", "varnish_cache"),
    "traefik":          ("traefik", "traefik"),
    # Message queues
    "rabbitmq-server":  ("pivotal_software", "rabbitmq"),
    "mosquitto":        ("eclipse", "mosquitto"),
    "activemq":         ("apache", "activemq"),
    # Monitoring
    "prometheus":       ("prometheus", "prometheus"),
    "grafana":          ("grafana", "grafana"),
    "zabbix-server-mysql": ("zabbix", "zabbix"),
    "zabbix-server-pgsql": ("zabbix", "zabbix"),
    "zabbix-agent":     ("zabbix", "zabbix"),
    "nagios4":          ("nagios", "nagios"),
    "nagios-nrpe-server": ("nagios", "nrpe"),
    # CI/CD
    "jenkins":          ("jenkins", "jenkins"),
    "gitlab-ce":        ("gitlab", "gitlab"),
    "gitlab-ee":        ("gitlab", "gitlab"),
    "gitlab-runner":    ("gitlab", "gitlab_runner"),
    # Caching
    "memcached":        ("memcached", "memcached"),
    "libmemcached11":   ("memcached", "memcached"),
    # Logging / ELK
    "logstash":         ("elastic", "logstash"),
    "filebeat":         ("elastic", "beats"),
    "elasticsearch":    ("elastic", "elasticsearch"),
    "kibana":           ("elastic", "kibana"),
    "fluentd":          ("fluentd", "fluentd"),
    "fluent-bit":       ("treasuredata", "fluent_bit"),
    # Virtualization
    "qemu-system-x86":  ("qemu", "qemu"),
    "qemu-kvm":         ("qemu", "qemu"),
    "libvirt-daemon":   ("redhat", "libvirt"),
    "libvirt0":         ("redhat", "libvirt"),
    # Security
    "fail2ban":         ("fail2ban", "fail2ban"),
    "snort":            ("snort", "snort"),
    "suricata":         ("oisf", "suricata"),
    "clamav":           ("clamav", "clamav"),
    "clamav-daemon":    ("clamav", "clamav"),
    # DNS / DHCP
    "isc-dhcp-server":  ("isc", "dhcp"),
    "unbound":          ("nlnetlabs", "unbound"),
    "knot-resolver":    ("nic", "knot_resolver"),
    # VPN
    "openvpn":          ("openvpn", "openvpn"),
    "strongswan":       ("strongswan", "strongswan"),
    "wireguard-tools":  ("wireguard", "wireguard"),
    # CMS (if installed as packages)
    "wordpress":        ("wordpress", "wordpress"),
    "drupal":           ("drupal", "drupal"),
    # Other common
    "tomcat9":          ("apache", "tomcat"),
    "tomcat10":         ("apache", "tomcat"),
    "lighttpd":         ("lighttpd", "lighttpd"),
    "proftpd-basic":    ("proftpd", "proftpd"),
    "vsftpd":           ("beasts", "vsftpd"),
    "openssh-sftp-server": ("openbsd", "openssh"),
    "socat":            ("dest-unreach", "socat"),
    "netcat-openbsd":   ("nmap", "ncat"),
    "tcpdump":          ("tcpdump", "tcpdump"),
    "nmap":             ("nmap", "nmap"),
    "inetutils-telnetd": ("gnu", "inetutils"),
    "cups":             ("openprinting", "cups"),
    "cups-daemon":      ("openprinting", "cups"),
    "libtiff5":         ("libtiff", "libtiff"),
    "libpng16-16":      ("libpng", "libpng"),
    "libjpeg-turbo8":   ("libjpeg-turbo", "libjpeg-turbo"),
    "krb5-user":        ("mit", "kerberos_5"),
    "libkrb5-3":        ("mit", "kerberos_5"),
    "ldap-utils":       ("openldap", "openldap"),
    "slapd":            ("openldap", "openldap"),
}

# Patterns for dynamic matching (linux kernel packages, etc.)
# Packages known to be network-facing services — findings for these get
# higher base confidence because they have actual attack surface.
_NETWORK_FACING_PKGS = {
    # SSH
    "openssh-server", "openssh-sftp-server",
    # Web servers
    "nginx", "nginx-common", "nginx-core", "apache2", "apache2-bin", "httpd",
    "lighttpd", "tomcat9", "tomcat10",
    # Databases (listen on network ports by default)
    "postgresql", "postgresql-16", "postgresql-15", "postgresql-14",
    "mysql-server", "mariadb-server", "redis-server", "redis",
    "mongodb-server", "elasticsearch",
    # SSL/TLS (used by network services)
    "openssl", "libssl3", "libssl1.1",
    # Proxy / LB
    "haproxy", "squid", "squid3", "varnish", "traefik",
    # Mail
    "postfix", "exim4", "dovecot-core",
    # DNS / DHCP
    "bind9", "dnsmasq", "isc-dhcp-server", "unbound",
    # VPN
    "openvpn", "strongswan", "wireguard-tools",
    # Containers
    "docker.io", "docker-ce", "containerd",
    # Message queues
    "rabbitmq-server", "mosquitto",
    # Monitoring (web UIs)
    "grafana", "zabbix-server-mysql", "zabbix-server-pgsql", "prometheus",
    "kibana", "nagios4",
    # CI/CD
    "jenkins", "gitlab-ce", "gitlab-ee",
    # CMS
    "wordpress", "drupal",
    # FTP
    "proftpd-basic", "vsftpd",
    # Runtime with web exposure
    "php", "php8.1-cli", "php8.2-cli", "php8.3-cli", "nodejs",
    # Misc network
    "cups", "cups-daemon", "samba", "nfs-common", "memcached",
    "slapd",
}

# Pattern-based network-facing detection
_NETWORK_FACING_PATTERNS = [
    r"^openssh", r"^nginx", r"^apache2", r"^httpd",
    r"^postgresql-\d+", r"^mysql-server", r"^mariadb-server",
    r"^redis-server", r"^mongodb-server",
    r"^php\d+\.\d+-(fpm|cgi)", r"^tomcat\d+",
    r"^haproxy", r"^squid", r"^postfix", r"^exim\d+",
    r"^dovecot", r"^bind9", r"^gitlab-",
    r"^zabbix-server", r"^jenkins", r"^grafana",
]


def _is_network_facing(pkg_name: str) -> bool:
    """Check if a package is a known network-facing service."""
    name_lower = pkg_name.lower().strip()
    if name_lower in _NETWORK_FACING_PKGS:
        return True
    return any(re.match(pat, name_lower) for pat in _NETWORK_FACING_PATTERNS)


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
    (r"^tomcat(\d+)", "apache", "tomcat"),
    (r"^mariadb-server", "mariadb", "mariadb"),
    (r"^mysql-server", "oracle", "mysql"),
    (r"^redis-server", "redis", "redis"),
    (r"^mongodb-server", "mongodb", "mongodb"),
    (r"^gitlab-", "gitlab", "gitlab"),
    (r"^zabbix-", "zabbix", "zabbix"),
    (r"^clamav", "clamav", "clamav"),
    (r"^libvirt", "redhat", "libvirt"),
    (r"^qemu", "qemu", "qemu"),
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
            "raw_version": version,
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
                    "raw_version": version,
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


def _is_installed_package(pkg: dict) -> bool:
    ecosystem = (pkg.get("ecosystem") or "").lower()
    if ecosystem == "deb":
        status = (pkg.get("status") or "").lower()
        if status:
            return status == "ii"
    return bool(pkg.get("installed", True))


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
                            "cwe": item.get("cwe", ""),
                            "refs": item.get("refs", []),
                            "summary": item.get("summary", ""),
                            "matched_cpe": cpe_db,
                        })
                    break

    return hits


class Check(Plugin):
    async def run(self, target, ctx):
        pkgs_all = ctx.get("inventory.packages", []) or []
        pkgs = [p for p in pkgs_all if _is_installed_package(p)]
        if not pkgs:
            return PluginResult()

        os_info = ctx.get("inventory.os", {}) or {}
        inventory_ts = os_info.get("inventory_timestamp") or ""
        host_identifier = os_info.get("host_identifier") or target
        scan_ts = os_info.get("scan_timestamp") or ctx.get("scan.started_at") or ""

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

        # Determine OS identifier for distro-patch checks
        os_id = (os_info.get("os_id") or os_info.get("id") or os_info.get("distro") or "").lower()

        # Build a lookup of raw versions from packages
        raw_ver_by_pkg = {}
        for p in pkgs:
            raw_ver_by_pkg[p["name"]] = p.get("version", "")

        findings = []
        for h in all_hits[:3000]:
            cve = h.get("cve") or h.get("id") or "UNKNOWN"
            fp = stable_fingerprint(
                target, META.plugin_id, cve, h.get("package", ""), h.get("installed", "")
            )

            # Check if the distro has likely backported the fix
            pkg_name = h.get("package", "")
            raw_ver = raw_ver_by_pkg.get(pkg_name, "")
            patched = os_id and raw_ver and is_likely_patched(raw_ver, os_id)

            network_facing = _is_network_facing(pkg_name)

            if patched:
                v_state = "likely_patched"
                v_method = "distro_backport_detected"
                v_confidence = 0.10
                v_note = (
                    "This package version contains a distro-specific patch suffix "
                    f"({raw_ver}) indicating a backported security fix. "
                    "The upstream version may be vulnerable, but the distro vendor "
                    "has likely applied the relevant security patches."
                )
            elif network_facing:
                v_state = "provisional"
                v_method = "package_version_match_network_service"
                v_confidence = 0.35
                v_note = (
                    "This is a network-facing service with a version-matched CVE. "
                    "This finding should be confirmed against vendor release "
                    "advisories and runtime exposure before treating it as a real vulnerability."
                )
            else:
                v_state = "provisional"
                v_method = "package_version_match_local_only"
                v_confidence = 0.15
                v_note = (
                    "This is a local/library package that is not directly network-reachable. "
                    "While the version matches a known CVE, exploitation typically requires "
                    "local access or a chained attack through a network-facing service. "
                    "Prioritize network-exposed services first."
                )

            # Build a more informative title based on validation state
            if patched:
                title_prefix = "[LIKELY PATCHED]"
            elif network_facing:
                title_prefix = "Potential"
            else:
                title_prefix = "[LOCAL]"

            findings.append(
                Finding(
                    severity=h.get("severity", "medium"),
                    plugin_id=META.plugin_id,
                    title=f"{title_prefix} {cve}: {h.get('package', '?')} {h.get('installed', '')}",
                    description=(
                        (h.get("summary", "") or "")
                        + f"\n\nValidation state: {v_state}"
                        + f"\nValidation method: {v_method}"
                        + f"\n{v_note}"
                    ),
                    references=h.get("refs", []),
                    evidence=(
                        f"package={pkg_name} installed={h.get('installed')} "
                        f"raw_version={raw_ver} "
                        f"ecosystem={h.get('ecosystem', '')} matched_cpe={h.get('matched_cpe', '')} "
                        f"network_facing={'yes' if network_facing else 'no'} "
                        f"validation_state={v_state} validation_method={v_method} "
                        f"scan_ts={scan_ts} inventory_ts={inventory_ts} host_id={host_identifier}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    cve=cve if cve.startswith("CVE-") else None,
                    cvss=h.get("cvss"),
                    confidence=v_confidence,
                )
            )

        return PluginResult(findings=findings, artifacts={"cve.package_hits": all_hits})
