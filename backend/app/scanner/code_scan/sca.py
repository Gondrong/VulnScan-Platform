"""
SCA track — dependency vulnerability analysis for the code scanner.

Parses dependency lockfiles/manifests from the ingested tree into pinned
(ecosystem, package, version) tuples, then matches them against the OSV
dataset using the existing matcher in cve_packages.match_osv. Produces a
Finding per vulnerable dependency.

Lockfiles (exact pins) are strongly preferred over manifests (version ranges),
because SCA precision depends on knowing the *installed* version. Manifests are
parsed only as a fallback and marked lower-confidence.

Ecosystem names follow OSV.dev's canonical spelling so they match the OSV
feeder's output exactly: npm, PyPI, Maven, Go, RubyGems, Packagist,
crates.io, NuGet.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Iterable

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.code_scan.sca")

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


# ── public entry ─────────────────────────────────────────────────────────────
def run_sca(tree, workspace_id: int) -> list[Finding]:
    from app.db.session import SessionLocal
    from app.db import models
    from app.cve.dataset_loader import load_json
    from app.scanner.plugins.cve_packages import match_osv

    # pkgs with origin tracking: (ecosystem, name, version) -> set(manifest rel paths)
    origin: dict[tuple[str, str, str], set[str]] = {}
    pkgs: list[dict] = []
    manifests_parsed = 0

    for rel in tree.manifest_files:
        name = os.path.basename(rel).lower()
        parser = _PARSERS.get(name) or _suffix_parser(name)
        if not parser:
            continue
        try:
            with open(tree.abspath(rel), "rb") as f:
                raw = f.read()
            found = list(parser(raw))
        except Exception as e:  # noqa: BLE001 — a bad manifest must not sink SCA
            logger.info("SCA: could not parse %s: %s", rel, e)
            continue
        manifests_parsed += 1
        for eco, pkg, ver in found:
            if not (eco and pkg and ver):
                continue
            key = (eco, pkg, ver)
            if key not in origin:
                origin[key] = set()
                pkgs.append({"ecosystem": eco, "name": pkg, "version": ver})
            origin[key].add(rel)

    findings: list[Finding] = []

    # Summary finding (always emitted, even with zero deps/hits)
    findings.append(Finding(
        plugin_id="code.sca.summary",
        title=f"SCA: {len(pkgs)} dependencies from {manifests_parsed} manifest(s)",
        severity="info",
        description=(
            "Dependencies extracted from lockfiles/manifests and checked against "
            "the OSV advisory dataset. A dependency with no finding either has no "
            "known advisory, or its ecosystem is not yet covered by the OSV feed."
        ),
        evidence="\n".join(sorted({os.path.basename(m) for m in tree.manifest_files})) or "(none)",
        affected=tree.label,
        fingerprint=stable_fingerprint(tree.label, "code.sca.summary", len(pkgs)),
    ))

    if not pkgs:
        return findings

    db = SessionLocal()
    try:
        osv_dsets = (
            db.query(models.CveDataset)
            .filter(
                models.CveDataset.workspace_id == workspace_id,
                models.CveDataset.kind == "osv",
                models.CveDataset.enabled == True,  # noqa: E712
            )
            .all()
        )
        if not osv_dsets:
            findings.append(Finding(
                plugin_id="code.sca.no_dataset",
                title="SCA ran without an OSV advisory dataset",
                severity="info",
                description=(
                    "No enabled 'osv' dataset is present, so dependency-to-CVE "
                    "matching found nothing. Refresh the OSV dataset (Datasets "
                    "page) to enable vulnerable-dependency detection."
                ),
                remediation="Enable/refresh the OSV dataset, then re-run the scan.",
                affected=tree.label,
                fingerprint=stable_fingerprint(tree.label, "code.sca.no_dataset", 0),
            ))
            return findings

        hits = []
        for ds in osv_dsets:
            try:
                hits += match_osv(pkgs, load_json(ds.path))
            except Exception as e:  # noqa: BLE001
                logger.warning("SCA: OSV match failed on %s: %s", ds.path, e)
    finally:
        db.close()

    seen: set[str] = set()
    for h in hits:
        eco = h.get("ecosystem", "")
        pkg = h.get("package", "")
        ver = h.get("installed", "")
        cve = h.get("cve") or h.get("id") or ""
        where = sorted(origin.get((eco, pkg, ver), {tree.label}))
        fp = stable_fingerprint(where[0] if where else tree.label, cve, f"{pkg}@{ver}")
        if fp in seen:
            continue
        seen.add(fp)
        sev = (h.get("severity") or "medium").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        refs = h.get("refs") or []
        findings.append(Finding(
            plugin_id=f"code.sca.{_slug(eco)}",
            title=f"Vulnerable dependency: {pkg} {ver} — {cve}",
            severity=sev,
            description=(
                f"{h.get('summary') or 'Known vulnerability in a third-party dependency.'}\n\n"
                f"Ecosystem: {eco}\nPackage: {pkg}\nInstalled: {ver}\n"
                f"Advisory: {h.get('id') or cve}"
            ),
            remediation=(
                f"Upgrade {pkg} to a non-affected version. Consult the advisory "
                f"({cve}) for the fixed version, then update the lockfile and redeploy."
            ),
            evidence="declared in: " + ", ".join(where),
            affected=f"{eco}:{pkg}@{ver}",
            cve=cve or None,
            references=list(refs) if isinstance(refs, (list, tuple)) else [str(refs)],
            fingerprint=fp,
            confidence=0.9,
        ))

    return findings


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "dep").lower()).strip("_") or "dep"


# ── manifest parsers → yield (ecosystem, package, version) ───────────────────
def _p_package_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    data = json.loads(raw)
    # npm lockfile v2/v3: "packages": {"node_modules/foo": {"version": ...}}
    for path, meta in (data.get("packages") or {}).items():
        if not path:  # the root project ("")
            continue
        nm = path.rsplit("node_modules/", 1)[-1]
        ver = (meta or {}).get("version")
        if nm and ver:
            yield ("npm", nm, ver)
    # v1 fallback: "dependencies": {"foo": {"version": ...}}
    if not data.get("packages"):
        def walk(deps):
            for nm, meta in (deps or {}).items():
                ver = (meta or {}).get("version")
                if nm and ver:
                    yield ("npm", nm, ver)
                yield from walk((meta or {}).get("dependencies"))
        yield from walk(data.get("dependencies"))


def _p_yarn_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    text = raw.decode("utf-8", "replace")
    # Entries: a header line "foo@^1.0.0, foo@~1.2:" then "  version \"1.2.3\""
    cur_names: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t", "#")):
            cur_names = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                # strip trailing @range → keep package name (handle @scope/pkg)
                at = spec.rfind("@")
                nm = spec[:at] if at > 0 else spec
                if nm:
                    cur_names.append(nm)
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m and cur_names:
                for nm in cur_names:
                    yield ("npm", nm, m.group(1))
                cur_names = []


def _p_requirements(raw: bytes) -> Iterable[tuple[str, str, str]]:
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            yield ("PyPI", _norm_py(m.group(1)), m.group(2))


def _p_pipfile_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    data = json.loads(raw)
    for section in ("default", "develop"):
        for nm, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "")
            ver = ver.lstrip("=") if isinstance(ver, str) else ""
            if nm and ver:
                yield ("PyPI", _norm_py(nm), ver)


def _p_poetry_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    if not tomllib:
        return
    data = tomllib.loads(raw.decode("utf-8", "replace"))
    for pkg in data.get("package", []) or []:
        nm, ver = pkg.get("name"), pkg.get("version")
        if nm and ver:
            yield ("PyPI", _norm_py(nm), ver)


def _p_composer_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    data = json.loads(raw)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []) or []:
            nm, ver = pkg.get("name"), pkg.get("version")
            if nm and ver:
                yield ("Packagist", nm, str(ver).lstrip("v"))


def _p_gemfile_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    # "    rails (7.0.4)" under the specs: section
    for line in raw.decode("utf-8", "replace").splitlines():
        m = re.match(r"^\s{4}([A-Za-z0-9._-]+) \(([^()]+)\)\s*$", line)
        if m:
            yield ("RubyGems", m.group(1), m.group(2))


def _p_cargo_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    if not tomllib:
        return
    data = tomllib.loads(raw.decode("utf-8", "replace"))
    for pkg in data.get("package", []) or []:
        nm, ver = pkg.get("name"), pkg.get("version")
        if nm and ver:
            yield ("crates.io", nm, ver)


def _p_go_mod(raw: bytes) -> Iterable[tuple[str, str, str]]:
    text = raw.decode("utf-8", "replace")
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("require "):
            s = s[len("require "):].strip()
        elif not in_block:
            continue
        s = s.split("//", 1)[0].strip()
        m = re.match(r"^(\S+)\s+v([0-9][^\s]*)", s)
        if m:
            yield ("Go", m.group(1), m.group(2))


def _p_pubspec_lock(raw: bytes) -> Iterable[tuple[str, str, str]]:
    # Dart/Flutter pubspec.lock (YAML): packages: {name: {version: "x.y.z"}}
    try:
        import yaml
    except ModuleNotFoundError:
        return
    try:
        data = yaml.safe_load(raw.decode("utf-8", "replace")) or {}
    except Exception:  # noqa: BLE001
        return
    for name, meta in (data.get("packages") or {}).items():
        ver = (meta or {}).get("version") if isinstance(meta, dict) else None
        if name and ver:
            yield ("Pub", str(name), str(ver))


def _norm_py(name: str) -> str:
    # PEP 503 normalisation so manifest names match OSV package names
    return re.sub(r"[-_.]+", "-", name).lower()


_PARSERS = {
    "package-lock.json": _p_package_lock,
    "npm-shrinkwrap.json": _p_package_lock,
    "yarn.lock": _p_yarn_lock,
    "requirements.txt": _p_requirements,
    "pipfile.lock": _p_pipfile_lock,
    "poetry.lock": _p_poetry_lock,
    "composer.lock": _p_composer_lock,
    "gemfile.lock": _p_gemfile_lock,
    "cargo.lock": _p_cargo_lock,
    "go.mod": _p_go_mod,
    "pubspec.lock": _p_pubspec_lock,
}


def _suffix_parser(name: str):
    return None
