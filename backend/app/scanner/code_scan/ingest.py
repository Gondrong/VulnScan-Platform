"""
Source ingestion for the code scanner.

Resolves a scan source — an uploaded archive, or a git remote (GitHub, GitLab,
Bitbucket, or any https/ssh URL) — into a local working tree under
/data/code/<job_id>/tree, then enumerates it with the strategy-C pre-filter.

Design choice honouring "nothing should be missed": the pre-filter is
*inverted* — a file is treated as source (and will be read) UNLESS it is
provably non-source: a binary, a media/asset file, VCS metadata, a vendored
dependency tree, or a minified/generated bundle. An unknown extension defaults
to source, not to skipped. Dependency lockfiles/manifests are routed to the SCA
track rather than read as source. Every excluded path is recorded.

Safety:
  * git clones are --depth 1 --no-recurse-submodules; submodules can fetch
    arbitrary URLs, and clone does not transfer or run hooks.
  * GIT_TERMINAL_PROMPT=0 — git never blocks waiting for a credential prompt.
  * Secrets are passed to git via a GIT_ASKPASS helper / key file in a 0700
    temp dir, never on the command line, and are wiped in a finally block.
  * Archive extraction is bounded (member count, total uncompressed bytes) and
    rejects path-traversal ("zip slip") members.
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("vulnscan.code_scan.ingest")

# ── Tunables (env-overridable, no rebuild needed) ───────────────────────────
MAX_FILE_BYTES = int(os.environ.get("CODE_SCAN_MAX_FILE_BYTES", str(1 * 1024 * 1024)))        # 1 MB
MAX_TREE_BYTES = int(os.environ.get("CODE_SCAN_MAX_TREE_BYTES", str(500 * 1024 * 1024)))      # 500 MB extracted
MAX_ARCHIVE_MEMBERS = int(os.environ.get("CODE_SCAN_MAX_ARCHIVE_MEMBERS", "100000"))
MAX_SOURCE_FILES = int(os.environ.get("CODE_SCAN_MAX_SOURCE_FILES", "1500"))                  # warn threshold
CODE_ROOT = os.environ.get("CODE_SCAN_ROOT", "/data/code")
GIT_TIMEOUT = int(os.environ.get("CODE_SCAN_GIT_TIMEOUT", "600"))

# Directories never descended into: VCS metadata, vendored deps, build output,
# tool caches. Their lockfiles live at the repo root, so SCA coverage is intact.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".bzr",
    "node_modules", "bower_components", "vendor", "vendored", "third_party",
    "dist", "build", "out", "target", ".next", ".nuxt", ".output",
    ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".gradle", ".idea", ".vscode", ".terraform", ".serverless",
    "coverage", ".nyc_output", "site-packages", ".cache",
}

# Dependency manifests / lockfiles → routed to the SCA track, not read as source.
_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "requirements.txt", "pipfile.lock", "poetry.lock",
    "composer.json", "composer.lock",
    "gemfile.lock",
    "go.mod", "go.sum",
    "pom.xml", "gradle.lockfile",
    "cargo.toml", "cargo.lock",
    "packages.config",
    "pubspec.lock",
}
_MANIFEST_SUFFIXES = (".csproj",)  # NuGet project files

# Provably non-source by extension → skipped (recorded).
_BINARY_EXTS = {
    # images / media
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm", ".wav", ".flac", ".ogg",
    # fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # archives / compiled / binaries
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".class", ".pyc", ".pyo", ".o", ".obj", ".a", ".lib", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".wasm", ".node", ".pdb",
    # documents / data blobs
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".db", ".sqlite", ".sqlite3", ".mo",
    # maps
    ".map",
}


class IngestError(Exception):
    """Source could not be prepared (bad URL/archive, network, etc.)."""


class CredentialRequired(IngestError):
    """Repository is private and no credential was supplied."""


class CredentialRejected(IngestError):
    """Supplied credential was refused by the remote."""


@dataclass
class SourceTree:
    root: str                                   # absolute path of the working tree
    label: str                                  # human label (repo url / filename)
    source_files: list[str] = field(default_factory=list)      # paths relative to root
    manifest_files: list[str] = field(default_factory=list)    # relative paths, for SCA
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (relpath, reason)
    over_cap: bool = False                       # exceeded MAX_SOURCE_FILES

    def abspath(self, rel: str) -> str:
        return str(Path(self.root) / rel)


# ── Public entry point ──────────────────────────────────────────────────────
def ingest_source(source: dict, *, job_id: int | None = None) -> SourceTree:
    stype = (source.get("type") or "").lower()
    workdir = _workdir(job_id)
    tree_dir = os.path.join(workdir, "tree")
    # Fresh tree every run
    if os.path.isdir(tree_dir):
        shutil.rmtree(tree_dir, ignore_errors=True)
    os.makedirs(tree_dir, exist_ok=True)

    if stype == "zip":
        label = source.get("filename") or source.get("ref") or "archive.zip"
        _extract_archive(source.get("ref") or "", tree_dir)
    elif stype == "git":
        label = source.get("ref") or "repository"
        _clone_git(source.get("ref") or "", tree_dir, source.get("auth"))
    else:
        raise IngestError(f"Unknown source type: {stype!r}")

    tree = SourceTree(root=tree_dir, label=str(label))
    _enumerate(tree)
    return tree


def _workdir(job_id: int | None) -> str:
    if job_id is not None:
        d = os.path.join(CODE_ROOT, str(job_id))
        os.makedirs(d, exist_ok=True)
        return d
    return tempfile.mkdtemp(prefix="code_scan_")


# ── Archive (zip) ───────────────────────────────────────────────────────────
def _extract_archive(archive_path: str, dest: str) -> None:
    if not archive_path or not os.path.isfile(archive_path):
        raise IngestError(f"Uploaded archive not found: {archive_path}")
    if not zipfile.is_zipfile(archive_path):
        raise IngestError("Upload is not a valid .zip archive")

    dest_real = os.path.realpath(dest)
    total = 0
    members = 0
    try:
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    raise IngestError(f"Archive has too many entries (> {MAX_ARCHIVE_MEMBERS})")
                if info.is_dir():
                    continue
                # zip-slip guard: resolved path must stay under dest
                target = os.path.realpath(os.path.join(dest, info.filename))
                if not (target == dest_real or target.startswith(dest_real + os.sep)):
                    raise IngestError(f"Archive member escapes extraction dir: {info.filename}")
                total += info.file_size
                if total > MAX_TREE_BYTES:
                    raise IngestError(
                        f"Archive expands beyond {MAX_TREE_BYTES // (1024*1024)} MB "
                        "(possible zip bomb); refusing to extract"
                    )
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
    except zipfile.BadZipFile as e:
        raise IngestError(f"Corrupt zip archive: {e}") from e

    # If the archive is a single top-level dir (GitHub-style export), flatten it.
    entries = [e for e in os.listdir(dest) if not e.startswith("__MACOSX")]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        inner = os.path.join(dest, entries[0])
        for item in os.listdir(inner):
            shutil.move(os.path.join(inner, item), os.path.join(dest, item))
        shutil.rmtree(inner, ignore_errors=True)


# ── Git ─────────────────────────────────────────────────────────────────────
def preflight_git(url: str, auth: dict | None) -> tuple[str, str]:
    """Check reachability/auth of a git remote without cloning. Never raises.

    Returns (status, message) where status is one of:
      ok                   reachable (public, or the credential works)
      credential_required  private and no credential supplied
      credential_rejected  credential supplied but refused
      unreachable          bad URL, DNS, network, or not a repository
    """
    if not url or not url.startswith(("http://", "https://", "git@", "ssh://")):
        return "unreachable", f"Not a supported git URL: {url!r}"
    env, cleanup = _git_auth_env(url, auth)
    try:
        pf = subprocess.run(
            ["git", "ls-remote", "--heads", url],
            env=env, capture_output=True, text=True, timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        cleanup()
        return "unreachable", f"git timed out after {GIT_TIMEOUT}s"
    except Exception as e:  # noqa: BLE001
        cleanup()
        return "unreachable", str(e)
    cleanup()
    if pf.returncode == 0:
        return "ok", "Repository reachable" + (" with credential" if auth else " (public)")
    try:
        _raise_git_error(pf.stderr or pf.stdout, auth)
    except CredentialRequired as e:
        return "credential_required", str(e)
    except CredentialRejected as e:
        return "credential_rejected", str(e)
    except IngestError as e:
        return "unreachable", str(e)
    return "unreachable", (pf.stderr or "").strip()[:400]


def _clone_git(url: str, dest: str, auth: dict | None) -> None:
    if not url or not (url.startswith(("http://", "https://", "git@", "ssh://"))):
        raise IngestError(f"Not a supported git URL: {url!r}")

    env, cleanup = _git_auth_env(url, auth)
    try:
        # 1) Preflight — ls-remote distinguishes missing-credential / rejected /
        #    unreachable before we commit to a clone.
        pf = subprocess.run(
            ["git", "ls-remote", "--heads", url],
            env=env, capture_output=True, text=True, timeout=GIT_TIMEOUT,
        )
        if pf.returncode != 0:
            _raise_git_error(pf.stderr or pf.stdout, auth)

        # 2) Clone (shallow, no submodules)
        cl = subprocess.run(
            ["git", "clone", "--depth", "1", "--no-recurse-submodules",
             "--quiet", url, dest],
            env=env, capture_output=True, text=True, timeout=GIT_TIMEOUT,
        )
        if cl.returncode != 0:
            _raise_git_error(cl.stderr or cl.stdout, auth)
    except subprocess.TimeoutExpired as e:
        raise IngestError(f"git timed out after {GIT_TIMEOUT}s") from e
    finally:
        cleanup()


def _git_auth_env(url: str, auth: dict | None):
    """Build an environment for git that never blocks on a prompt and carries
    the credential out-of-band. Returns (env, cleanup_callable)."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    tmp_paths: list[str] = []

    def cleanup():
        for p in tmp_paths:
            try:
                os.remove(p)
            except OSError:
                pass

    if not auth:
        return env, cleanup

    scheme = (auth.get("scheme") or "").lower()
    if scheme == "ssh" or url.startswith(("git@", "ssh://")):
        key = auth.get("secret") or ""
        if key:
            fd, keyfile = tempfile.mkstemp(prefix="code_scan_key_")
            os.write(fd, key.encode() + (b"\n" if not key.endswith("\n") else b""))
            os.close(fd)
            os.chmod(keyfile, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            tmp_paths.append(keyfile)
            env["GIT_SSH_COMMAND"] = (
                f"ssh -i {keyfile} -o IdentitiesOnly=yes "
                "-o StrictHostKeyChecking=accept-new -o BatchMode=yes"
            )
    else:
        # HTTPS: username + token/password via a GIT_ASKPASS helper so the
        # secret never appears in argv or the URL.
        username = auth.get("username") or "x-access-token"
        secret = auth.get("secret") or ""
        fd, askpass = tempfile.mkstemp(prefix="code_scan_ap_", suffix=".sh")
        script = (
            "#!/bin/sh\n"
            'case "$1" in\n'
            f"  *[Uu]sername*) printf '%s' \"{_sh_quote(username)}\" ;;\n"
            f"  *[Pp]assword*) printf '%s' \"{_sh_quote(secret)}\" ;;\n"
            "esac\n"
        )
        os.write(fd, script.encode())
        os.close(fd)
        os.chmod(askpass, stat.S_IRWXU)  # 0700
        tmp_paths.append(askpass)
        env["GIT_ASKPASS"] = askpass

    return env, cleanup


def _sh_quote(val: str) -> str:
    # Embedded inside double quotes in the askpass script; neutralise the few
    # characters that would break out of the quoting.
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")


def _raise_git_error(stderr: str, auth: dict | None) -> None:
    low = (stderr or "").lower()
    auth_markers = (
        "authentication failed", "could not read username", "could not read password",
        "terminal prompts disabled", "permission denied (publickey)", "403 forbidden",
        "invalid username or password", "access denied", "fatal: could not read",
        "remote: not found",  # GitHub hides private-repo 404 behind auth
    )
    is_auth = any(m in low for m in auth_markers)
    snippet = (stderr or "").strip()[:400]
    if is_auth:
        if auth:
            raise CredentialRejected(f"Remote refused the credential. git: {snippet}")
        raise CredentialRequired(f"Repository appears private — credential needed. git: {snippet}")
    raise IngestError(f"git failed: {snippet}")


# ── Enumeration + pre-filter ────────────────────────────────────────────────
def _enumerate(tree: SourceTree) -> None:
    root = tree.root
    for dirpath, dirnames, filenames in os.walk(root):
        # prune skip-dirs in place so we never descend into them
        pruned = [d for d in dirnames if d in _SKIP_DIRS]
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for d in pruned:
            rel = os.path.relpath(os.path.join(dirpath, d), root)
            tree.skipped.append((rel, "vendored_or_generated_dir"))

        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            cls, reason = _classify(full, name)
            if cls == "manifest":
                tree.manifest_files.append(rel)
            elif cls == "source":
                tree.source_files.append(rel)
            else:  # skip
                tree.skipped.append((rel, reason))

    tree.source_files.sort()
    tree.manifest_files.sort()
    tree.skipped.sort()
    if len(tree.source_files) > MAX_SOURCE_FILES:
        tree.over_cap = True
        logger.warning("Code scan tree has %d source files (> cap %d) for %s",
                       len(tree.source_files), MAX_SOURCE_FILES, tree.label)


def _classify(full: str, name: str) -> tuple[str, str]:
    lname = name.lower()
    if lname in _MANIFEST_NAMES or lname.endswith(_MANIFEST_SUFFIXES):
        return "manifest", ""
    ext = os.path.splitext(lname)[1]
    if ext in _BINARY_EXTS:
        return "skip", "binary_or_media"
    # minified / generated bundles
    if ".min." in lname or lname.endswith((".min.js", ".min.css", "-min.js", ".bundle.js")):
        return "skip", "minified_bundle"
    try:
        size = os.path.getsize(full)
    except OSError:
        return "skip", "unreadable"
    if size == 0:
        return "skip", "empty"
    if size > MAX_FILE_BYTES:
        return "skip", "oversize"
    if _looks_binary(full):
        return "skip", "binary_content"
    if _looks_minified(full, size):
        return "skip", "minified_content"
    return "source", ""


def _looks_binary(full: str) -> bool:
    """NUL byte in the first 8 KiB → treat as binary (covers unknown formats)."""
    try:
        with open(full, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def _looks_minified(full: str, size: int) -> bool:
    """Generated/minified text: very long average line length. Skips the token
    cost of unreadable bundles that slipped past the name/extension check."""
    if size < 50_000:
        return False
    try:
        with open(full, "rb") as f:
            chunk = f.read(65536)
    except OSError:
        return False
    newlines = chunk.count(b"\n")
    if newlines == 0:
        return True
    return (len(chunk) / (newlines + 1)) > 2000  # avg >2000 chars/line
