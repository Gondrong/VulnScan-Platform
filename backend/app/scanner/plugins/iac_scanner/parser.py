"""
IaC archive ingestion + file-type detection.

Accepts either:
  • a single config file (Terraform .tf, Dockerfile, K8s YAML, etc.)
  • a .zip archive containing many files

Returns a list of ParsedFile, each tagged with a kind so the orchestrator
can dispatch to the right rule module.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import zipfile
from dataclasses import dataclass

logger = logging.getLogger("vulnscan.iac.parser")

_MAX_FILES_PER_ARCHIVE = 2000
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB per individual file


# File kinds the rules engine knows how to check
KIND_TERRAFORM = "terraform"
KIND_KUBERNETES = "kubernetes"
KIND_DOCKERFILE = "dockerfile"
KIND_CLOUDFORMATION = "cloudformation"
KIND_COMPOSE = "compose"
KIND_HELM_VALUES = "helm_values"
KIND_UNKNOWN = "unknown"


@dataclass
class ParsedFile:
    path: str          # logical path within the upload
    kind: str          # one of the KIND_* constants
    content: str       # raw file content (text)


def detect_kind(path: str, content: str) -> str:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]

    if ext in (".tf", ".tfvars"):
        return KIND_TERRAFORM
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return KIND_DOCKERFILE
    if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        return KIND_COMPOSE
    if name in ("values.yaml", "values.yml") or "/charts/" in path.lower() or "/helm/" in path.lower():
        if ext in (".yaml", ".yml"):
            return KIND_HELM_VALUES

    if ext in (".yaml", ".yml", ".json"):
        head = content[:4096].lower()
        # CloudFormation indicators
        if "awstemplateformatversion" in head or '"awstemplateformatversion"' in head:
            return KIND_CLOUDFORMATION
        if "transform: aws::serverless" in head or '"transform": "aws::serverless' in head:
            return KIND_CLOUDFORMATION
        # K8s indicators
        if "apiversion:" in head and "kind:" in head:
            return KIND_KUBERNETES
        if '"apiversion"' in head and '"kind"' in head:
            return KIND_KUBERNETES

    return KIND_UNKNOWN


def parse_upload(filename: str, raw_bytes: bytes) -> list[ParsedFile]:
    """
    Ingest a single upload (file or .zip) and return a list of ParsedFile.
    Caps file count and per-file size to keep workers safe.
    """
    files: list[ParsedFile] = []
    name_lower = (filename or "").lower()

    if name_lower.endswith(".zip"):
        files.extend(_extract_zip(raw_bytes))
    else:
        try:
            content = raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return []
        if len(raw_bytes) > _MAX_FILE_BYTES:
            content = content[:_MAX_FILE_BYTES]
        kind = detect_kind(filename or "upload", content)
        files.append(ParsedFile(path=filename or "upload", kind=kind, content=content))

    return files


def _extract_zip(raw_bytes: bytes) -> list[ParsedFile]:
    out: list[ParsedFile] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        logger.warning("IaC parser: not a valid zip archive")
        return out

    extracted = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        if extracted >= _MAX_FILES_PER_ARCHIVE:
            break
        # Path traversal / absolute-path guard
        if info.filename.startswith("/") or ".." in info.filename.split("/"):
            continue
        if info.file_size > _MAX_FILE_BYTES:
            continue
        try:
            data = zf.read(info)
        except Exception:
            continue
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            continue

        kind = detect_kind(info.filename, text)
        out.append(ParsedFile(path=info.filename, kind=kind, content=text))
        extracted += 1

    return out


def decode_archive(b64: str) -> bytes:
    """Decode the base64 archive blob carried in scan job meta_json."""
    try:
        return base64.b64decode(b64.encode("ascii"), validate=False)
    except Exception:
        return b""


def encode_archive(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
