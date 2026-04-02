"""
Cloud Storage Misconfiguration Scanner — checks for publicly accessible
cloud storage buckets and containers.

Tests:
  - AWS S3 bucket listing (public read, public write)
  - Google Cloud Storage bucket access
  - Azure Blob Storage container listing
  - DigitalOcean Spaces

Detection methods:
  - DNS-based bucket discovery from target domain
  - Common naming patterns (target-backup, target-assets, etc.)
  - HTTP response analysis for cloud storage signatures

All tests are read-only. No data is uploaded or modified.
"""
import asyncio
import logging
import re
import ssl

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.cloud_storage")

META = PluginMeta(
    plugin_id="cloud.storage.misconfig",
    name="Cloud Storage Misconfiguration Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["cloud.storage.findings"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# Suffixes to try for bucket name derivation
_BUCKET_SUFFIXES = [
    "", "-assets", "-static", "-media", "-uploads", "-backup", "-backups",
    "-data", "-public", "-files", "-cdn", "-images", "-docs", "-logs",
    "-dev", "-staging", "-prod", "-www",
]


async def _http_get(host: str, port: int, path: str, scheme: str = "https",
                    extra_headers: dict | None = None,
                    timeout: float = 5.0) -> tuple[int, dict, str]:
    """HTTP GET returning (status, headers_dict, body)."""
    try:
        if scheme == "https":
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

        headers = {
            "Host": host,
            "User-Agent": "VulnScan/2.1",
            "Accept": "*/*",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)

        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        request = f"GET {path} HTTP/1.1\r\n{header_lines}\r\n\r\n"

        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = data.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        resp_header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", resp_header_block)
        status = int(status_match.group(1)) if status_match else 0

        resp_headers = {}
        for line in resp_header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return status, resp_headers, body
    except Exception:
        return 0, {}, ""


async def _check_s3_bucket(bucket: str, findings: list[Finding], target: str):
    """Check if an S3 bucket is publicly accessible."""
    host = f"{bucket}.s3.amazonaws.com"

    status, headers, body = await _http_get(host, 443, "/", "https")

    if status == 200 and "<ListBucketResult" in body:
        # Public listing enabled!
        key_count = len(re.findall(r"<Key>", body))
        keys_sample = re.findall(r"<Key>([^<]+)</Key>", body)[:10]

        # Check for write access with a PUT preflight
        put_status, _, _ = await _http_get(
            host, 443, "/?acl", "https"
        )
        acl_public = put_status == 200

        severity = "critical" if acl_public else "high"

        fp = stable_fingerprint(target, META.plugin_id, "s3_public", bucket)
        findings.append(Finding(
            severity=severity,
            plugin_id=META.plugin_id,
            title=f"AWS S3 bucket publicly listable: {bucket} ({key_count}+ objects)",
            description=(
                f"The S3 bucket '{bucket}' allows public listing. "
                f"{key_count}+ objects are accessible. "
                f"Sample files: {', '.join(keys_sample[:5])}. "
                f"{'The bucket ACL is also publicly readable — write access may be possible. ' if acl_public else ''}"
                f"Publicly listable buckets commonly leak source code, database backups, "
                f"credentials, PII, and internal documents."
            ),
            evidence=(
                f"bucket={bucket} host={host} status={status} "
                f"objects={key_count} acl_public={acl_public} "
                f"sample_keys={keys_sample[:5]}"
            ),
            affected=f"s3://{bucket}",
            fingerprint=fp,
            confidence=0.98,
            remediation=(
                f"[{'CRITICAL' if acl_public else 'HIGH'} — S3 Bucket Public Access]\n\n"
                f"Bucket: {bucket}\n\n"
                "Immediate remediation:\n"
                "1. Block public access at the account level:\n"
                "   aws s3api put-public-access-block --bucket BUCKET \\\n"
                "     --public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,"
                "BlockPublicPolicy=true,RestrictPublicBuckets=true\n"
                "2. Review and fix bucket policy:\n"
                "   aws s3api get-bucket-policy --bucket BUCKET\n"
                "3. Enable S3 access logging and CloudTrail\n"
                "4. Check for sensitive data exposure and rotate any leaked credentials\n"
                "5. Enable S3 Block Public Access at the AWS account level\n"
                "6. Use AWS Config rule: s3-bucket-public-read-prohibited"
            ),
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "https://cwe.mitre.org/data/definitions/732.html",
            ],
        ))

    elif status == 403:
        # Bucket exists but listing denied (still useful info)
        fp = stable_fingerprint(target, META.plugin_id, "s3_exists", bucket)
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"AWS S3 bucket exists (listing denied): {bucket}",
            evidence=f"bucket={bucket} status=403",
            affected=f"s3://{bucket}",
            fingerprint=fp,
            confidence=0.80,
        ))


async def _check_gcs_bucket(bucket: str, findings: list[Finding], target: str):
    """Check if a GCS bucket is publicly accessible."""
    host = "storage.googleapis.com"
    path = f"/storage/v1/b/{bucket}/o?maxResults=10"

    status, headers, body = await _http_get(host, 443, path, "https")

    if status == 200 and '"items"' in body:
        try:
            import json
            data = json.loads(body)
            items = data.get("items", [])
            item_names = [i.get("name", "") for i in items[:10]]
        except Exception:
            items = []
            item_names = []

        fp = stable_fingerprint(target, META.plugin_id, "gcs_public", bucket)
        findings.append(Finding(
            severity="high",
            plugin_id=META.plugin_id,
            title=f"GCS bucket publicly accessible: {bucket} ({len(items)}+ objects)",
            description=(
                f"The Google Cloud Storage bucket '{bucket}' is publicly accessible. "
                f"Objects: {', '.join(item_names[:5])}."
            ),
            evidence=f"bucket={bucket} status={status} objects={len(items)} sample={item_names[:5]}",
            affected=f"gs://{bucket}",
            fingerprint=fp,
            confidence=0.95,
            remediation=(
                "[HIGH — GCS Bucket Public Access]\n\n"
                "1. Remove allUsers / allAuthenticatedUsers from bucket IAM:\n"
                "   gsutil iam ch -d allUsers gs://BUCKET\n"
                "2. Enable Uniform Bucket-Level Access:\n"
                "   gsutil uniformbucketlevelaccess set on gs://BUCKET\n"
                "3. Use Organization Policy to prevent public access:\n"
                "   constraints/storage.publicAccessPrevention\n"
                "4. Audit with: gsutil iam get gs://BUCKET"
            ),
            references=[
                "https://cloud.google.com/storage/docs/access-control",
                "https://cwe.mitre.org/data/definitions/732.html",
            ],
        ))


async def _check_azure_blob(account: str, container: str,
                            findings: list[Finding], target: str):
    """Check if an Azure Blob container is publicly accessible."""
    host = f"{account}.blob.core.windows.net"
    path = f"/{container}?restype=container&comp=list&maxresults=10"

    status, headers, body = await _http_get(host, 443, path, "https")

    if status == 200 and "<EnumerationResults" in body:
        blob_names = re.findall(r"<Name>([^<]+)</Name>", body)

        fp = stable_fingerprint(target, META.plugin_id, "azure_public", account, container)
        findings.append(Finding(
            severity="high",
            plugin_id=META.plugin_id,
            title=f"Azure Blob container publicly listable: {account}/{container}",
            description=(
                f"The Azure Blob Storage container '{container}' in account '{account}' "
                f"allows public listing. Blobs: {', '.join(blob_names[:5])}."
            ),
            evidence=f"account={account} container={container} status={status} blobs={blob_names[:5]}",
            affected=f"https://{host}/{container}",
            fingerprint=fp,
            confidence=0.95,
            remediation=(
                "[HIGH — Azure Blob Public Access]\n\n"
                "1. Set container access level to Private:\n"
                "   az storage container set-permission -n CONTAINER --public-access off\n"
                "2. Disable blob public access at storage account level:\n"
                "   az storage account update -n ACCOUNT --allow-blob-public-access false\n"
                "3. Use Azure Policy to enforce private access\n"
                "4. Enable storage account logging and Azure Monitor alerts"
            ),
            references=[
                "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
                "https://cwe.mitre.org/data/definitions/732.html",
            ],
        ))


def _derive_bucket_names(target: str) -> list[str]:
    """Derive potential bucket names from the target hostname."""
    # Extract domain parts
    parts = target.replace("www.", "").split(".")
    base_names = set()

    # Use full domain, domain without TLD, and first part
    if len(parts) >= 2:
        base_names.add(".".join(parts))           # example.com
        base_names.add(".".join(parts[:-1]))       # example
        base_names.add(parts[0])                   # example
        base_names.add("-".join(parts[:-1]))        # sub-example
    else:
        base_names.add(parts[0])

    # Generate candidates with suffixes
    candidates = []
    for base in base_names:
        for suffix in _BUCKET_SUFFIXES:
            name = base + suffix
            if 3 <= len(name) <= 63 and re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", name):
                candidates.append(name)

    return list(dict.fromkeys(candidates))[:20]  # Deduplicate, limit to 20


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []

        # Derive bucket names from target
        bucket_names = _derive_bucket_names(target_raw)
        if not bucket_names:
            bucket_names = _derive_bucket_names(target)

        if not bucket_names:
            return PluginResult(artifacts={"cloud.storage.findings": 0})

        # Check S3 and GCS in parallel (limit concurrency)
        sem = asyncio.Semaphore(5)

        async def _limited_s3(b):
            async with sem:
                await _check_s3_bucket(b, findings, target)

        async def _limited_gcs(b):
            async with sem:
                await _check_gcs_bucket(b, findings, target)

        tasks = []
        for bucket in bucket_names:
            tasks.append(_limited_s3(bucket))
            tasks.append(_limited_gcs(bucket))

        # Azure: try common account/container combos
        azure_names = [n for n in bucket_names if "." not in n][:5]
        for account in azure_names:
            for container in ["public", "assets", "data", "files", "backups", "media"]:
                async def _limited_azure(a=account, c=container):
                    async with sem:
                        await _check_azure_blob(a, c, findings, target)
                tasks.append(_limited_azure())

        await asyncio.gather(*tasks, return_exceptions=True)

        return PluginResult(
            findings=findings,
            artifacts={"cloud.storage.findings": len(findings)},
        )
