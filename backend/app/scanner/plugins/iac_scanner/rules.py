"""
IaC rule definitions and per-language check functions.

Each check function takes (path, content) and returns a list of RuleHit.
The orchestrator turns RuleHits into Finding objects.

Detection is intentionally pattern/regex/YAML based — fast, no external
deps. False positives are filtered with `confidence` and the AI deep
analysis pass can validate later.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable


@dataclass
class RuleHit:
    rule_id: str
    title: str
    severity: str           # critical | high | medium | low | info
    description: str
    remediation: str
    evidence: str
    line: int = 0
    confidence: float = 0.85
    framework: str = ""     # NIST 800-53 | CIS | PCI tag


# ─── Terraform (HCL — regex-based) ────────────────────────────────────────────

_TF_SECRET_RE = re.compile(
    r'(?i)(password|secret|api[_-]?key|access[_-]?key|private[_-]?key|aws[_-]?secret)'
    r'\s*=\s*"([^"\$\{][^"]{6,})"'
)
_TF_PUBLIC_S3_RE = re.compile(
    r'resource\s+"aws_s3_bucket(?:_acl)?"\s+"[^"]+"\s*\{[^{}]*?'
    r'(?:acl|access)\s*=\s*"(public-read|public-read-write)"',
    re.S,
)
_TF_OPEN_SG_RE = re.compile(
    r'(?:ingress|egress)\s*\{[^{}]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
    re.S,
)
_TF_PUBLIC_RDS_RE = re.compile(
    r'resource\s+"aws_db_instance"[^{}]*\{[^{}]*?publicly_accessible\s*=\s*true',
    re.S,
)
_TF_NO_ENCRYPTION_RE = re.compile(
    r'resource\s+"aws_(?:s3_bucket|ebs_volume|rds_cluster|db_instance)"[^{}]*\{[^{}]*$',
    re.S,
)
_TF_LATEST_AMI_RE = re.compile(r'ami\s*=\s*"ami-[a-f0-9]+"')


def check_terraform(path: str, content: str) -> list[RuleHit]:
    hits: list[RuleHit] = []

    for m in _TF_SECRET_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.tf.hardcoded_secret",
            title=f"Hardcoded secret in Terraform — {m.group(1)}",
            severity="critical",
            description=(
                "Terraform configuration contains what appears to be a hardcoded "
                "secret. Secrets in source-controlled IaC are exposed to anyone "
                "with repo access and risk leaking into Terraform state files."
            ),
            remediation=(
                "Move the secret to a secret manager (AWS Secrets Manager, "
                "HashiCorp Vault, SOPS, AWS SSM Parameter Store) and reference "
                "it via data sources. Rotate the leaked value immediately."
            ),
            evidence=f"{path}:{line} match={m.group(0)[:120]}",
            line=line,
            framework="NIST IA-5",
        ))

    for m in _TF_PUBLIC_S3_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.tf.s3_public_acl",
            title="S3 bucket configured with public ACL",
            severity="high",
            description=(
                "An aws_s3_bucket / aws_s3_bucket_acl resource sets acl to "
                "public-read or public-read-write. Public buckets are a leading "
                "cause of cloud data breaches."
            ),
            remediation=(
                "Set acl=\"private\" and use aws_s3_bucket_public_access_block to "
                "enforce. Use signed URLs or CloudFront for public asset delivery."
            ),
            evidence=f"{path}:{line} {m.group(0)[:160]}",
            line=line,
            framework="CIS AWS 2.1.5",
        ))

    for m in _TF_OPEN_SG_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.tf.sg_open_world",
            title="Security group rule allows 0.0.0.0/0",
            severity="high",
            description=(
                "A security group ingress/egress rule allows traffic from/to the "
                "entire internet (0.0.0.0/0). Combined with an open port, this "
                "exposes the workload directly to the public internet."
            ),
            remediation=(
                "Restrict cidr_blocks to specific source ranges. Use VPC peering, "
                "PrivateLink, or a bastion + IAM-authenticated access for "
                "administrative ports (22, 3389)."
            ),
            evidence=f"{path}:{line} {m.group(0)[:160]}",
            line=line,
            framework="CIS AWS 5.2",
        ))

    for m in _TF_PUBLIC_RDS_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.tf.rds_public",
            title="RDS instance is publicly accessible",
            severity="high",
            description=(
                "aws_db_instance has publicly_accessible=true. Database engines "
                "should never be exposed to the public internet — even with strong "
                "passwords, they are a frequent target of credential stuffing and "
                "engine-level exploits."
            ),
            remediation=(
                "Set publicly_accessible=false. Place the RDS in a private subnet "
                "and connect from application tier via VPC routing or IAM auth."
            ),
            evidence=f"{path}:{line}",
            line=line,
            framework="CIS AWS 2.3.3",
        ))

    return hits


# ─── Dockerfile ───────────────────────────────────────────────────────────────

_DF_LATEST_TAG_RE = re.compile(r"^\s*FROM\s+\S+:latest", re.I | re.M)
_DF_NO_TAG_RE = re.compile(r"^\s*FROM\s+([^\s:@]+)\s*$", re.I | re.M)
_DF_USER_ROOT_RE = re.compile(r"^\s*USER\s+(0|root)\s*$", re.I | re.M)
_DF_ADD_REMOTE_RE = re.compile(r"^\s*ADD\s+https?://", re.I | re.M)
_DF_SECRET_ENV_RE = re.compile(
    r'(?i)^\s*(?:ENV|ARG)\s+([A-Z_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Z_]*)\s*[= ]\s*(.+)$',
    re.M,
)
_DF_CURL_PIPE_SH_RE = re.compile(
    r"(?i)curl\s+(?:-[a-z]+\s+)*\S+\s*\|\s*(?:bash|sh)"
)
_DF_APT_NO_FIX_RE = re.compile(
    r"(?i)apt-get\s+install(?!.*--no-install-recommends)"
)


def check_dockerfile(path: str, content: str) -> list[RuleHit]:
    hits: list[RuleHit] = []

    has_user_clause = bool(re.search(r"^\s*USER\s+\S+", content, re.I | re.M))
    if not has_user_clause:
        hits.append(RuleHit(
            rule_id="iac.docker.no_user",
            title="Dockerfile does not specify a non-root USER",
            severity="medium",
            description=(
                "No USER instruction means the container runs as root by default. "
                "A compromise of the application then gives root inside the "
                "container, which is a much easier path to host escape."
            ),
            remediation=(
                "Add 'RUN useradd -r -u 10001 app' and 'USER app' near the end of "
                "the Dockerfile. Ensure the application can write only to "
                "directories it owns."
            ),
            evidence=f"{path} (no USER directive)",
            framework="CIS Docker 4.1",
        ))

    for m in _DF_LATEST_TAG_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.docker.latest_tag",
            title="Base image uses :latest tag",
            severity="medium",
            description=(
                "FROM ...:latest is non-deterministic — image content changes "
                "silently across builds, which breaks reproducibility and lets "
                "supply-chain compromises slip in."
            ),
            remediation=(
                "Pin to an immutable tag and ideally a digest, "
                "e.g. 'FROM nginx:1.25.4@sha256:abcd...'."
            ),
            evidence=f"{path}:{line}",
            line=line,
        ))

    for m in _DF_NO_TAG_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.docker.no_tag",
            title=f"Base image '{m.group(1)}' has no tag (defaults to :latest)",
            severity="medium",
            description="FROM with no tag is equivalent to ':latest' and inherits the same risks.",
            remediation="Pin to an explicit version tag and digest.",
            evidence=f"{path}:{line} image={m.group(1)}",
            line=line,
        ))

    for m in _DF_USER_ROOT_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.docker.user_root",
            title="Dockerfile explicitly sets USER root",
            severity="high",
            description="USER 0/root forces the container to run as root.",
            remediation="Switch to a dedicated non-root UID (>= 10000).",
            evidence=f"{path}:{line}",
            line=line,
            framework="CIS Docker 4.1",
        ))

    for m in _DF_ADD_REMOTE_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.docker.add_remote",
            title="ADD with a remote URL",
            severity="medium",
            description=(
                "ADD with a remote URL bypasses Docker's layer caching, does not "
                "verify integrity, and embeds the fetched content into the image "
                "without a checksum check."
            ),
            remediation=(
                "Use 'curl -fsSL ... | sha256sum -c -' followed by 'COPY' from a "
                "build stage, or fetch artifacts at deploy time with verification."
            ),
            evidence=f"{path}:{line}",
            line=line,
        ))

    for m in _DF_SECRET_ENV_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        # Skip obvious placeholders
        val = (m.group(2) or "").strip().strip('"').strip("'")
        if val.startswith("$") or val == "" or val.lower() in ("changeme", "placeholder"):
            continue
        hits.append(RuleHit(
            rule_id="iac.docker.secret_env",
            title=f"Hardcoded secret in ENV/ARG: {m.group(1)}",
            severity="critical",
            description=(
                "Secrets in ENV/ARG land in image layers and 'docker history'. "
                "They are visible to anyone with pull access to the image."
            ),
            remediation=(
                "Use --secret build mounts, runtime secret injection (Vault, AWS "
                "Secrets Manager, K8s Secrets), or external configuration. Rotate "
                "the leaked value immediately."
            ),
            evidence=f"{path}:{line} key={m.group(1)}",
            line=line,
            confidence=0.7,
            framework="NIST IA-5",
        ))

    for m in _DF_CURL_PIPE_SH_RE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        hits.append(RuleHit(
            rule_id="iac.docker.curl_pipe_sh",
            title="curl | sh / curl | bash detected",
            severity="medium",
            description=(
                "Piping a remote script directly into a shell removes any chance "
                "of integrity verification and is a classic supply-chain risk."
            ),
            remediation=(
                "Download with curl/wget to a file, verify its checksum or "
                "signature, then execute. Pin the version of the upstream script."
            ),
            evidence=f"{path}:{line}",
            line=line,
        ))

    return hits


# ─── Kubernetes / Helm values ─────────────────────────────────────────────────

_K8S_PRIVILEGED_RE = re.compile(r"privileged\s*:\s*true", re.I)
_K8S_HOSTNETWORK_RE = re.compile(r"hostNetwork\s*:\s*true", re.I)
_K8S_HOSTPID_RE = re.compile(r"hostPID\s*:\s*true", re.I)
_K8S_HOSTIPC_RE = re.compile(r"hostIPC\s*:\s*true", re.I)
_K8S_RUNASROOT_RE = re.compile(r"runAsUser\s*:\s*0\b", re.I)
_K8S_PRIVESC_RE = re.compile(r"allowPrivilegeEscalation\s*:\s*true", re.I)
_K8S_LATEST_IMG_RE = re.compile(r'image\s*:\s*[\'"]?[^\s\'":]+:latest[\'"]?', re.I)
_K8S_NO_TAG_IMG_RE = re.compile(r'image\s*:\s*[\'"]?([^\s\'":@]+)[\'"]?\s*$', re.I | re.M)
_K8S_DEFAULT_NAMESPACE_RE = re.compile(r"namespace\s*:\s*default\b", re.I)
_K8S_CAP_SYS_ADMIN_RE = re.compile(r"SYS_ADMIN", re.I)


def check_kubernetes(path: str, content: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    rules = [
        (_K8S_PRIVILEGED_RE, "iac.k8s.privileged", "high", "Container runs in privileged mode",
         "privileged: true grants near-root access to the host kernel.",
         "Set privileged: false and grant only the specific Linux capabilities required.",
         "CIS K8s 5.2.5"),
        (_K8S_HOSTNETWORK_RE, "iac.k8s.host_network", "high", "Pod uses hostNetwork: true",
         "hostNetwork lets the pod listen on the host's network namespace, bypassing NetworkPolicy and exposing host services.",
         "Remove hostNetwork; expose services with a proper Service/Ingress.",
         "CIS K8s 5.2.4"),
        (_K8S_HOSTPID_RE, "iac.k8s.host_pid", "high", "Pod uses hostPID: true",
         "hostPID lets the container see the host's process tree, enabling cross-pod and host process inspection.",
         "Remove hostPID unless absolutely required (e.g., a node-debug DaemonSet).",
         "CIS K8s 5.2.2"),
        (_K8S_HOSTIPC_RE, "iac.k8s.host_ipc", "medium", "Pod uses hostIPC: true",
         "hostIPC shares the host's IPC namespace with the container.",
         "Remove hostIPC.", "CIS K8s 5.2.3"),
        (_K8S_RUNASROOT_RE, "iac.k8s.run_as_root", "high", "Container runs as UID 0 (root)",
         "runAsUser: 0 runs the container as root, breaking least-privilege.",
         "Set runAsUser to a non-zero UID and runAsNonRoot: true.",
         "CIS K8s 5.2.6"),
        (_K8S_PRIVESC_RE, "iac.k8s.priv_escalation", "high",
         "Container allows privilege escalation",
         "allowPrivilegeEscalation: true permits a process to gain more privileges than its parent.",
         "Set allowPrivilegeEscalation: false.",
         "CIS K8s 5.2.5"),
        (_K8S_DEFAULT_NAMESPACE_RE, "iac.k8s.default_ns", "low",
         "Resource deployed to the default namespace",
         "Workloads in 'default' inherit weaker default policies and complicate RBAC scoping.",
         "Use a purpose-named namespace and matching NetworkPolicy/RBAC.", ""),
        (_K8S_CAP_SYS_ADMIN_RE, "iac.k8s.cap_sys_admin", "high",
         "Container adds CAP_SYS_ADMIN",
         "CAP_SYS_ADMIN is effectively root inside the container — many container escapes start here.",
         "Drop SYS_ADMIN and add only the specific capabilities required.",
         "CIS K8s 5.2.8"),
        (_K8S_LATEST_IMG_RE, "iac.k8s.image_latest", "medium",
         "Container image uses :latest tag",
         "Image tag :latest is non-deterministic and breaks rollback.",
         "Pin to an immutable tag + digest.", ""),
    ]

    for regex, rid, sev, title, desc, remed, fw in rules:
        for m in regex.finditer(content):
            line = content[: m.start()].count("\n") + 1
            hits.append(RuleHit(
                rule_id=rid, severity=sev, title=title,
                description=desc, remediation=remed,
                evidence=f"{path}:{line} {m.group(0)[:120]}",
                line=line, framework=fw,
            ))

    # No resource limits — passive heuristic on the YAML body
    if "kind: Pod" in content or "kind: Deployment" in content or "kind: StatefulSet" in content:
        if "resources:" not in content or "limits:" not in content:
            hits.append(RuleHit(
                rule_id="iac.k8s.no_limits",
                severity="low",
                title="Workload missing resource limits",
                description=(
                    "Without resource limits, a noisy or compromised container can "
                    "exhaust node CPU/memory and impact co-tenants."
                ),
                remediation="Set resources.limits.{cpu, memory} and matching requests.",
                evidence=f"{path} (no resources.limits block found)",
                framework="CIS K8s 5.7",
            ))

    return hits


# ─── docker-compose ───────────────────────────────────────────────────────────

_DC_PRIVILEGED_RE = re.compile(r"privileged\s*:\s*true", re.I)
_DC_NETWORK_HOST_RE = re.compile(r"network_mode\s*:\s*[\'\"]?host[\'\"]?", re.I)
_DC_DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock", re.I)
_DC_LATEST_TAG_RE = re.compile(r'image\s*:\s*[\'"]?[^\s\'":]+:latest[\'"]?', re.I)


def check_compose(path: str, content: str) -> list[RuleHit]:
    hits: list[RuleHit] = []
    rules = [
        (_DC_PRIVILEGED_RE, "iac.compose.privileged", "high",
         "Compose service runs privileged",
         "privileged: true grants the container full host kernel access.",
         "Set privileged: false; grant specific cap_add only when required."),
        (_DC_NETWORK_HOST_RE, "iac.compose.host_network", "high",
         "Compose service uses host network mode",
         "network_mode: host bypasses Docker's network isolation.",
         "Use a bridge network and publish only the ports needed."),
        (_DC_DOCKER_SOCK_RE, "iac.compose.docker_sock", "critical",
         "Container mounts /var/run/docker.sock",
         "Mounting the Docker socket gives the container effective root on the host.",
         "Avoid mounting docker.sock. If management is required, run a dedicated host "
         "agent or use a rootless Docker proxy with restricted API access."),
        (_DC_LATEST_TAG_RE, "iac.compose.latest_tag", "medium",
         "Image uses :latest tag",
         "Non-deterministic image tag.",
         "Pin to a specific version tag and digest."),
    ]
    for regex, rid, sev, title, desc, remed in rules:
        for m in regex.finditer(content):
            line = content[: m.start()].count("\n") + 1
            hits.append(RuleHit(
                rule_id=rid, severity=sev, title=title,
                description=desc, remediation=remed,
                evidence=f"{path}:{line} {m.group(0)[:120]}",
                line=line,
            ))
    return hits


# ─── CloudFormation ───────────────────────────────────────────────────────────

def check_cloudformation(path: str, content: str) -> list[RuleHit]:
    hits: list[RuleHit] = []

    # Try to load as YAML or JSON; if both fail, fall back to regex sweeps
    parsed: dict | None = None
    try:
        if content.lstrip().startswith("{"):
            parsed = json.loads(content)
        else:
            try:
                import yaml  # type: ignore
                parsed = yaml.safe_load(content)
            except Exception:
                parsed = None
    except Exception:
        parsed = None

    if isinstance(parsed, dict) and "Resources" in parsed:
        resources = parsed.get("Resources") or {}
        for rname, r in (resources.items() if isinstance(resources, dict) else []):
            rtype = (r or {}).get("Type", "")
            props = (r or {}).get("Properties", {}) or {}

            if rtype == "AWS::S3::Bucket":
                acl = props.get("AccessControl") or props.get("AccessControlEnum")
                if acl in ("PublicRead", "PublicReadWrite"):
                    hits.append(RuleHit(
                        rule_id="iac.cfn.s3_public_acl",
                        severity="high",
                        title=f"S3 bucket '{rname}' uses public ACL ({acl})",
                        description="Public S3 buckets are a leading cause of cloud data leaks.",
                        remediation="Set AccessControl: Private and add a PublicAccessBlockConfiguration.",
                        evidence=f"{path} resource={rname} type={rtype} AccessControl={acl}",
                        framework="CIS AWS 2.1.5",
                    ))
                if not props.get("BucketEncryption"):
                    hits.append(RuleHit(
                        rule_id="iac.cfn.s3_no_encryption",
                        severity="medium",
                        title=f"S3 bucket '{rname}' lacks default encryption",
                        description="No BucketEncryption configured — objects may be stored unencrypted.",
                        remediation="Add BucketEncryption with SSE-KMS or SSE-S3.",
                        evidence=f"{path} resource={rname}",
                        framework="CIS AWS 2.1.1",
                    ))

            if rtype == "AWS::EC2::SecurityGroup":
                ingress = props.get("SecurityGroupIngress", []) or []
                if isinstance(ingress, list):
                    for rule in ingress:
                        cidr = (rule or {}).get("CidrIp", "")
                        if cidr in ("0.0.0.0/0", "::/0"):
                            hits.append(RuleHit(
                                rule_id="iac.cfn.sg_open_world",
                                severity="high",
                                title=f"Security group '{rname}' opens to the world",
                                description=f"Ingress rule allows {cidr}.",
                                remediation="Restrict CidrIp to specific allowed source ranges.",
                                evidence=f"{path} resource={rname} cidr={cidr}",
                                framework="CIS AWS 5.2",
                            ))

            if rtype == "AWS::RDS::DBInstance":
                if props.get("PubliclyAccessible") is True:
                    hits.append(RuleHit(
                        rule_id="iac.cfn.rds_public",
                        severity="high",
                        title=f"RDS instance '{rname}' is publicly accessible",
                        description="PubliclyAccessible: true exposes the database to the internet.",
                        remediation="Set PubliclyAccessible: false; place RDS in private subnets.",
                        evidence=f"{path} resource={rname}",
                        framework="CIS AWS 2.3.3",
                    ))
                if props.get("StorageEncrypted") is not True:
                    hits.append(RuleHit(
                        rule_id="iac.cfn.rds_no_encryption",
                        severity="medium",
                        title=f"RDS instance '{rname}' has storage encryption disabled",
                        description="StorageEncrypted is not true — RDS data at rest is unencrypted.",
                        remediation="Set StorageEncrypted: true and KmsKeyId to a CMK.",
                        evidence=f"{path} resource={rname}",
                        framework="CIS AWS 2.3.1",
                    ))

    return hits


# ─── Helm values.yaml ─────────────────────────────────────────────────────────

def check_helm_values(path: str, content: str) -> list[RuleHit]:
    """
    Helm values share many primitives with K8s manifests — we reuse the K8s
    checks since the same flags (privileged, hostNetwork, runAsUser, etc.)
    appear in chart values.
    """
    return check_kubernetes(path, content)


# ─── Dispatch table ───────────────────────────────────────────────────────────

CHECKS: dict[str, Callable[[str, str], list[RuleHit]]] = {
    "terraform": check_terraform,
    "dockerfile": check_dockerfile,
    "kubernetes": check_kubernetes,
    "compose": check_compose,
    "cloudformation": check_cloudformation,
    "helm_values": check_helm_values,
}
