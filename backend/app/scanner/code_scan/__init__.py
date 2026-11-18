"""
Source-code scanner — standalone orchestrator.

Standalone-only plugin (not registered in the engine plugin loader), invoked
from /scan/code/jobs via worker_tasks.run_scan_job when a scan job has
scan_type == "source_code".

Three tracks run over one ingested working tree:

  1. SCA (deterministic) — parse dependency manifests/lockfiles, match pinned
     versions against the OSV dataset. This is the "time bomb" track: it finds
     third-party dependencies with *known* CVEs, and re-running it on a
     schedule catches CVEs disclosed after the code last changed.

  2. Agentic source read — the configured AI provider reads the first-party
     source with read-only file tools (list/read/grep) and reports logic bugs,
     hardcoded secrets, injection, and auth flaws.

  3. Verification (adversarial) — SCA reachability check + a second AI agent
     that tries to DISPROVE each serious finding from tracks 1-2.  Adjusts
     confidence and severity in-place.

config shape (built by routes_code_scanner):
  {
    "source": {"type": "zip"|"git", "ref": "...", "filename": "...",
               "auth": {...} | null},
    "provider": "db:7" | "claude_cli" | ...,   # for the agentic track
    "tracks": ["sca", "agent"],                # which tracks to run
  }
"""
from __future__ import annotations

import logging
from typing import Any

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

from . import ingest

logger = logging.getLogger("vulnscan.code_scan.orchestrator")


class Check:
    """Source-code scanner — standalone orchestrator only."""

    async def run_standalone(
        self, config: dict, progress_callback=None, *, job_id: int | None = None,
        workspace_id: int | None = None,
    ) -> list[Finding]:
        source = config.get("source") or {}
        tracks = set(config.get("tracks") or ["sca", "agent", "verify"])

        all_findings: list[Finding] = []

        async def _progress(step, total, pid, label, status):
            if not progress_callback:
                return
            try:
                r = progress_callback(step, total, pid, label, status)
                if hasattr(r, "__await__"):
                    await r
            except Exception:
                pass

        total_steps = 5 if "verify" in tracks else 4

        # ── Ingest: resolve source → working tree → file inventory ──────────
        await _progress(1, total_steps, "code.ingest", "Preparing source tree", "running")
        # Re-resolve the credential (if any) in memory — the plaintext secret is
        # never stored in meta_json, only its credential_id.
        src = dict(source)
        cred_id = source.get("credential_id")
        if cred_id and workspace_id is not None:
            from . import credentials as _cred
            src["auth"] = _cred.resolve_auth(workspace_id, cred_id)
        try:
            tree = ingest.ingest_source(src, job_id=job_id)
        except ingest.CredentialRequired as e:
            all_findings.append(_blocked_finding(source, str(e), "credential_required"))
            return all_findings
        except ingest.CredentialRejected as e:
            all_findings.append(_blocked_finding(source, str(e), "credential_rejected"))
            return all_findings
        except ingest.IngestError as e:
            all_findings.append(_blocked_finding(source, str(e), "ingest_failed"))
            return all_findings

        all_findings.append(_coverage_finding(tree))
        await _progress(1, total_steps, "code.ingest", f"{len(tree.source_files)} source files", "done")

        # ── Track 1: SCA (deterministic) ────────────────────────────────────
        if "sca" in tracks and workspace_id is not None:
            await _progress(2, total_steps, "code.sca", "Dependency analysis (SCA)", "running")
            try:
                from . import sca
                all_findings += sca.run_sca(tree, workspace_id)
            except Exception as e:  # noqa: BLE001 — SCA must never sink the whole scan
                logger.warning("SCA track failed for job %s: %s", job_id, e)
                all_findings.append(Finding(
                    plugin_id="code.sca.error",
                    title="Dependency analysis (SCA) did not complete",
                    severity="info",
                    description=f"The SCA track raised an error and was skipped: {e}",
                    affected=tree.label,
                    fingerprint=stable_fingerprint(tree.label, "code.sca.error", 0),
                ))
            await _progress(2, total_steps, "code.sca", "Dependency analysis (SCA)", "done")

        # ── Track 2: agentic source read (Phase 2) ─────────────────────────
        if "agent" in tracks:
            await _progress(3, total_steps, "code.agent", "Agentic source review", "running")
            try:
                from . import agent_runner
                all_findings += await agent_runner.run_agent_scan(
                    tree, config, job_id=job_id, workspace_id=workspace_id,
                    progress=_progress,
                )
            except ImportError:
                logger.info("Agentic track not yet available; skipping")
            except Exception as e:  # noqa: BLE001
                logger.warning("Agentic track failed for job %s: %s", job_id, e)
                all_findings.append(Finding(
                    plugin_id="code.agent.error",
                    title="Agentic source review did not complete",
                    severity="info",
                    description=f"The agentic track raised an error and was skipped: {e}",
                    affected=tree.label,
                    fingerprint=stable_fingerprint(tree.label, "code.agent.error", 0),
                ))
            await _progress(3, total_steps, "code.agent", "Agentic source review", "done")

        # ── Track 3: verification (adversarial sub-agent) ─────────────────
        if "verify" in tracks:
            await _progress(4, total_steps, "code.verify", "Adversarial verification", "running")
            try:
                from . import verify_runner
                verify_findings = await verify_runner.run_verification(
                    tree, all_findings, config,
                    job_id=job_id, workspace_id=workspace_id,
                    progress=_progress,
                )
                all_findings += verify_findings
            except Exception as e:  # noqa: BLE001
                logger.warning("Verify track failed for job %s: %s", job_id, e)
                all_findings.append(Finding(
                    plugin_id="code.verify.error",
                    title="Adversarial verification did not complete",
                    severity="info",
                    description=f"The verification track raised an error and was skipped: {e}",
                    affected=tree.label,
                    fingerprint=stable_fingerprint(tree.label, "code.verify.error", 0),
                ))
            await _progress(4, total_steps, "code.verify", "Adversarial verification", "done")

        await _progress(total_steps, total_steps, "code.done", "Scan complete", "done")
        return all_findings

    async def run(self, target: str, ctx: Any) -> Any:
        """Engine-mode placeholder — the code scanner is upload/git-driven and
        never runs inside scan_target()."""
        from app.scanner.plugins.base import PluginResult
        return PluginResult(findings=[], artifacts={})


def _blocked_finding(source: dict, message: str, reason: str) -> Finding:
    label = source.get("ref") or source.get("filename") or "source"
    remediation = {
        "credential_required": (
            "This repository is private. Add or select a credential from the "
            "vault (a personal access token for HTTPS, or an SSH deploy key) "
            "and run the scan again."
        ),
        "credential_rejected": (
            "The remote refused the supplied credential. Check the token/key is "
            "valid, not expired, and has read access to this repository."
        ),
        "ingest_failed": (
            "Could not prepare the source tree. Check the URL/upload is reachable "
            "and is a valid repository or archive."
        ),
    }.get(reason, "")
    return Finding(
        plugin_id="policy.code_scan_blocked",
        title=f"Code scan could not start: {message}",
        severity="info",
        description=(
            "The scan was stopped cleanly before any analysis because the source "
            "could not be prepared. No partial results were produced."
        ),
        remediation=remediation,
        evidence=f"reason={reason}\nsource={label}",
        affected=str(label),
        fingerprint=stable_fingerprint(str(label), f"code_scan_blocked.{reason}", 0),
    )


def _coverage_finding(tree: "ingest.SourceTree") -> Finding:
    skipped = tree.skipped
    by_reason: dict[str, int] = {}
    for _path, reason in skipped:
        by_reason[reason] = by_reason.get(reason, 0) + 1

    sample = "\n".join(f"  {p}  [{r}]" for p, r in skipped[:200])
    summary = "\n".join(f"  {reason:22s} {count} file(s)"
                        for reason, count in sorted(by_reason.items()))

    return Finding(
        plugin_id="policy.code_scan_coverage",
        title=(
            f"Code scan coverage: {len(tree.source_files)} source files read, "
            f"{len(tree.manifest_files)} manifest(s) analysed, {len(skipped)} path(s) skipped"
        ),
        severity="info",
        description=(
            "Full-coverage inventory of the ingested tree. Every file is treated "
            "as source (and read) unless it is provably non-source — a binary, "
            "media file, vendored dependency, VCS metadata, or a minified/generated "
            "bundle. Nothing is dropped silently: the skip list below records each "
            "excluded path and why. If a skipped path should have been scanned, "
            "it can be opted in and the scan re-run.\n\n"
            f"Skipped by reason:\n{summary or '  (nothing skipped)'}"
        ),
        evidence=(
            f"root={tree.root}\n"
            f"source_files={len(tree.source_files)} manifests={len(tree.manifest_files)} "
            f"skipped={len(skipped)} truncated_to_first_200={len(skipped) > 200}\n\n"
            f"{sample}"
        ),
        remediation=(
            "This is an inventory, not a vulnerability. Review the skipped paths "
            "if you expected broader coverage; minified bundles and vendored "
            "dependencies are intentionally excluded (dependencies are covered by "
            "the SCA track via their lockfiles instead)."
        ),
        affected=tree.label,
        fingerprint=stable_fingerprint(tree.label, "code_scan_coverage", len(tree.source_files)),
    )
