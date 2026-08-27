"""
AI Analysis Engine — orchestrates the analysis pipeline.
Loads findings, builds prompts, calls AI provider, parses/stores results.
"""
import json
import logging
import re
import time
from datetime import datetime, timezone

from app.db.session import SessionLocal
from app.db import models
from app.ai.providers import get_provider
from app.ai.prompts import build_prompt, build_poc_prompt

logger = logging.getLogger("vulnscan.ai.engine")


def _update_progress(db, analysis: models.AiAnalysis, progress: dict) -> None:
    """Update the progress_json field and commit.

    Also logs the step. The DB write is the only progress signal the UI gets,
    so if this commit ever blocks on a lock the analysis goes completely silent
    — the log line is what makes such a stall visible.
    """
    logger.info("AI analysis #%s progress: %s%% %s",
                analysis.id, progress.get("pct"), progress.get("step"))
    analysis.progress_json = json.dumps(progress)
    db.commit()


def _finalize_job_after_ai(db, job_id: int) -> None:
    """If the scan job is in 'analyzing' state, move it back to 'done'.

    Only transitions if no other AI analyses are still queued/running
    for this job (in case multiple analyses were triggered).
    """
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job or job.status != "analyzing":
            return
        # Check if any other analysis for this job is still pending
        still_running = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.job_id == job_id,
            models.AiAnalysis.status.in_(["queued", "running"]),
        ).count()
        if still_running == 0:
            job.status = "done"
            db.commit()
            logger.info("Job #%d status: analyzing -> done (AI complete)", job_id)
    except Exception as e:
        logger.warning("Failed to finalize job #%d after AI: %s", job_id, e)


def _serialize_finding_from_db(f: models.Finding) -> dict:
    """Convert a DB Finding model to a dict for prompt building."""
    return {
        "id": f.id,
        "title": f.title or "",
        "severity": f.severity or "info",
        "description": f.description or "",
        "evidence": f.evidence or "",
        "plugin_id": f.plugin_id or "",
        "cvss_base": f.cvss_base,
        "risk_score": f.risk_score,
        "confidence": f.confidence,
        "remediation": f.remediation or "",
        "is_kev": f.is_kev if hasattr(f, "is_kev") else False,
    }


def _extract_json(text: str) -> dict:
    """
    Parse JSON from AI response. Handles:
    1. Direct JSON
    2. JSON wrapped in markdown code blocks
    3. JSON embedded in surrounding prose text
    4. Model refusals / non-JSON responses (returns fallback dict)
    """
    # Try direct parse
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code blocks
    block_patterns = [
        r"```json\s*\n([\s\S]*?)\n```",
        r"```\s*\n([\s\S]*?)\n```",
    ]
    for pattern in block_patterns:
        match = re.search(pattern, text)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                continue

    # Try to find a JSON object in the text — scan for outermost { ... }
    # by finding each '{' and attempting to parse from there
    for m in re.finditer(r"\{", text):
        candidate = text[m.start():]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            # Try trimming trailing junk after the last '}'
            last_brace = candidate.rfind("}")
            if last_brace > 0:
                try:
                    return json.loads(candidate[: last_brace + 1])
                except json.JSONDecodeError:
                    continue
                    
    # No valid JSON found — return a fallback with the raw text as summary
    # so the analysis doesn't crash and the user sees the AI's response.
    logger.warning(
        "AI response contained no valid JSON (length=%d), using fallback. Preview: %.300s",
        len(text), text,
    )
    return {
        "executive_summary": text[:2000],
        "_parse_warning": "AI response was not valid JSON — raw text preserved as executive_summary",
    }


# Two-stage mode: run `validate` first, then `full_exploit` on only the findings
# that survived. Cheaper than full_exploit over everything, and more accurate —
# attack chains and PoCs no longer get built on top of false positives.
TWO_STAGE_MODE = "validate_then_exploit"

# Verdicts that graduate from stage 1 into stage 2. Only findings the model
# actively refuted are dropped; "needs_manual" ones are exactly the cases that
# benefit most from a deeper look, so they go through.
STAGE2_VERDICTS = {"true_positive", "needs_manual"}


def _run_two_stage(db, analysis, provider, findings_data: list[dict],
                   target: str) -> tuple[dict, int]:
    """Run validate → filter → full_exploit. Returns (result, tokens_used)."""
    total = len(findings_data)

    # ── Stage 1: validate everything ────────────────────────────────────
    _update_progress(db, analysis, {
        "pct": 25,
        "step": f"Stage 1/2 — validating {total} findings...",
    })
    sys1, usr1 = build_prompt(mode="validate", findings=findings_data, target=target)
    resp1 = provider.generate(sys1, usr1)
    stage1 = _validate_result(_extract_json(resp1.content), "validate")
    validations = stage1.get("finding_validations") or {}

    # A stage-1 response we could not parse leaves `validations` empty, which
    # defaults every finding to "needs_manual" — i.e. it degrades to a plain
    # full_exploit run rather than silently dropping findings.
    kept = [
        f for f in findings_data
        if str((validations.get(str(f["id"])) or {}).get("verdict", "needs_manual"))
        in STAGE2_VERDICTS
    ]
    dropped = total - len(kept)
    logger.info(
        "AI analysis #%d stage 1: %d findings validated, %d promoted, %d refuted",
        analysis.id, total, len(kept), dropped,
    )

    # `total` is how many findings were *submitted*, not how many the model
    # actually saw: build_prompt truncates to MAX_FULL_DETAIL + MAX_SUMMARY.
    # Report both, otherwise this metadata overstates coverage — a 100-finding
    # scan submits 100 but only 80 ever reach the prompt, and the remaining 20
    # are promoted purely by the "needs_manual" default.
    stage_meta = {
        "validated": total,
        "verdicts_returned": len(validations),
        "not_assessed": max(0, total - len(validations)),
        "promoted": len(kept),
        "skipped_false_positive": dropped,
    }

    # ── Everything refuted: no point paying for stage 2 ─────────────────
    if not kept:
        result = dict(stage1)
        result["executive_summary"] = (
            f"All {total} findings were classified as false positives during "
            f"validation, so no exploit analysis was performed."
        )
        result.setdefault("attack_chains", [])
        result.setdefault("remediation_priority", [])
        result.setdefault("poc_results", {})
        result["_two_stage"] = stage_meta
        return result, resp1.tokens_used

    # ── Stage 2: deep analysis on survivors only ────────────────────────
    _update_progress(db, analysis, {
        "pct": 60,
        "step": (
            f"Stage 2/2 — exploit analysis on {len(kept)} confirmed "
            f"({dropped} false positives skipped)..."
        ),
    })
    sys2, usr2 = build_prompt(mode="full_exploit", findings=kept, target=target)
    resp2 = provider.generate(sys2, usr2)
    stage2 = _validate_result(_extract_json(resp2.content), "full_exploit")

    # Merge: stage 2 drives the output, but stage 1's verdicts are kept for
    # *every* finding so the UI can still explain what was dropped and why.
    result = dict(stage2)
    result["finding_validations"] = {
        **validations,
        **(stage2.get("finding_validations") or {}),
    }
    result["_two_stage"] = stage_meta
    return result, resp1.tokens_used + resp2.tokens_used


def _validate_result(result: dict, mode: str) -> dict:
    """Validate and normalize the AI result structure."""
    # Ensure required keys exist
    if mode == "validate":
        result.setdefault("finding_validations", {})
    elif mode in ("full", "full_exploit", TWO_STAGE_MODE):
        result.setdefault("executive_summary", "Analysis completed.")
        result.setdefault("attack_chains", [])
        result.setdefault("finding_validations", {})
        result.setdefault("remediation_priority", [])
    if mode in ("full_exploit", TWO_STAGE_MODE):
        result.setdefault("poc_results", {})

    # Normalize finding_validations keys to strings
    if "finding_validations" in result:
        normalized = {}
        for k, v in result["finding_validations"].items():
            normalized[str(k)] = v
            # Ensure verdict field
            if isinstance(v, dict):
                v.setdefault("verdict", "needs_manual")
                v.setdefault("reasoning", "")
                v.setdefault("confidence", 0.5)
        result["finding_validations"] = normalized

    return result


# ─────────────────────────────────────────────────────────────────────────
# Main analysis task (called by RQ worker)
# ─────────────────────────────────────────────────────────────────────────

def run_analysis(analysis_id: int) -> None:
    """
    RQ task entry point — runs AI analysis on scan findings.
    """
    db = SessionLocal()
    analysis = None
    try:
        analysis = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.id == analysis_id
        ).first()
        if not analysis:
            logger.error("AiAnalysis #%d not found", analysis_id)
            return

        analysis.status = "running"
        # Stamp the moment a worker actually picks this up — the stale-analysis
        # watchdog measures its timeout from here, not from created_at.
        analysis.started_at = datetime.now(timezone.utc)
        _update_progress(db, analysis, {"pct": 5, "step": "Loading findings..."})

        # Load findings
        findings = db.query(models.Finding).filter(
            models.Finding.job_id == analysis.job_id,
        ).all()

        if not findings:
            analysis.status = "failed"
            analysis.error = "No findings to analyze"
            analysis.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        # Load job info for target
        job = db.query(models.ScanJob).filter(
            models.ScanJob.id == analysis.job_id
        ).first()
        target = job.target if job else "unknown"

        _update_progress(db, analysis, {
            "pct": 10,
            "step": f"Preparing {len(findings)} findings for analysis...",
        })

        # Serialize findings
        findings_data = [_serialize_finding_from_db(f) for f in findings]

        provider = get_provider(analysis.provider, workspace_id=analysis.workspace_id)
        start_time = time.time()

        if analysis.mode == TWO_STAGE_MODE:
            result, tokens_used = _run_two_stage(
                db, analysis, provider, findings_data, target,
            )
            _update_progress(db, analysis, {"pct": 90, "step": "Storing results..."})
        else:
            system_prompt, user_prompt = build_prompt(
                mode=analysis.mode,
                findings=findings_data,
                target=target,
            )

            _update_progress(db, analysis, {
                "pct": 20,
                "step": f"Sending to {analysis.provider}...",
            })

            response = provider.generate(system_prompt, user_prompt)

            _update_progress(db, analysis, {
                "pct": 80,
                "step": "Parsing response...",
            })

            logger.debug(
                "AI raw response (analysis #%d, len=%d): %.500s",
                analysis_id, len(response.content), response.content,
            )
            result = _validate_result(_extract_json(response.content), analysis.mode)
            tokens_used = response.tokens_used

        duration = time.time() - start_time

        # Store results
        analysis.result_json = json.dumps(result)
        analysis.token_usage = tokens_used
        analysis.duration_seconds = round(duration, 2)
        analysis.status = "done"
        analysis.finished_at = datetime.now(timezone.utc)
        _update_progress(db, analysis, {"pct": 100, "step": "Complete"})
        db.commit()

        # If scan job is in "analyzing" state, move it to "done"
        _finalize_job_after_ai(db, analysis.job_id)

        logger.info(
            "AI analysis #%d complete: provider=%s mode=%s tokens=%d duration=%.1fs findings=%d",
            analysis_id, analysis.provider, analysis.mode,
            tokens_used, duration, len(findings),
        )

    except Exception as e:
        logger.exception("AI analysis #%d failed: %s", analysis_id, e)
        # Record the failure so it shows up in the UI. Two things made the
        # naive version of this silently do nothing:
        #   * the failure may happen *before* `analysis` is loaded, so touching
        #     it raises UnboundLocalError inside the handler;
        #   * a DB-level error leaves the session in a failed transaction, so
        #     the commit fails too.
        # Either way the row stayed "queued" with no error, and the stale
        # watchdog later mislabelled it as a 15-minute timeout — which is why
        # these failures were undebuggable.
        try:
            db.rollback()
            if analysis is None:
                analysis = db.query(models.AiAnalysis).filter(
                    models.AiAnalysis.id == analysis_id
                ).first()
            if analysis is None:
                logger.error(
                    "AI analysis #%d failed and the row could not be loaded to "
                    "record the error", analysis_id,
                )
            else:
                analysis.status = "failed"
                analysis.error = str(e)[:2000]
                analysis.finished_at = datetime.now(timezone.utc)
                db.commit()
                # Also finalize job on failure so it doesn't stay stuck in "analyzing"
                _finalize_job_after_ai(db, analysis.job_id)
        except Exception:
            logger.exception(
                "AI analysis #%d: could not persist the failure state", analysis_id,
            )
            db.rollback()
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────
# Per-finding PoC generation (called by RQ worker)
# ─────────────────────────────────────────────────────────────────────────

def generate_poc(analysis_id: int, finding_id: int) -> None:
    """
    RQ task — generates a PoC for a single finding and appends to result_json.
    """
    db = SessionLocal()
    try:
        analysis = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.id == analysis_id
        ).first()
        if not analysis:
            logger.error("AiAnalysis #%d not found for PoC", analysis_id)
            return

        finding = db.query(models.Finding).filter(
            models.Finding.id == finding_id,
        ).first()
        if not finding:
            logger.error("Finding #%d not found for PoC", finding_id)
            return

        job = db.query(models.ScanJob).filter(
            models.ScanJob.id == analysis.job_id
        ).first()
        target = job.target if job else "unknown"

        # Build PoC prompt
        finding_data = _serialize_finding_from_db(finding)
        system_prompt, user_prompt = build_poc_prompt(finding_data, target)

        # Call provider
        provider = get_provider(analysis.provider, workspace_id=analysis.workspace_id)
        response = provider.generate(system_prompt, user_prompt, max_tokens=4096)

        # Parse response
        poc_result = _extract_json(response.content)

        # Merge into existing result_json
        existing = json.loads(analysis.result_json or "{}")
        existing.setdefault("poc_results", {})
        existing["poc_results"][str(finding_id)] = poc_result

        analysis.result_json = json.dumps(existing)
        analysis.token_usage = (analysis.token_usage or 0) + response.tokens_used
        db.commit()

        logger.info(
            "PoC generated for finding #%d (analysis #%d, tokens=%d)",
            finding_id, analysis_id, response.tokens_used,
        )

    except Exception as e:
        logger.exception("PoC generation failed for finding #%d: %s", finding_id, e)
    finally:
        db.close()

