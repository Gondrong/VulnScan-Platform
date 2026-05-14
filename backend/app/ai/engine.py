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
    """Update the progress_json field and commit."""
    analysis.progress_json = json.dumps(progress)
    db.commit()


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


def _validate_result(result: dict, mode: str) -> dict:
    """Validate and normalize the AI result structure."""
    # Ensure required keys exist
    if mode == "validate":
        result.setdefault("finding_validations", {})
    elif mode in ("full", "full_exploit"):
        result.setdefault("executive_summary", "Analysis completed.")
        result.setdefault("attack_chains", [])
        result.setdefault("finding_validations", {})
        result.setdefault("remediation_priority", [])
    if mode == "full_exploit":
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
    try:
        analysis = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.id == analysis_id
        ).first()
        if not analysis:
            logger.error("AiAnalysis #%d not found", analysis_id)
            return

        analysis.status = "running"
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

        # Build prompts
        system_prompt, user_prompt = build_prompt(
            mode=analysis.mode,
            findings=findings_data,
            target=target,
        )

        _update_progress(db, analysis, {
            "pct": 20,
            "step": f"Sending to {analysis.provider}...",
        })

        # Call AI provider
        provider = get_provider(analysis.provider, workspace_id=analysis.workspace_id)
        start_time = time.time()
        response = provider.generate(system_prompt, user_prompt)
        duration = time.time() - start_time

        _update_progress(db, analysis, {
            "pct": 80,
            "step": "Parsing response...",
        })

        # Parse response
        logger.debug(
            "AI raw response (analysis #%d, len=%d): %.500s",
            analysis_id, len(response.content), response.content,
        )
        result = _extract_json(response.content)
        result = _validate_result(result, analysis.mode)

        # Store results
        analysis.result_json = json.dumps(result)
        analysis.token_usage = response.tokens_used
        analysis.duration_seconds = round(duration, 2)
        analysis.status = "done"
        analysis.finished_at = datetime.now(timezone.utc)
        _update_progress(db, analysis, {"pct": 100, "step": "Complete"})
        db.commit()

        logger.info(
            "AI analysis #%d complete: provider=%s mode=%s tokens=%d duration=%.1fs findings=%d",
            analysis_id, analysis.provider, analysis.mode,
            response.tokens_used, duration, len(findings),
        )

    except Exception as e:
        logger.exception("AI analysis #%d failed: %s", analysis_id, e)
        try:
            analysis.status = "failed"
            analysis.error = str(e)[:2000]
            analysis.finished_at = datetime.now(timezone.utc)
            db.commit()
        except Exception:
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

