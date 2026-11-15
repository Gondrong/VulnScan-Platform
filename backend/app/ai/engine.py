"""
AI Analysis Engine — orchestrates the analysis pipeline.
Loads findings, builds prompts, calls AI provider, parses/stores results.
"""
import json
import logging
import os
import re
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone

from app.core.config import settings
from app.db.session import SessionLocal
from app.db import models
from app.ai.providers import (
    EmptyResponseError, ProviderUnavailableError, TurnLimitError, get_provider,
)
from app.ai.prompts import build_investigate_prompt, build_prompt, build_poc_prompt

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


# Findings that make no vulnerability claim — a check that did not run, a
# passing check, a scanner summary — get their verdict from these rules rather
# than from the model. Asked "true or false positive?" about "testssl.sh: no TLS
# issues detected", models answered differently on repeated runs of the same
# scan: 13 of the 26 verdicts that flipped across three re-run pairs were
# findings like these, and the prompt-level rules for them (c41b88e) did not
# stop it. A rule gives the same answer every run, at no cost.
_DID_NOT_RUN = re.compile(r"\b(timed out|timeout|failed|failure|skipped|requires root|unreachable)\b", re.I)
_CHECK_SUMMARY = re.compile(r"\b\d+/\d+ checks passed\b", re.I)
# Narrow on purpose: passing CIS checks routinely carry harmless stderr such as
# "command not found: rpm" (the rpm fallback on Debian) or "No such file" (the
# file the check wants absent is absent). Only these mean the check could not
# read what it was checking.
_UNREADABLE = re.compile(r"permission denied|operation not permitted", re.I)


def _rule_verdict(f: dict) -> dict | None:
    """Verdict for a finding that makes no vulnerability claim, else None.

    `confidence` is None, not a number: the verdict comes from a rule, and the
    UI and reports only show a percentage when one is present.
    """
    title = f["title"].strip()
    if title.startswith("SKIP:") or (f["severity"] == "info" and _DID_NOT_RUN.search(title)):
        return {"verdict": "needs_manual", "confidence": None, "rule": "did_not_run",
                "reasoning": "The check did not run to completion, so it confirms nothing either way."}
    if title.startswith("PASS:"):
        out = f["evidence"].strip()
        if not out or _UNREADABLE.search(out):
            return {"verdict": "needs_manual", "confidence": None, "rule": "pass_unverified",
                    "reasoning": "Reported as passing, but the output is empty or shows the check "
                                 "could not read what it was checking."}
        return {"verdict": "true_positive", "confidence": None, "rule": "pass",
                "reasoning": "Passing check; the output shows the compliant state."}
    if f["severity"] == "info" or _CHECK_SUMMARY.search(title):
        return {"verdict": "true_positive", "confidence": None, "rule": "observation",
                "reasoning": "Scanner summary or inventory: it records what the tool observed "
                             "and makes no vulnerability claim."}
    return None


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


# ── Batched analysis ──────────────────────────────────────────────────────
# build_prompt() truncates: the first MAX_FULL_DETAIL findings are sent with
# full detail, the next MAX_SUMMARY as title-only summaries, and anything past
# that is dropped. On a 100-finding scan that means 50 findings get judged on
# their title alone and 20 are never seen at all. Sending findings in batches of
# MAX_FULL_DETAIL keeps every finding at full detail and loses none.

# Per-finding maps are merged; cross-finding narratives are concatenated.
_MERGE_DICT_KEYS = ("finding_validations", "poc_results")
_MERGE_LIST_KEYS = ("attack_chains", "remediation_priority")


def _merge_result(dst: dict, src: dict) -> None:
    """Fold one batch's result into the accumulated result."""
    for k in _MERGE_DICT_KEYS:
        if isinstance(src.get(k), dict) and src[k]:
            dst.setdefault(k, {}).update(src[k])
    for k in _MERGE_LIST_KEYS:
        if isinstance(src.get(k), list) and src[k]:
            dst.setdefault(k, []).extend(src[k])
    summary = (src.get("executive_summary") or "").strip()
    if summary:
        prev = (dst.get("executive_summary") or "").strip()
        dst["executive_summary"] = f"{prev}\n\n{summary}" if prev else summary


def _run_batched(db, analysis, provider, mode: str, findings_data: list[dict],
                 target: str, pct_from: int, pct_to: int,
                 deadline: float | None, label: str) -> tuple[dict, int, int]:
    """Run `mode` over every finding, in batches. Returns (result, tokens, assessed)."""
    size = max(1, settings.AI_BATCH_SIZE)
    batches = [findings_data[i:i + size] for i in range(0, len(findings_data), size)]
    merged: dict = {}
    tokens = 0
    assessed = 0
    failed: list[dict] = []
    stats: list[dict] = []

    for i, batch in enumerate(batches):
        # Never start a call that cannot finish inside the job budget — being
        # SIGKILLed by RQ mid-call loses everything collected so far.
        if deadline is not None and time.monotonic() + settings.AI_CLI_TIMEOUT > deadline:
            logger.warning(
                "AI analysis #%s: stopping %s after %d/%d batches — not enough "
                "budget left for another call", analysis.id, label, i, len(batches),
            )
            break

        pct = pct_from + (pct_to - pct_from) * i // max(1, len(batches))
        _update_progress(db, analysis, {
            "pct": pct,
            "step": f"{label} — batch {i + 1}/{len(batches)} ({len(batch)} findings)...",
        })
        prompts = build_prompt(mode=mode, findings=batch, target=target)
        resp = None
        for attempt in (1, 2):
            try:
                resp = provider.generate(*prompts, max_tokens=settings.AI_MAX_TOKENS)
                break
            except EmptyResponseError as e:
                # The tokens were billed even though nothing came back.
                tokens += e.tokens_used
                # finish_reason=length means the budget ran out; the same call
                # again would just burn the same budget, so only retry the
                # other cases (transient provider hiccups).
                retry = attempt == 1 and e.finish_reason != "length"
                logger.warning(
                    "AI analysis #%s: %s batch %d/%d empty response (attempt %d%s): %s",
                    analysis.id, label, i + 1, len(batches), attempt,
                    ", retrying" if retry else "", e,
                )
                if not retry:
                    failed.append({
                        "batch": i + 1,
                        "findings": len(batch),
                        "finding_ids": [f["id"] for f in batch],
                        "finish_reason": e.finish_reason,
                        "error": str(e)[:300],
                    })
                    break
        if resp is None:
            continue
        stats.append({"batch": i + 1, "findings": len(batch), **(resp.meta or {})})
        _merge_result(merged, _validate_result(_extract_json(resp.content), mode))
        tokens += resp.tokens_used
        assessed += len(batch)

    # Every batch empty: fail loudly rather than report a clean-looking result
    # (in two-stage mode, "0 refuted, all promoted") that the model never produced.
    if batches and len(failed) == len(batches):
        raise RuntimeError(
            f"{label}: all {len(batches)} batches returned an empty response "
            f"(finish_reasons: {sorted({str(f['finish_reason']) for f in failed})}). "
            f"First error: {failed[0]['error']}"
        )
    result = _validate_result(merged, mode)
    result["_failed_batches"] = failed
    result["_batch_stats"] = stats
    return result, tokens, assessed


# Two-stage mode: run `validate` first, then `full_exploit` on only the findings
# that survived. Cheaper than full_exploit over everything, and more accurate —
# attack chains and PoCs no longer get built on top of false positives.
TWO_STAGE_MODE = "validate_then_exploit"

# Verdicts that graduate from stage 1 into stage 2. Only findings the model
# actively refuted are dropped; "needs_manual" ones are exactly the cases that
# benefit most from a deeper look, so they go through.
STAGE2_VERDICTS = {"true_positive", "needs_manual"}


def _run_two_stage(db, analysis, provider, findings_data: list[dict],
                   target: str, deadline: float | None = None) -> tuple[dict, int]:
    """Run validate → filter → full_exploit. Returns (result, tokens_used)."""
    total = len(findings_data)

    # ── Stage 1: validate everything ────────────────────────────────────
    stage1, tokens1, assessed1 = _run_batched(
        db, analysis, provider, "validate", findings_data, target,
        pct_from=10, pct_to=50, deadline=deadline,
        label=f"Stage 1/2 — validating {total} findings",
    )
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
    # Findings with no stage-1 verdict are still promoted (never silently
    # dropped), but listed here so they are not mistaken for "needs_manual".
    not_assessed_ids = [f["id"] for f in findings_data if str(f["id"]) not in validations]
    stage_meta = {
        "validated": total,
        "submitted_to_model": assessed1,
        "verdicts_returned": len(validations),
        "not_assessed": len(not_assessed_ids),
        "not_assessed_ids": not_assessed_ids,
        "promoted": len(kept),
        "skipped_false_positive": dropped,
        "batch_size": settings.AI_BATCH_SIZE,
        "max_tokens": settings.AI_MAX_TOKENS,
        "stage1_failed_batches": stage1.pop("_failed_batches", []),
        "stage1_batches": stage1.pop("_batch_stats", []),
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
        return result, tokens1

    # ── Stage 2: deep analysis on survivors only ────────────────────────
    stage2, tokens2, assessed2 = _run_batched(
        db, analysis, provider, "full_exploit", kept, target,
        pct_from=55, pct_to=90, deadline=deadline,
        label=(
            f"Stage 2/2 — exploit analysis on {len(kept)} confirmed "
            f"({dropped} false positives skipped)"
        ),
    )
    stage_meta["deep_analysed"] = assessed2
    stage_meta["stage2_failed_batches"] = stage2.pop("_failed_batches", [])
    stage_meta["stage2_batches"] = stage2.pop("_batch_stats", [])

    # Merge: stage 2 drives the output, but stage 1's verdicts are kept for
    # *every* finding so the UI can still explain what was dropped and why.
    result = dict(stage2)
    result["finding_validations"] = {
        **validations,
        **(stage2.get("finding_validations") or {}),
    }
    result["_two_stage"] = stage_meta
    return result, tokens1 + tokens2


# Investigate mode: batch validation (phase A), then one agentic session per
# finding the batch left in doubt (phase B), using the read-only tools in
# ai/tools.py. Findings the batch settled keep their batch verdict.
INVESTIGATE_MODE = "investigate"

_VERDICTS = {"true_positive", "false_positive", "needs_manual"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _read_trail(path: str) -> list[dict]:
    steps = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    steps.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return steps


def _run_investigate(db, analysis, provider, findings_data: list[dict],
                     target: str, deadline: float) -> tuple[dict, int]:
    # Plain values only from here on. After a commit, reading an attribute of
    # `analysis` re-opens a transaction, and one opened just before a
    # ten-minute CLI session would sit idle-in-transaction throughout it.
    aid, ws_id, job_id = analysis.id, analysis.workspace_id, analysis.job_id
    runs = settings.AI_INVESTIGATE_PHASE_A_RUNS
    tokens = 0

    # ── Phase A: batch validation ──────────────────────────────────────
    passes: list[dict] = []
    phase_a_meta: list[dict] = []
    span = 35 // runs
    for r in range(runs):
        res, tok, _assessed = _run_batched(
            db, analysis, provider, "validate", findings_data, target,
            pct_from=10 + r * span, pct_to=10 + (r + 1) * span, deadline=deadline,
            label=f"Phase A — batch validation {r + 1}/{runs}",
        )
        tokens += tok
        passes.append(res.get("finding_validations") or {})
        phase_a_meta.append({"failed_batches": res.pop("_failed_batches", []),
                             "batches": res.pop("_batch_stats", [])})

    # ── Queue: whatever phase A left in doubt ──────────────────────────
    by_id = {str(f["id"]): f for f in findings_data}
    queue: list[tuple[dict, list[str]]] = []
    for fid, f in by_id.items():
        verdicts = [p.get(fid, {}).get("verdict") for p in passes]
        why = []
        if None in verdicts:
            why.append("not_assessed")
        if len({v for v in verdicts if v}) > 1:
            why.append("disagreement")
        if "needs_manual" in verdicts:
            why.append("needs_manual")
        if "false_positive" in verdicts:
            why.append("false_positive")
        if why:
            queue.append((f, why))
    queue.sort(key=lambda item: (not item[0].get("is_kev"),
                                 _SEV_RANK.get(item[0].get("severity"), 5),
                                 "disagreement" not in item[1]))
    cap = settings.AI_INVESTIGATE_MAX_FINDINGS
    overflow = queue[cap:]
    queue = queue[:cap]

    final = {fid: dict(passes[0].get(fid) or passes[-1].get(fid) or {}) for fid in by_id}
    stopped: dict[str, str] = {str(f["id"]): "over_cap" for f, _ in overflow}
    sessions: dict[str, dict] = {}
    aborted = None

    if not provider.supports_tools:
        aborted = f"provider {getattr(provider, 'name', '?')} has no tool support"
        stopped.update({str(f["id"]): "no_tool_support" for f, _ in queue})
        queue = []

    # ── Phase B: one agentic session per queued finding ────────────────
    for i, (f, why) in enumerate(queue):
        fid = str(f["id"])
        if aborted:
            stopped[fid] = "aborted"
            continue
        if time.monotonic() + settings.AI_CLI_TIMEOUT > deadline:
            stopped[fid] = "budget"
            continue
        _update_progress(db, analysis, {
            "pct": 45 + 43 * i // max(1, len(queue)),
            "step": f"Phase B — investigating {i + 1}/{len(queue)} (finding #{fid})...",
        })
        prior = [p[fid] for p in passes if isinstance(p.get(fid), dict)]
        prompts = build_investigate_prompt(f, target, prior)
        fd, trail = tempfile.mkstemp(prefix="vs-trail-", suffix=".jsonl")
        os.close(fd)
        t0 = time.monotonic()
        try:
            resp = provider.investigate(
                *prompts, workspace_id=ws_id, job_id=job_id, trail_path=trail,
                max_turns=settings.AI_INVESTIGATE_MAX_TURNS,
            )
            tokens += resp.tokens_used
            out = _extract_json(resp.content)
            verdict = out.get("verdict")
            if verdict not in _VERDICTS:
                stopped[fid] = "unparseable"
            else:
                entry = {"verdict": verdict, "confidence": out.get("confidence"),
                         "reasoning": out.get("reasoning") or ""}
                if out.get("adjusted_severity"):
                    entry["adjusted_severity"] = out["adjusted_severity"]
                final[fid] = entry
                stopped[fid] = "verdict"
            sessions[fid] = {"turns": (resp.meta or {}).get("turns"),
                             "cost_usd": (resp.meta or {}).get("cost_usd")}
        except ProviderUnavailableError as e:
            # Expired login, or a model without tool calls: every later
            # session would fail the same way, slowly.
            aborted = str(e)
            stopped[fid] = "aborted"
            logger.warning("AI analysis #%s: investigation aborted: %s", aid, e)
        except TurnLimitError:
            stopped[fid] = "max_turns"
        except Exception as e:
            stopped[fid] = "error"
            sessions[fid] = {"error": str(e)[:300]}
            logger.warning("AI analysis #%s: investigating finding #%s failed: %s", aid, fid, e)
        finally:
            sessions.setdefault(fid, {})["duration_s"] = round(time.monotonic() - t0, 1)
            sessions[fid]["steps"] = _read_trail(trail)
            try:
                os.unlink(trail)
            except OSError:
                pass

    # ── Merge: every queued finding records what happened to it ─────────
    for f, why in queue + overflow:
        fid = str(f["id"])
        batch = [p.get(fid, {}).get("verdict") for p in passes]
        how = stopped.get(fid, "not_run")
        if how != "verdict" and "disagreement" in why:
            # Phase A split and nothing settled it: neither batch verdict is
            # more trustworthy than the other.
            final[fid] = {"verdict": "needs_manual", "confidence": None,
                          "reasoning": (f"Batch passes disagreed ({' vs '.join(str(v) for v in batch)}) "
                                        f"and the investigation did not settle it ({how}).")}
        elif how != "verdict" and not final[fid].get("verdict"):
            final[fid] = {"verdict": "needs_manual", "confidence": None,
                          "reasoning": f"No batch pass assessed this finding and the "
                                       f"investigation did not settle it ({how})."}
        final[fid]["investigation"] = {
            "queued_because": why,
            "phase_a": batch,
            "stopped": how,
            "changed": how == "verdict" and final[fid]["verdict"] not in batch,
            **sessions.get(fid, {}),
        }

    counts = Counter(stopped.get(str(f["id"]), "not_run") for f, _ in queue + overflow)
    result = {
        "finding_validations": final,
        "_investigation": {
            "phase_a_runs": runs,
            "candidates": len(findings_data),
            "queued": len(queue) + len(overflow),
            "outcomes": dict(counts),
            "changed": sum(1 for v in final.values()
                           if (v.get("investigation") or {}).get("changed")),
            "max_turns": settings.AI_INVESTIGATE_MAX_TURNS,
            "aborted": aborted,
        },
        "_phase_a": phase_a_meta,
    }
    return result, tokens


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
        ruled = {str(f["id"]): v for f in findings_data if (v := _rule_verdict(f))}
        findings_data = [f for f in findings_data if str(f["id"]) not in ruled]

        provider = get_provider(analysis.provider, workspace_id=analysis.workspace_id)
        start_time = time.time()
        # Leave headroom for parsing and the DB writes that follow the last call.
        deadline = time.monotonic() + max(60, settings.AI_ANALYSIS_TIMEOUT - 240)

        if not findings_data:
            # Every finding was decided by a rule; nothing left for the model.
            result, tokens_used = _validate_result({}, analysis.mode), 0
        elif analysis.mode == INVESTIGATE_MODE:
            result, tokens_used = _run_investigate(
                db, analysis, provider, findings_data, target, deadline=deadline,
            )
        elif analysis.mode == TWO_STAGE_MODE:
            result, tokens_used = _run_two_stage(
                db, analysis, provider, findings_data, target, deadline=deadline,
            )
        else:
            result, tokens_used, assessed = _run_batched(
                db, analysis, provider, analysis.mode, findings_data, target,
                pct_from=20, pct_to=85, deadline=deadline,
                label=f"Analysing {len(findings_data)} findings",
            )
            result["_batching"] = {
                "total": len(findings_data),
                "submitted_to_model": assessed,
                "batch_size": settings.AI_BATCH_SIZE,
                "max_tokens": settings.AI_MAX_TOKENS,
                "failed_batches": result.pop("_failed_batches", []),
                "batches": result.pop("_batch_stats", []),
            }
        # After the last _validate_result(): it would stamp confidence=0.5 on
        # every rule verdict.
        result.setdefault("finding_validations", {}).update(ruled)
        result["_rules"] = {
            "decided": len(ruled),
            "by_rule": {r: sum(1 for v in ruled.values() if v["rule"] == r)
                        for r in sorted({v["rule"] for v in ruled.values()})},
        }
        _update_progress(db, analysis, {"pct": 90, "step": "Storing results..."})

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

