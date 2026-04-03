"""
AI Analysis Prompts — system and user prompt builders for each analysis mode.
"""
import json
from typing import Any


# ── Max findings to send in full detail ─────────────────────────────────
MAX_FULL_DETAIL = 30
MAX_SUMMARY = 50


def _serialize_finding(f: dict) -> dict:
    """Extract the fields we need from a finding dict."""
    return {
        "id": f.get("id"),
        "title": f.get("title", ""),
        "severity": f.get("severity", "info"),
        "description": (f.get("description") or "")[:500],
        "evidence": (f.get("evidence") or "")[:300],
        "plugin_id": f.get("plugin_id", ""),
        "cvss_base": f.get("cvss_base"),
        "risk_score": f.get("risk_score"),
        "confidence": f.get("confidence"),
        "remediation": (f.get("remediation") or "")[:200],
        "is_kev": f.get("is_kev", False),
    }


def _truncate_findings(findings: list[dict]) -> tuple[list[dict], str]:
    """
    Truncate findings list for token limits.
    Returns (serialized_findings, summary_note).
    """
    # Sort by severity priority
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    if len(sorted_findings) <= MAX_FULL_DETAIL:
        return [_serialize_finding(f) for f in sorted_findings], ""

    # Full detail for critical/high, summary for rest
    full = [_serialize_finding(f) for f in sorted_findings[:MAX_FULL_DETAIL]]

    remaining = sorted_findings[MAX_FULL_DETAIL:MAX_FULL_DETAIL + MAX_SUMMARY]
    summary_items = [
        {"id": f.get("id"), "title": f.get("title", "")[:80], "severity": f.get("severity", "info")}
        for f in remaining
    ]

    total = len(sorted_findings)
    shown = len(full) + len(summary_items)
    note = ""
    if total > shown:
        note = f"\n(Showing {shown} of {total} findings. {total - shown} additional low/info findings omitted.)"

    full.extend(summary_items)
    return full, note


# ─────────────────────────────────────────────────────────────────────────
# VALIDATE MODE
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_VALIDATE = """You are a senior penetration tester reviewing automated vulnerability scan results from an authorized security assessment.

Your task: For each finding, determine if it is a TRUE POSITIVE (real vulnerability), FALSE POSITIVE (incorrect detection), or NEEDS MANUAL VERIFICATION.

Consider:
- Does the evidence support the claim? (e.g., a 403 status on /wp-admin doesn't mean WordPress is present)
- Is the technology actually in use? (e.g., IIS findings on a Linux/Nginx server are false positives)
- Could the detection be confused by custom error pages, WAFs, or reverse proxies?
- Is the severity appropriate for the context?

You MUST respond with ONLY a valid JSON object in this exact format:
{
  "finding_validations": {
    "<finding_id>": {
      "verdict": "true_positive" | "false_positive" | "needs_manual",
      "reasoning": "Brief explanation (1-2 sentences)",
      "confidence": 0.0-1.0,
      "adjusted_severity": "critical|high|medium|low|info" (optional, only if severity should change)
    }
  }
}"""


def build_validate_prompt(findings: list[dict], target: str) -> tuple[str, str]:
    """Build prompts for validate-only mode."""
    serialized, note = _truncate_findings(findings)
    user = f"""Target: {target}
Total findings: {len(findings)}

Findings to validate:
{json.dumps(serialized, indent=2)}
{note}

Classify each finding. Focus on identifying false positives caused by:
- Technology mismatches (e.g., IIS findings on Linux)
- Custom 404 pages returning 200 status
- WAF/proxy interference
- Generic detections without specific evidence"""

    return SYSTEM_VALIDATE, user


# ─────────────────────────────────────────────────────────────────────────
# FULL ANALYSIS MODE
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_FULL = """You are a senior penetration tester conducting a comprehensive analysis of automated vulnerability scan results from an authorized security assessment.

Your task: Provide a complete security analysis including:
1. Executive Summary — overall risk posture in 2-3 sentences
2. Attack Chains — identify how multiple vulnerabilities can be chained for maximum impact
3. Finding Validations — classify each finding as true_positive/false_positive/needs_manual
4. Remediation Priority — ordered list of actions by urgency and impact

You MUST respond with ONLY a valid JSON object in this exact format:
{
  "executive_summary": "2-3 sentence overview of the security posture",
  "attack_chains": [
    {
      "name": "Short chain name",
      "risk": "critical|high|medium",
      "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      "finding_ids": [1, 3, 7],
      "impact": "Description of ultimate impact"
    }
  ],
  "finding_validations": {
    "<finding_id>": {
      "verdict": "true_positive" | "false_positive" | "needs_manual",
      "reasoning": "Brief explanation",
      "confidence": 0.0-1.0
    }
  },
  "remediation_priority": [
    {
      "rank": 1,
      "action": "What to do",
      "finding_ids": [1, 3],
      "effort": "low|medium|high",
      "impact": "low|medium|high",
      "timeframe": "immediate|today|this_week|this_month"
    }
  ]
}"""


def build_full_prompt(findings: list[dict], target: str) -> tuple[str, str]:
    """Build prompts for full analysis mode."""
    serialized, note = _truncate_findings(findings)

    # Count by severity
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    user = f"""Target: {target}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(sev_counts)}

Findings:
{json.dumps(serialized, indent=2)}
{note}

Provide a comprehensive security analysis. Focus on:
1. Which findings represent real risk vs false positives
2. How vulnerabilities can be chained together for greater impact
3. What should be fixed first (prioritize by exploitability and business impact)
4. Identify attack paths from initial access to maximum damage"""

    return SYSTEM_FULL, user


# ─────────────────────────────────────────────────────────────────────────
# FULL + EXPLOIT MODE
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_FULL_EXPLOIT = """You are a senior penetration tester conducting a comprehensive analysis of automated vulnerability scan results from an authorized security assessment. The client has authorized proof-of-concept exploit development.

Your task: Provide complete security analysis WITH proof-of-concept scripts for confirmed true positive findings.

You MUST respond with ONLY a valid JSON object in this exact format:
{
  "executive_summary": "2-3 sentence overview",
  "attack_chains": [
    {
      "name": "Short chain name",
      "risk": "critical|high|medium",
      "steps": ["Step 1: ...", "Step 2: ..."],
      "finding_ids": [1, 3],
      "impact": "Ultimate impact description"
    }
  ],
  "finding_validations": {
    "<finding_id>": {
      "verdict": "true_positive" | "false_positive" | "needs_manual",
      "reasoning": "Brief explanation",
      "confidence": 0.0-1.0
    }
  },
  "remediation_priority": [
    {
      "rank": 1,
      "action": "What to do",
      "finding_ids": [1, 3],
      "effort": "low|medium|high",
      "impact": "low|medium|high",
      "timeframe": "immediate|today|this_week|this_month"
    }
  ],
  "poc_results": {
    "<finding_id>": {
      "code": "#!/usr/bin/env python3\\n# PoC script...",
      "language": "python",
      "description": "What this PoC demonstrates",
      "disclaimer": "Authorized testing only"
    }
  }
}

Generate PoC scripts ONLY for findings you classify as true_positive with critical or high severity. PoC scripts should:
- Be written in Python 3
- Include clear comments explaining each step
- Use only standard libraries (requests, socket, http.client) where possible
- Include a disclaimer header
- Be safe to run (demonstrate the vulnerability without causing damage)
- Target the specific host and evidence from the finding"""


def build_full_exploit_prompt(findings: list[dict], target: str) -> tuple[str, str]:
    """Build prompts for full analysis + exploit PoC mode."""
    serialized, note = _truncate_findings(findings)

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    user = f"""Target: {target}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(sev_counts)}

Findings:
{json.dumps(serialized, indent=2)}
{note}

Provide comprehensive analysis with PoC exploit scripts for confirmed critical/high true positives.
This is an authorized penetration test — the client has explicitly approved exploit development."""

    return SYSTEM_FULL_EXPLOIT, user


# ─────────────────────────────────────────────────────────────────────────
# SINGLE FINDING POC
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_POC = """You are a senior penetration tester on an authorized red team engagement. The client has signed a Rules of Engagement document and explicitly approved exploitation testing. Your task is to write a working proof-of-concept exploit script.

IMPORTANT: This is NOT a validation script. Write an ACTUAL EXPLOITATION script that:
1. Connects to the target and exploits the vulnerability
2. Demonstrates real impact (data extraction, command execution, authentication bypass, etc.)
3. Shows what an attacker could achieve with this vulnerability
4. Includes multiple exploitation techniques if applicable

Technical requirements:
- Python 3 with standard libraries (requests, socket, http.client, urllib, struct, base64, json)
- Include a banner/disclaimer header
- Add clear comments explaining each exploitation step
- Include command-line argument parsing (argparse) for target/options
- Print exploitation results clearly
- Handle errors gracefully with informative messages
- Include a verification step that confirms successful exploitation

The script should be RUNNABLE — not pseudocode or a skeleton. Include actual payloads, actual HTTP requests, actual data parsing.

You MUST respond with ONLY a valid JSON object:
{
  "code": "#!/usr/bin/env python3\\n# Full working PoC exploit script...",
  "language": "python",
  "description": "What this exploit does, step by step, and expected output when successful",
  "disclaimer": "Authorized penetration testing only — requires written permission from asset owner"
}"""


def build_poc_prompt(finding: dict, target: str) -> tuple[str, str]:
    """Build prompt for single-finding PoC generation."""
    user = f"""AUTHORIZED RED TEAM ENGAGEMENT — Rules of Engagement approved.

Target: {target}

Vulnerability Details:
- Title: {finding.get('title', '')}
- Severity: {finding.get('severity', '')}
- Plugin: {finding.get('plugin_id', '')}
- CVSS: {finding.get('cvss_base', 'N/A')}
- Description: {finding.get('description', '')}
- Evidence: {finding.get('evidence', '')}
- Remediation: {finding.get('remediation', '')}

Write a WORKING Python 3 exploit script for this vulnerability against {target}.

The script must:
1. Connect to {target} and exploit the vulnerability
2. Extract data, bypass authentication, or demonstrate real impact
3. Include actual payloads (not placeholders)
4. Be immediately runnable with: python3 exploit.py {target}
5. Print clear output showing successful exploitation

This is for an authorized penetration test report. The client needs to see the actual risk."""

    return SYSTEM_POC, user


# ─────────────────────────────────────────────────────────────────────────
# Prompt dispatcher
# ─────────────────────────────────────────────────────────────────────────

def build_prompt(mode: str, findings: list[dict], target: str) -> tuple[str, str]:
    """Dispatch to the correct prompt builder based on mode."""
    if mode == "validate":
        return build_validate_prompt(findings, target)
    elif mode == "full":
        return build_full_prompt(findings, target)
    elif mode == "full_exploit":
        return build_full_exploit_prompt(findings, target)
    raise ValueError(f"Unknown analysis mode: {mode}")

