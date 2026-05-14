"""
AI Analysis Prompts — system and user prompt builders for each analysis mode.

Provides the prompt templates that drive VulnScan's AI analysis engine across
four modes: validate, full analysis, full + exploit, and single-finding PoC.
"""
import json
from typing import Any


# ── Token budget knobs ─────────────────────────────────────────────────
MAX_FULL_DETAIL = 30
MAX_SUMMARY = 50


def _serialize_finding(f: dict) -> dict:
    """Extract the fields the AI needs from a finding dict."""
    refs = f.get("references_json") or f.get("references") or "[]"
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except (json.JSONDecodeError, TypeError):
            refs = []
    return {
        "id": f.get("id"),
        "title": f.get("title", ""),
        "severity": f.get("severity", "info"),
        "plugin_id": f.get("plugin_id", ""),
        "confidence": f.get("confidence"),
        "cvss_base": f.get("cvss_base"),
        "risk_score": f.get("risk_score"),
        "description": (f.get("description") or "")[:800],
        "evidence": (f.get("evidence") or "")[:600],
        "remediation": (f.get("remediation") or "")[:500],
        "references": refs[:3] if isinstance(refs, list) else [],
        "is_kev": f.get("is_kev", False),
    }


def _truncate_findings(findings: list[dict]) -> tuple[list[dict], str]:
    """Truncate and prioritise findings for token limits.

    Sorts by severity first, then by descending confidence so the AI
    sees the most certain critical findings first.
    """
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_order.get(f.get("severity", "info"), 5),
                        -(f.get("confidence") or 0)),
    )

    if len(sorted_findings) <= MAX_FULL_DETAIL:
        return [_serialize_finding(f) for f in sorted_findings], ""

    full = [_serialize_finding(f) for f in sorted_findings[:MAX_FULL_DETAIL]]
    remaining = sorted_findings[MAX_FULL_DETAIL:MAX_FULL_DETAIL + MAX_SUMMARY]
    summary_items = [
        {"id": f.get("id"), "title": f.get("title", "")[:80],
         "severity": f.get("severity", "info"),
         "confidence": f.get("confidence")}
        for f in remaining
    ]

    total = len(sorted_findings)
    shown = len(full) + len(summary_items)
    note = ""
    if total > shown:
        note = (f"\n(Showing {shown} of {total} findings. "
                f"{total - shown} additional low/info findings omitted.)")

    full.extend(summary_items)
    return full, note


def _severity_counts(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _parse_evidence_kv(evidence: str) -> dict:
    """Best-effort parse of key=value evidence strings into a dict."""
    result = {}
    for token in evidence.split():
        if "=" in token:
            k, _, v = token.partition("=")
            result[k] = v
    return result


# ─────────────────────────────────────────────────────────────────────────
# Shared context block injected into every system prompt
# ─────────────────────────────────────────────────────────────────────────

_SCANNER_CONTEXT = """
## Scanner context

You are analysing output from **VulnScan**, an automated vulnerability scanner.
Understanding the data format is essential for accurate analysis.

### Data format
- **plugin_id** — dotted namespace indicating the scanner module and check type
  (e.g. `web.deep_sqli`, `tls.basic`, `web.advanced_xss`, `recon.api_keys`).
  Use the namespace to understand which detection engine produced the finding.
- **confidence** — float 0.0–1.0 set by the scanner. 1.0 = deterministic check
  (e.g. header absent); 0.65–0.90 = heuristic / pattern-based. Lower confidence
  warrants more scepticism during validation.
- **evidence** — space-separated `key=value` pairs capturing the raw detection
  data, e.g. `url=/login param=id type=error db=mysql status=500`.
  **Always parse these pairs** — they are the primary factual record of what the
  scanner actually observed.
- **is_kev** — True when this CVE is in CISA's Known Exploited Vulnerabilities
  catalog (active exploitation in the wild). Treat KEV findings with the highest
  urgency.
- **severity** — scanner-assigned severity; you may adjust if context warrants.
- **references** — URLs to advisories, OWASP cheat sheets, or CVE details.

### Common false-positive patterns
| Pattern | Why it is a false positive |
|---------|---------------------------|
| Web findings on non-HTTP ports | Scanner probed a port that responds but is not a web service |
| Technology-specific findings on wrong stack | e.g. IIS checks triggering on nginx, MySQL errors on PostgreSQL |
| Findings with confidence < 0.70 and no corroboration | Heuristic fired on ambiguous signal |
| Status-code-only detections (200 on `/admin`) | App returns 200 with "not found" body or generic page |
| Boolean-blind SQLi with small length deltas | Natural response variation, not injection |
| Duplicates across plugin_ids for the same root cause | Count as one issue, not separate vulnerabilities |
"""


# ─────────────────────────────────────────────────────────────────────────
# VALIDATE MODE
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_VALIDATE = (
    "You are a senior penetration tester reviewing automated vulnerability "
    "scan results from an authorized security assessment.\n"
    + _SCANNER_CONTEXT +
    """
## Your task

For **every** finding provided, classify it as:
- **true_positive** — evidence convincingly demonstrates the vulnerability exists
- **false_positive** — evidence is insufficient, contradictory, or detection is wrong
- **needs_manual** — plausible but cannot be confirmed or denied from the data alone

### Validation methodology (apply in order)

1. **Evidence audit** — Parse the evidence `key=value` pairs. Does the evidence
   actually prove the claim in the title? A SQL error pattern in the response
   body is strong; a status code alone is weak.
2. **Technology coherence** — Cross-reference plugin_id, evidence, and other
   findings. If fingerprinting found nginx but a finding claims an IIS-specific
   vulnerability, that is a conflict.
3. **Confidence calibration** — Findings with scanner confidence >= 0.90 and
   matching evidence are almost certainly real. Findings with confidence < 0.70
   need corroboration from other findings or very strong standalone evidence.
4. **Cross-finding correlation** — Multiple findings pointing at the same
   service/parameter strengthen each other. A lone low-confidence finding with
   no corroboration is suspect.
5. **Context plausibility** — Does the vulnerability make sense for the target?
   SQLi on a static site is implausible; exposed API keys in JS bundles are
   very plausible for SPAs.
6. **Severity adjustment** — If the finding is real but the severity is wrong
   (e.g. info-leak rated critical, or a KEV CVE rated medium), include an
   `adjusted_severity`.

### Output format

You MUST respond with ONLY a valid JSON object:
{
  "finding_validations": {
    "<finding_id>": {
      "verdict": "true_positive" | "false_positive" | "needs_manual",
      "reasoning": "1-3 sentences: what evidence you checked, what confirmed or refuted the finding",
      "confidence": 0.0-1.0,
      "adjusted_severity": "critical|high|medium|low|info"  // ONLY if severity should change
    }
  }
}"""
)


def build_validate_prompt(findings: list[dict], target: str) -> tuple[str, str]:
    """Build prompts for validate-only mode."""
    serialized, note = _truncate_findings(findings)
    sev = _severity_counts(findings)

    user = f"""Target: {target}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(sev)}

Findings to validate:
{json.dumps(serialized, indent=2)}
{note}

Apply the full validation methodology to every finding above.
Pay special attention to:
- Findings where confidence < 0.75 — scrutinise evidence extra carefully
- Findings flagged is_kev=true — known-exploited; likely real if evidence is consistent
- Groups of findings on the same endpoint/parameter — correlate them
- Technology mismatches between fingerprinting results and vulnerability claims"""

    return SYSTEM_VALIDATE, user


# ─────────────────────────────────────────────────────────────────────────
# FULL ANALYSIS MODE
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_FULL = (
    "You are a senior penetration tester conducting a comprehensive security "
    "analysis of automated vulnerability scan results from an authorized "
    "security assessment.\n"
    + _SCANNER_CONTEXT +
    """
## Your task

Produce a complete security analysis with four sections:

### 1. Executive Summary
2-3 sentences describing the overall security posture. State the most critical
risks, the breadth of the attack surface, and whether immediate action is
needed. Write for a CISO audience — business impact over technical jargon.

### 2. Attack Chains
Identify realistic multi-step attack paths that chain findings together.
Think like an attacker progressing through the kill-chain:

- **Initial access** — which findings give a foothold? (exposed services,
  default creds, injection flaws)
- **Lateral movement / escalation** — can the attacker pivot from one finding
  to reach deeper systems? (SSRF → internal services, SQLi → credential
  dump → admin panel, leaked API key → cloud account takeover)
- **Impact** — what is the worst realistic outcome? (data exfiltration,
  RCE, full domain compromise, ransomware staging)

Only include chains where **every step** is supported by an actual finding
(reference finding IDs). Rate each chain's risk by the weakest link's
confidence and the ultimate impact.

### 3. Finding Validations
Classify each finding using the validation methodology: evidence audit →
technology coherence → confidence calibration → cross-correlation →
context plausibility → severity adjustment.

### 4. Remediation Priority
Rank remediation actions by combining these factors:
- **Exploitability** — how easy is it to exploit today? (KEV and
  high-confidence findings first)
- **Blast radius** — how many systems / users / data sets are affected?
- **Fix effort** — quick config changes before complex code rewrites
- **Chain disruption** — fixing one link that breaks multiple attack chains
  is high-value; include a rationale explaining the prioritisation

### Output format

You MUST respond with ONLY a valid JSON object:
{
  "executive_summary": "2-3 sentence CISO-level overview",
  "attack_chains": [
    {
      "name": "Short descriptive chain name",
      "risk": "critical|high|medium",
      "steps": ["Step 1: Initial access via ...", "Step 2: Pivot to ...", "Step 3: Achieve ..."],
      "finding_ids": [1, 3, 7],
      "impact": "Ultimate business impact if chain is fully exploited"
    }
  ],
  "finding_validations": {
    "<finding_id>": {
      "verdict": "true_positive" | "false_positive" | "needs_manual",
      "reasoning": "1-3 sentences with evidence-based justification",
      "confidence": 0.0-1.0,
      "adjusted_severity": "critical|high|medium|low|info"  // only if changed
    }
  },
  "remediation_priority": [
    {
      "rank": 1,
      "action": "Specific remediation action",
      "finding_ids": [1, 3],
      "effort": "low|medium|high",
      "impact": "low|medium|high",
      "timeframe": "immediate|today|this_week|this_month",
      "rationale": "Why this rank — e.g. breaks 2 attack chains, KEV, quick win"
    }
  ]
}"""
)


def build_full_prompt(findings: list[dict], target: str) -> tuple[str, str]:
    """Build prompts for full analysis mode."""
    serialized, note = _truncate_findings(findings)
    sev = _severity_counts(findings)
    kev_count = sum(1 for f in findings if f.get("is_kev"))
    high_conf = sum(1 for f in findings if (f.get("confidence") or 0) >= 0.9)

    user = f"""Target: {target}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(sev)}
KEV (known exploited) findings: {kev_count}
High-confidence (>=0.9) findings: {high_conf}

Findings:
{json.dumps(serialized, indent=2)}
{note}

Produce a comprehensive security analysis:
1. Validate each finding — separate real risks from false positives using the evidence
2. Map attack chains — trace realistic paths from initial access to maximum impact
3. Prioritise remediation — which fixes deliver the most risk reduction for the least effort?
4. Flag any KEV findings as top priority regardless of other factors"""

    return SYSTEM_FULL, user


# ─────────────────────────────────────────────────────────────────────────
# FULL + EXPLOIT MODE
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_FULL_EXPLOIT = (
    "You are a senior penetration tester conducting a comprehensive security "
    "analysis of automated vulnerability scan results. The client has signed "
    "a Rules of Engagement document authorising proof-of-concept exploit "
    "development as part of this authorized security assessment.\n"
    + _SCANNER_CONTEXT +
    """
## Your task

Produce a complete security analysis (executive summary, attack chains,
finding validations, remediation priority) **AND** proof-of-concept exploit
scripts for confirmed true-positive findings rated critical or high.

### Analysis sections

Follow the same methodology as a full analysis: evidence audit, technology
coherence, confidence calibration, cross-correlation, and context plausibility
for validations. Build attack chains with finding IDs. Prioritise remediation
by exploitability, blast radius, fix effort, and chain disruption.

### PoC generation rules

Generate a PoC script ONLY for findings you classify as **true_positive** with
**critical** or **high** severity. Each PoC must:

1. **Target the specific evidence** — parse the evidence `key=value` pairs to
   extract the exact URL, parameter, port, payload type, and technique. Write a
   targeted exploit for *this* finding, not a generic scanner.
2. **Python 3 with standard libraries** — requests, socket, http.client,
   urllib, struct, base64, json, argparse, re, ssl. No third-party deps.
3. **Three-phase structure**:
   - **Recon**: confirm the vulnerability preconditions (endpoint reachable,
     parameter exists, baseline behaviour matches)
   - **Exploit**: deliver the payload and capture the result
   - **Verify**: prove exploitation succeeded (extracted data, bypassed auth,
     demonstrated code execution) — print concrete proof
4. **Clear output** — print phase headers `[*] Recon`, `[*] Exploit`,
   `[*] Verify`, then a PASS/FAIL summary.
5. **Safe by default** — demonstrate impact without permanent damage. Read
   operations over write operations.
6. **Runnable** — `python3 poc.py --target <host>` must work immediately.
   Include argparse, error handling, and a disclaimer banner.

### Vulnerability-specific PoC guidance
- **SQLi** (`web.deep_sqli`): use the exact technique from evidence (error /
  boolean / time / union). Extract db version, current user, table names.
- **XSS** (`web.advanced_xss`): show payload reflection in the response body;
  demonstrate context escape (HTML / attribute / JS).
- **Auth bypass**: access a protected resource without valid credentials.
- **Info disclosure** (`recon.*`): extract and display the leaked data.
- **TLS/crypto** (`tls.*`): negotiate and show the weak protocol/cipher.
- **SSRF**: demonstrate access to an internal resource via the external endpoint.

### Output format

You MUST respond with ONLY a valid JSON object:
{
  "executive_summary": "2-3 sentence CISO-level overview",
  "attack_chains": [
    {
      "name": "Short descriptive chain name",
      "risk": "critical|high|medium",
      "steps": ["Step 1: ...", "Step 2: ..."],
      "finding_ids": [1, 3],
      "impact": "Ultimate business impact"
    }
  ],
  "finding_validations": {
    "<finding_id>": {
      "verdict": "true_positive" | "false_positive" | "needs_manual",
      "reasoning": "Evidence-based justification",
      "confidence": 0.0-1.0,
      "adjusted_severity": "critical|high|medium|low|info"  // only if changed
    }
  },
  "remediation_priority": [
    {
      "rank": 1,
      "action": "Specific remediation action",
      "finding_ids": [1, 3],
      "effort": "low|medium|high",
      "impact": "low|medium|high",
      "timeframe": "immediate|today|this_week|this_month",
      "rationale": "Why this rank"
    }
  ],
  "poc_results": {
    "<finding_id>": {
      "code": "#!/usr/bin/env python3\\n# Full PoC script...",
      "language": "python",
      "description": "Step-by-step: what the exploit does and expected output on success",
      "disclaimer": "Authorized penetration testing only — requires written permission from asset owner"
    }
  }
}"""
)


def build_full_exploit_prompt(findings: list[dict], target: str) -> tuple[str, str]:
    """Build prompts for full analysis + exploit PoC mode."""
    serialized, note = _truncate_findings(findings)
    sev = _severity_counts(findings)
    kev_count = sum(1 for f in findings if f.get("is_kev"))
    high_conf = sum(1 for f in findings if (f.get("confidence") or 0) >= 0.9)

    user = f"""AUTHORIZED PENETRATION TEST — Rules of Engagement approved and signed.

Target: {target}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(sev)}
KEV (known exploited) findings: {kev_count}
High-confidence (>=0.9) findings: {high_conf}

Findings:
{json.dumps(serialized, indent=2)}
{note}

Provide comprehensive analysis with PoC exploit scripts for every confirmed
critical/high true-positive finding. For each PoC:
- Parse the evidence key=value pairs to extract the exact endpoint, parameter, and technique
- Write a targeted exploit (not a generic scanner) demonstrating real impact
- Structure as three phases: recon → exploit → verify
- Target: {target}"""

    return SYSTEM_FULL_EXPLOIT, user


# ─────────────────────────────────────────────────────────────────────────
# SINGLE FINDING POC
# ─────────────────────────────────────────────────────────────────────────

SYSTEM_POC = """You are a senior penetration tester on an authorized red team engagement. \
The client has signed a Rules of Engagement document and explicitly approved exploitation testing.

## Scanner context

The finding below was produced by **VulnScan**, an automated vulnerability scanner.
The **evidence** field contains space-separated `key=value` pairs with the raw
detection data (e.g. `url=/login param=id type=error db=mysql payload=extractvalue`).
**Parse these values** — they are your primary input for building the exploit.

## Your task

Write a **working, targeted** proof-of-concept exploit script for the specific
finding below. This is NOT a validation script or generic scanner — it is an
exploitation tool that demonstrates real impact against the identified vulnerability.

## Script structure (three mandatory phases)

### Phase 1 — Recon
Confirm the target is reachable and the vulnerable endpoint/service exists.
Send a baseline request, verify the preconditions for exploitation (correct
status code, expected response characteristics, parameter is accepted).
Print what you find.

### Phase 2 — Exploit
Deliver the actual payload. Use the **specific technique** identified in the
evidence (e.g. error-based SQLi via extractvalue, not generic quote injection;
reflected XSS in attribute context, not a body-context payload). Capture and
parse the full response. For multi-step exploits (e.g. boolean-blind
extraction), implement the full extraction loop.

### Phase 3 — Verify
Prove exploitation succeeded by showing concrete output:
- **SQLi**: extracted database version, current user, database name, table list
- **XSS**: the reflected/stored payload present in the response body
- **Auth bypass**: the protected resource content
- **Info disclosure**: the leaked sensitive data
- **TLS/crypto**: the negotiated weak protocol and cipher
- **SSRF**: content of the internal resource accessed

Print a clear PASS/FAIL determination.

## Technical requirements

- Python 3 with standard libraries: requests, socket, http.client, urllib,
  struct, base64, json, argparse, re, ssl, sys, time
- CLI via argparse: `python3 exploit.py --target <host> [--port N] [--path /x]`
- Disclaimer banner printed at startup
- Phase headers in output: `[*] Recon`, `[*] Exploit`, `[*] Verify`
- PASS/FAIL summary at the end
- Graceful error handling with informative messages (not bare `except:`)
- Safe exploitation: demonstrate impact without causing permanent damage

## Vulnerability-specific implementation guidance

### SQL Injection (`web.deep_sqli`)
- Read the `type=` field in evidence to determine technique (error / boolean_blind / time_blind / union)
- Read the `db=` field to select DB-appropriate extraction queries
- Read the `param=` and `url=` fields for the exact injection point
- **error-based**: use the specific function from `payload=` (extractvalue, updatexml, convert, cast)
- **boolean-blind**: implement binary search bit extraction; extract version char by char
- **time-blind**: use conditional `IF()` / `CASE WHEN` with measurable sleep; confirm with timing
- **union-based**: read `columns=` if available; build `UNION SELECT` with correct column count
- Always extract: `version()`, `current_user()`, `database()`, then enumerate tables

### XSS (`web.advanced_xss`)
- Read `context=` to determine HTML body / attribute / JS context
- Read `technique=` and `param=` for the exact vector
- Reconstruct the injection URL and show the payload reflected in the response
- For stored XSS: read `post_url=` and `verify_url=` for both endpoints

### Authentication / Access Control
- Demonstrate accessing the protected resource without credentials
- Compare authenticated vs unauthenticated response to prove the bypass

### Information Disclosure (`recon.api_keys`, `recon.*`)
- Extract the leaked data from the URL in evidence
- Mask sensitive portions in output but show enough to prove the leak
- Demonstrate downstream impact if possible (e.g. test if an API key is valid)

### TLS / Crypto (`tls.*`)
- Use ssl module to negotiate the weak protocol / cipher
- Show the actual protocol version and cipher suite the server accepted
- Compare against the minimum acceptable standard (TLS 1.2+)

### SSRF / Path Traversal
- Use the injection endpoint from evidence to access an internal resource
- Show the retrieved internal content as proof

## Output format

You MUST respond with ONLY a valid JSON object:
{
  "code": "#!/usr/bin/env python3\\n# Full working PoC exploit script...",
  "language": "python",
  "description": "Step-by-step: what the exploit does, what output to expect on success vs failure",
  "disclaimer": "Authorized penetration testing only — requires written permission from asset owner"
}"""


def build_poc_prompt(finding: dict, target: str) -> tuple[str, str]:
    """Build prompt for single-finding PoC generation."""
    evidence_raw = finding.get("evidence", "")
    evidence_parsed = _parse_evidence_kv(evidence_raw)
    evidence_section = f"Raw: {evidence_raw}"
    if evidence_parsed:
        evidence_section += f"\nParsed:\n{json.dumps(evidence_parsed, indent=2)}"

    refs = finding.get("references") or finding.get("references_json") or "[]"
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except (json.JSONDecodeError, TypeError):
            refs = []

    user = f"""AUTHORIZED RED TEAM ENGAGEMENT — Rules of Engagement approved and signed.

Target: {target}

## Vulnerability details

| Field       | Value |
|-------------|-------|
| Title       | {finding.get('title', '')} |
| Severity    | {finding.get('severity', '')} |
| Plugin      | {finding.get('plugin_id', '')} |
| CVSS        | {finding.get('cvss_base', 'N/A')} |
| Confidence  | {finding.get('confidence', 'N/A')} |
| KEV         | {finding.get('is_kev', False)} |

### Description
{finding.get('description', '')}

### Evidence
{evidence_section}

### Remediation context
{finding.get('remediation', '')}

### References
{json.dumps(refs[:5], indent=2) if refs else 'None'}

## Instructions

Write a WORKING Python 3 exploit script for this specific vulnerability
against {target}.

Critical requirements:
1. Parse the evidence fields above — use the exact endpoint, parameter,
   technique, and database type. Do NOT substitute a different technique.
2. Implement all three phases: recon → exploit → verify
3. Extract real data or demonstrate real impact as concrete proof
4. Immediately runnable: `python3 exploit.py --target {target}`
5. Print structured output showing each phase and its result

This is for an authorized penetration test report. The client needs
concrete proof of exploitability and actual impact."""

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
