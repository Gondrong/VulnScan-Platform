"""
Read-only tools for the agentic `investigate` analysis mode.

One implementation behind every caller: today the MCP server the Claude CLI
talks to (ai/mcp_server.py), later in-process tool loops for API providers.

Scope is fixed by our code, never by the model. Every tool runs against a
ToolScope (workspace, scan job) set when the session starts; a model can ask
for finding #N, but only gets it if #N belongs to the scan being analysed.

Text that originated on the scanned target — evidence, banners, titles built
from them — comes back under keys ending in `_untrusted`. The target controls
that text, so it can carry instructions aimed at the model; the investigate
prompt tells the model to treat those fields as data only.

Nothing here writes, and nothing here touches the network beyond our own
database and graph. That is what keeps a successful prompt injection down to a
wrong verdict, which the recorded trail makes visible.
"""
import inspect
import json
import logging
import re
import time
from dataclasses import dataclass

from sqlalchemy import or_

from app.db.session import SessionLocal
from app.db import models

logger = logging.getLogger("vulnscan.ai.tools")

_EVIDENCE_MAX = 20_000
_SNIPPET = 300
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class ToolScope:
    workspace_id: int
    job_id: int


def _finding_row(db, scope: ToolScope, finding_id):
    try:
        fid = int(finding_id)
    except (TypeError, ValueError):
        return None
    return db.query(models.Finding).filter(
        models.Finding.id == fid,
        models.Finding.job_id == scope.job_id,
        models.Finding.workspace_id == scope.workspace_id,
    ).first()


def _json_list(raw: str | None) -> list:
    try:
        v = json.loads(raw or "[]")
        return v if isinstance(v, list) else []
    except Exception:
        return []


def get_finding(scope: ToolScope, finding_id: int) -> dict:
    db = SessionLocal()
    try:
        f = _finding_row(db, scope, finding_id)
        if not f:
            return {"error": f"finding {finding_id} is not part of this scan"}
        ev = f.evidence or ""
        return {
            "id": f.id,
            "plugin_id": f.plugin_id,
            "severity": f.severity,
            "cvss_base": f.cvss_base,
            "is_kev": f.is_kev,
            "target": f.target,
            "references": _json_list(f.references_json),
            "title_untrusted": f.title,
            "description_untrusted": f.description,
            "evidence_untrusted": ev[:_EVIDENCE_MAX],
            "evidence_truncated": len(ev) > _EVIDENCE_MAX,
        }
    finally:
        db.close()


def search_findings(scope: ToolScope, query: str = "", plugin_id: str = "",
                    limit: int = 20) -> dict:
    db = SessionLocal()
    try:
        q = db.query(models.Finding).filter(
            models.Finding.job_id == scope.job_id,
            models.Finding.workspace_id == scope.workspace_id,
        )
        if query:
            pat = "%" + re.sub(r"([\\%_])", r"\\\1", query) + "%"
            q = q.filter(or_(models.Finding.title.ilike(pat, escape="\\"),
                             models.Finding.evidence.ilike(pat, escape="\\")))
        if plugin_id:
            q = q.filter(models.Finding.plugin_id == plugin_id)
        try:
            n = min(max(int(limit), 1), 50)
        except (TypeError, ValueError):
            n = 20
        rows = q.order_by(models.Finding.id).limit(n).all()
        return {
            "count": len(rows),
            "findings": [{
                "id": f.id,
                "plugin_id": f.plugin_id,
                "severity": f.severity,
                "title_untrusted": f.title,
                "evidence_snippet_untrusted": (f.evidence or "")[:_SNIPPET],
            } for f in rows],
        }
    finally:
        db.close()


def lookup_cve(scope: ToolScope, cve_id: str) -> dict:
    cve = (cve_id or "").strip().upper()
    if not _CVE_RE.match(cve):
        return {"error": f"not a CVE id: {cve_id!r}"}
    # Imported here, not at module level: the first lookup builds a merged
    # cache of every CVE (measured at 4.3s and 630 MB RSS), and most findings
    # — CIS checks, header and CORS issues — never ask for one.
    from app.threat_intel import aggregator
    db = SessionLocal()
    try:
        rec = aggregator.detail(db, scope.workspace_id, cve)
    finally:
        db.close()
    if not rec:
        return {"cve": cve, "found": False,
                "note": "not in the local datasets; absence says nothing about exploitability"}
    keys = ("cve", "cvss", "severity", "vendor", "product", "epss", "epss_percentile",
            "kev", "kev_added", "kev_due", "ransomware", "threat_score")
    out = {k: rec.get(k) for k in keys}
    out["found"] = True
    out["summary"] = (rec.get("summary") or "")[:1200]
    return out


def finding_history(scope: ToolScope, finding_id: int) -> dict:
    db = SessionLocal()
    try:
        f = _finding_row(db, scope, finding_id)
        if not f:
            return {"error": f"finding {finding_id} is not part of this scan"}
        others = db.query(models.Finding).filter(
            models.Finding.workspace_id == scope.workspace_id,
            models.Finding.fingerprint == f.fingerprint,
            models.Finding.id != f.id,
        ).order_by(models.Finding.id.desc()).limit(10).all()

        verdicts = []
        for o in others:
            an = db.query(models.AiAnalysis).filter(
                models.AiAnalysis.job_id == o.job_id,
                models.AiAnalysis.status == "done",
            ).order_by(models.AiAnalysis.id.desc()).first()
            if not (an and an.result_json):
                continue
            try:
                v = (json.loads(an.result_json).get("finding_validations") or {}).get(str(o.id))
            except Exception:
                v = None
            if isinstance(v, dict):
                verdicts.append({
                    "finding_id": o.id, "job_id": o.job_id, "analysis_id": an.id,
                    "verdict": v.get("verdict"), "rule": v.get("rule"),
                    "prior_model_reasoning": (v.get("reasoning") or "")[:400],
                })

        suppressed = db.query(models.SuppressedFinding).filter(
            models.SuppressedFinding.workspace_id == scope.workspace_id,
            models.SuppressedFinding.fingerprint == f.fingerprint,
        ).all()
        return {
            "earlier_occurrences": len(others),
            "earlier_ai_verdicts": verdicts,
            "human_suppressions": [
                {"reason": s.reason, "at": s.created_at.isoformat() if s.created_at else None}
                for s in suppressed
            ],
        }
    finally:
        db.close()


def blast_radius(scope: ToolScope, target: str) -> dict:
    from app.graph.neo4j_client import Neo4jClient
    client = Neo4jClient()
    try:
        if not client.available:
            return {"error": "attack graph is unavailable"}
        g = client.query_blast_radius(scope.workspace_id, target, depth=1)
    finally:
        client.close()
    if not g or not g.get("nodes"):
        return {"target": target, "found": False}
    vulns = [n for n in g["nodes"] if n.get("type") != "asset"]
    assets = [n["id"] for n in g["nodes"] if n.get("type") == "asset" and not n.get("origin")]
    return {
        "target": target,
        "found": True,
        "vulnerabilities_on_target": len(vulns),
        "other_assets_sharing_them": assets[:25],
        "other_asset_count": len(assets),
    }


def plugin_info(scope: ToolScope, plugin_id: str) -> dict:
    import sys
    from app.scanner.engine import PLUGINS
    chk = PLUGINS.get(plugin_id)
    if not chk:
        return {"error": f"unknown plugin {plugin_id!r}"}
    m = chk.meta
    doc = (sys.modules[type(chk).__module__].__doc__ or "").strip()
    return {
        "plugin_id": m.plugin_id, "name": m.name, "category": m.category,
        "depends_on": m.depends_on, "consumes": m.consumes, "provides": m.provides,
        "timeout_seconds": m.timeout_seconds,
        "what_it_checks": doc[:3000] or "(no description in the plugin source)",
    }


_ID = {"type": "integer", "description": "Finding id from this scan."}

TOOLS = {
    "get_finding": (get_finding, (
        "Full record of one finding from this scan: untruncated evidence, references, "
        "plugin, severity. Use it when the evidence you were given looks cut short."),
        {"type": "object", "properties": {"finding_id": _ID}, "required": ["finding_id"]}),
    "search_findings": (search_findings, (
        "Other findings from the same scan, matched by a substring of the title or "
        "evidence and/or an exact plugin_id. Use it to corroborate or contradict a "
        "finding, e.g. whether a WAF, a TLS listener or an HTTP service was seen."),
        {"type": "object", "properties": {
            "query": {"type": "string"}, "plugin_id": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50}}}),
    "lookup_cve": (lookup_cve, (
        "Local threat intel for a CVE id: CVSS, EPSS, CISA KEV listing, ransomware use, "
        "affected vendor/product and summary."),
        {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}),
    "finding_history": (finding_history, (
        "The same finding (by fingerprint) in earlier scans of this workspace: earlier AI "
        "verdicts and any human suppression with its reason. A human suppression is the "
        "strongest signal available."),
        {"type": "object", "properties": {"finding_id": _ID}, "required": ["finding_id"]}),
    "blast_radius": (blast_radius, (
        "From the attack graph: how many vulnerabilities the target carries and which other "
        "assets share them."),
        {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}),
    "plugin_info": (plugin_info, (
        "What a scanner plugin actually tests and how — e.g. a version-banner match versus "
        "an active probe. Use it to judge how much a finding's evidence can prove."),
        {"type": "object", "properties": {"plugin_id": {"type": "string"}}, "required": ["plugin_id"]}),
}


def _summarise(name: str, r: dict) -> str:
    """One line for the investigation trail the UI shows."""
    if "error" in r:
        return f"error: {r['error']}"
    if name == "get_finding":
        return (f"{r['severity']} {r['plugin_id']}, evidence {len(r['evidence_untrusted'])} chars"
                + (" (truncated)" if r["evidence_truncated"] else ""))
    if name == "search_findings":
        ids = ", ".join(f"#{f['id']}" for f in r["findings"][:8])
        return f"{r['count']} match(es)" + (f": {ids}" if ids else "")
    if name == "lookup_cve":
        if not r.get("found"):
            return f"{r['cve']} not in local datasets"
        return f"{r['cve']}: KEV {'yes' if r['kev'] else 'no'}, EPSS {r['epss']}, CVSS {r['cvss']}"
    if name == "finding_history":
        vs = ", ".join(v["verdict"] or "?" for v in r["earlier_ai_verdicts"]) or "none"
        return (f"{r['earlier_occurrences']} earlier occurrence(s); AI verdicts: {vs}; "
                f"human suppressions: {len(r['human_suppressions'])}")
    if name == "blast_radius":
        if not r.get("found"):
            return f"{r['target']} not in the attack graph"
        return (f"{r['vulnerabilities_on_target']} vuln(s) on target, "
                f"{r['other_asset_count']} other asset(s) share them")
    if name == "plugin_info":
        return f"{r['name']} ({r['category']})"
    return "ok"


def call_tool(scope: ToolScope, name: str, args: dict, trail_path: str | None = None) -> dict:
    """Run one tool, record it to the trail, and never raise to the caller.

    A tool failure is reported to the model as {"error": ...} so it can try
    something else; a raised exception would end the whole session instead.
    """
    entry = TOOLS.get(name)
    t0 = time.monotonic()
    if not entry:
        result = {"error": f"unknown tool {name!r}"}
    else:
        try:
            # Bind first, so a TypeError raised *inside* a tool is not mistaken
            # for a bad argument from the model — which would send it off to
            # "fix" arguments that were fine.
            bound = inspect.signature(entry[0]).bind(scope, **(args or {}))
        except TypeError as e:
            bound, result = None, {"error": f"bad arguments: {e}"}
        if bound is not None:
            try:
                result = entry[0](*bound.args, **bound.kwargs)
            except Exception as e:
                logger.warning("Tool %s failed: %s", name, e)
                result = {"error": f"{type(e).__name__}: {e}"}
    ms = int((time.monotonic() - t0) * 1000)
    if trail_path:
        try:
            with open(trail_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"tool": name, "args": args or {}, "ms": ms,
                                     "summary": _summarise(name, result)}) + "\n")
        except Exception as e:
            logger.warning("Could not record %s to the trail: %s", name, e)
    return result
