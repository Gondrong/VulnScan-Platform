"""
Graph API routes — serves Neo4j attack graph data to the frontend.
Falls back to PostgreSQL findings data if Neo4j is unavailable.
"""
import json
import logging
import re
from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.db import models
from app.graph.neo4j_client import Neo4jClient

logger = logging.getLogger("vulnscan.graph")

router = APIRouter(prefix="/graph", tags=["graph"])

# Shared singleton — reused across requests instead of opening a new driver each time
_neo4j: Neo4jClient | None = None


def _get_neo4j() -> Neo4jClient:
    global _neo4j
    if _neo4j is None:
        _neo4j = Neo4jClient()
    return _neo4j


def _neo4j_graph(ws_id: int) -> dict | None:
    """Try to fetch the attack graph from the shared Neo4j client."""
    neo = _get_neo4j()
    if not neo.available:
        return None
    return neo.query_attack_map(ws_id)


def _pg_graph(ws_id: int, db: Session) -> dict:
    """Build attack graph from PostgreSQL findings as fallback."""
    findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.workspace_id == ws_id,
        )
        .order_by(models.Finding.risk_score.desc().nullslast())
        .limit(500)
        .all()
    )

    nodes = []
    links = []
    node_ids = set()
    by_target = defaultdict(list)
    for f in findings:
        by_target[f.target].append(f)

    for target, target_findings in by_target.items():
        # Always add the asset node (even if only info findings)
        if target not in node_ids:
            nodes.append({
                "id": target, "label": target,
                "type": "asset", "size": 18,
            })
            node_ids.add(target)

        # Limit vuln nodes per host: show top findings by risk
        shown = 0
        for f in target_findings:
            if shown >= 30:
                break

            # Build a unique ID scoped to this target
            # Use CVE if available, otherwise target+fingerprint
            label = f.title[:30] if f.title else "unknown"
            if f.evidence and "CVE-" in (f.evidence or ""):
                cve_match = re.search(r"(CVE-\d{4}-\d+)", f.evidence)
                if cve_match:
                    label = cve_match.group(1)

            # Scope vuln ID to target so same-titled findings on different
            # hosts appear as separate nodes
            vuln_id = f"{target}::{f.fingerprint or f.title[:40]}"

            if vuln_id not in node_ids:
                nodes.append({
                    "id": vuln_id, "label": label,
                    "type": "vuln", "severity": f.severity,
                    "risk": round(f.risk_score or 0, 1),
                    "title": f.title,
                    "size": max(5, min(16, (f.risk_score or 0) * 1.5 + 2)),
                })
                node_ids.add(vuln_id)
                shown += 1

            links.append({
                "source": target, "target": vuln_id,
                "risk": round(f.risk_score or 0, 1),
                "plugin": f.plugin_id,
            })

    return {"nodes": nodes, "links": links, "source": "postgres"}


@router.get("/attack-map")
def attack_map(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """
    Returns attack graph data for D3 force visualization.
    Tries Neo4j first, falls back to PostgreSQL findings.
    """
    ws_id = user["ws"]
    graph = _neo4j_graph(ws_id)
    if graph and graph["nodes"]:
        return graph
    return _pg_graph(ws_id, db)


@router.post("/sync")
def sync_graph(
    full: bool = True,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Sync Neo4j graph from PostgreSQL findings.
    full=true (default): clears graph and rebuilds entirely.
    full=false: incremental — only syncs findings created since last sync.
    """
    ws_id = user["ws"]
    try:
        neo = _get_neo4j()
        if not neo.available:
            return {"ok": False, "error": "Neo4j is not available"}

        query = db.query(models.Finding).filter(
            models.Finding.workspace_id == ws_id,
        )
        if not full:
            # Incremental: read last sync timestamp from workspace settings
            setting = (
                db.query(models.WorkspaceSetting)
                .filter(
                    models.WorkspaceSetting.workspace_id == ws_id,
                    models.WorkspaceSetting.key == "graph_last_sync",
                )
                .first()
            )
            if setting:
                try:
                    from datetime import datetime, timezone
                    last_sync = datetime.fromisoformat(
                        json.loads(setting.value_json).get("at", "")
                    )
                    query = query.filter(models.Finding.created_at > last_sync)
                except Exception:
                    pass  # fall through to sync all

        findings = query.all()
        finding_dicts = []
        for f in findings:
            cve = None
            if f.evidence and "CVE-" in f.evidence:
                cve_match = re.search(r"(CVE-\d{4}-\d+)", f.evidence)
                if cve_match:
                    cve = cve_match.group(1)
            comp_ids = None
            if f.compliance_json:
                try:
                    comp_ids = json.loads(f.compliance_json)
                except Exception:
                    pass
            finding_dicts.append({
                "target": f.target,
                "cve": cve,
                "plugin_id": f.plugin_id,
                "risk_score": f.risk_score,
                "fingerprint": f.fingerprint,
                "title": f.title,
                "severity": f.severity,
                "compliance_ids": comp_ids,
            })
        count = neo.sync_from_findings(ws_id, finding_dicts, full=full)

        # Record last sync timestamp
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        setting = (
            db.query(models.WorkspaceSetting)
            .filter(
                models.WorkspaceSetting.workspace_id == ws_id,
                models.WorkspaceSetting.key == "graph_last_sync",
            )
            .first()
        )
        if setting:
            setting.value_json = json.dumps({"at": now_iso})
        else:
            db.add(models.WorkspaceSetting(
                workspace_id=ws_id, key="graph_last_sync",
                value_json=json.dumps({"at": now_iso}),
            ))
        db.commit()

        # Sync asset groups from Asset model hierarchy
        assets = (
            db.query(models.Asset)
            .filter(models.Asset.workspace_id == ws_id)
            .all()
        )
        # Build parent groups: top-level assets with children
        children_by_parent: dict[int, list[str]] = {}
        asset_by_id = {a.id: a for a in assets}
        for a in assets:
            if a.parent_id and a.parent_id in asset_by_id:
                children_by_parent.setdefault(a.parent_id, []).append(a.name)
        for parent_id, targets in children_by_parent.items():
            parent = asset_by_id[parent_id]
            neo.upsert_asset_group(
                workspace_id=ws_id,
                group_id=f"asset:{parent_id}",
                group_name=parent.name,
                targets=targets,
            )

        return {"ok": True, "nodes_synced": count, "findings_total": len(findings)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/shared-vulns")
def shared_vulns(
    user=Depends(require_role("admin", "analyst", "viewer")),
):
    """Vulnerabilities affecting the most assets — patch prioritisation."""
    neo = _get_neo4j()
    result = neo.query_shared_vulns(user["ws"]) if neo.available else None
    return result or []


@router.get("/blast-radius/{target:path}")
def blast_radius(
    target: str,
    user=Depends(require_role("admin", "analyst", "viewer")),
):
    """From a target, show all shared vulns and co-affected assets."""
    neo = _get_neo4j()
    result = neo.query_blast_radius(user["ws"], target) if neo.available else None
    return result or {"nodes": [], "links": [], "origin": target}


@router.get("/stats")
def graph_stats(
    user=Depends(require_role("admin", "analyst", "viewer")),
):
    """Aggregate graph statistics for dashboard widgets."""
    neo = _get_neo4j()
    result = neo.query_stats(user["ws"]) if neo.available else None
    return result or {"assets": 0, "vulns": 0, "by_severity": {}}


@router.get("/most-vulnerable")
def most_vulnerable(
    user=Depends(require_role("admin", "analyst", "viewer")),
):
    """Assets ranked by vulnerability count and max risk."""
    neo = _get_neo4j()
    result = neo.query_most_vulnerable_assets(user["ws"]) if neo.available else None
    return result or []