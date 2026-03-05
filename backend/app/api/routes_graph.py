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

logger = logging.getLogger("vulnscan.graph")

router = APIRouter(prefix="/graph", tags=["graph"])


def _neo4j_graph(ws_id: int) -> dict | None:
    """Try to fetch the attack graph from Neo4j."""
    try:
        from app.graph.neo4j_client import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()

        nodes = []
        links = []
        node_ids = set()

        with driver.session() as session:
            result = session.run(
                """
                MATCH (a:Asset {workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                RETURN a.target AS target, v.cve AS cve, r.risk AS risk, r.plugin AS plugin
                ORDER BY r.risk DESC
                LIMIT 200
                """,
                ws=ws_id,
            )

            for record in result:
                target = record["target"]
                cve = record["cve"]
                risk = record["risk"] or 0
                plugin = record["plugin"] or ""

                if target not in node_ids:
                    nodes.append({
                        "id": target, "label": target,
                        "type": "asset", "size": 18,
                    })
                    node_ids.add(target)

                if cve not in node_ids:
                    sev = (
                        "critical" if risk >= 9
                        else "high" if risk >= 7
                        else "medium" if risk >= 4
                        else "low" if risk > 0
                        else "info"
                    )
                    nodes.append({
                        "id": cve, "label": cve, "type": "vuln",
                        "severity": sev, "risk": round(risk, 1),
                        "size": max(6, min(16, risk * 1.5)),
                    })
                    node_ids.add(cve)

                links.append({
                    "source": target, "target": cve,
                    "risk": round(risk, 1), "plugin": plugin,
                })

        driver.close()
        return {"nodes": nodes, "links": links, "source": "neo4j"}

    except Exception as e:
        logger.debug("Neo4j graph query failed: %s", e)
        return None


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
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Rebuild Neo4j graph from current PostgreSQL findings."""
    ws_id = user["ws"]
    try:
        from app.graph.neo4j_client import Neo4jClient
        neo = Neo4jClient()
        findings = (
            db.query(models.Finding)
            .filter(models.Finding.workspace_id == ws_id)
            .all()
        )
        finding_dicts = []
        for f in findings:
            cve = None
            if f.evidence and "CVE-" in f.evidence:
                cve_match = re.search(r"(CVE-\d{4}-\d+)", f.evidence)
                if cve_match:
                    cve = cve_match.group(1)
            if cve:
                finding_dicts.append({
                    "target": f.target,
                    "cve": cve,
                    "plugin_id": f.plugin_id,
                    "risk_score": f.risk_score,
                })
        count = neo.sync_from_findings(ws_id, finding_dicts)
        neo.close()
        return {"ok": True, "nodes_synced": count, "findings_total": len(findings)}
    except Exception as e:
        return {"ok": False, "error": str(e)}