"""
Neo4j graph client for storing asset/vulnerability relationships.
The backend treats Neo4j as best-effort — if it's unavailable, scans still work.
"""
import logging
import os

logger = logging.getLogger("vulnscan.graph")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")


class Neo4jClient:
    def __init__(self):
        try:
            from neo4j import GraphDatabase  # type: ignore
            self._driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
            )
            # Verify connectivity
            self._driver.verify_connectivity()
            self._ensure_indexes()
            logger.info("Neo4j connected at %s", NEO4J_URI)
        except ImportError:
            logger.warning("neo4j driver not installed — graph features disabled")
            self._driver = None
        except Exception as e:
            logger.warning("Neo4j unavailable (%s) — graph features disabled", e)
            self._driver = None

    def _ensure_indexes(self) -> None:
        """Create indexes and constraints if they don't already exist."""
        if not self._driver:
            return
        statements = [
            "CREATE INDEX asset_target IF NOT EXISTS FOR (a:Asset) ON (a.target)",
            "CREATE INDEX asset_workspace IF NOT EXISTS FOR (a:Asset) ON (a.workspace)",
            "CREATE INDEX vuln_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_id)",
            "CREATE INDEX vuln_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve)",
            "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX plugin_id IF NOT EXISTS FOR (p:Plugin) ON (p.plugin_id)",
            "CREATE INDEX compliance_id IF NOT EXISTS FOR (c:Compliance) ON (c.ctrl_id)",
            "CREATE INDEX assetgroup_id IF NOT EXISTS FOR (g:AssetGroup) ON (g.group_id)",
        ]
        try:
            with self._driver.session() as session:
                for stmt in statements:
                    session.run(stmt)
            logger.info("Neo4j indexes ensured")
        except Exception as e:
            logger.warning("Neo4j index creation failed: %s", e)

    def upsert_finding(
        self,
        workspace_id: int,
        target: str,
        plugin_id: str,
        cve: str | None = None,
        risk_score: float = 0,
        fingerprint: str = "",
        title: str = "",
        severity: str = "info",
        compliance_ids: list[str] | None = None,
    ) -> None:
        if not self._driver:
            return
        # Use CVE as the vuln identifier when available, else fingerprint
        vuln_id = cve if cve else fingerprint
        if not vuln_id:
            return
        label = cve if cve else (title[:60] if title else fingerprint)
        try:
            with self._driver.session() as session:
                # Core: Asset -> Vulnerability + Plugin -> Vulnerability
                session.run(
                    """
                    MERGE (a:Asset {target: $target, workspace: $ws})
                    MERGE (v:Vulnerability {vuln_id: $vuln_id})
                    ON CREATE SET v.cve = $cve, v.title = $title,
                                  v.severity = $severity, v.label = $label
                    ON MATCH SET  v.severity = $severity, v.title = $title,
                                  v.label = $label
                    MERGE (a)-[r:HAS_VULN]->(v)
                    SET r.risk = $risk, r.plugin = $plugin
                    WITH v
                    MERGE (p:Plugin {plugin_id: $plugin})
                    MERGE (p)-[:DETECTED]->(v)
                    """,
                    target=target,
                    ws=workspace_id,
                    vuln_id=vuln_id,
                    cve=cve or "",
                    plugin=plugin_id,
                    risk=risk_score,
                    title=title,
                    severity=severity,
                    label=label,
                )
                # Compliance relationships
                if compliance_ids:
                    for ctrl in compliance_ids:
                        session.run(
                            """
                            MERGE (v:Vulnerability {vuln_id: $vuln_id})
                            MERGE (c:Compliance {ctrl_id: $ctrl})
                            MERGE (v)-[:VIOLATES]->(c)
                            """,
                            vuln_id=vuln_id,
                            ctrl=ctrl,
                        )
        except Exception as e:
            logger.debug("Neo4j upsert error: %s", e)

    def upsert_asset_group(
        self,
        workspace_id: int,
        group_id: str,
        group_name: str,
        targets: list[str],
    ) -> None:
        """Create an AssetGroup node linked to its Asset nodes."""
        if not self._driver:
            return
        try:
            with self._driver.session() as session:
                session.run(
                    """
                    MERGE (g:AssetGroup {group_id: $gid, workspace: $ws})
                    SET g.name = $name
                    """,
                    gid=group_id, ws=workspace_id, name=group_name,
                )
                for t in targets:
                    session.run(
                        """
                        MATCH (g:AssetGroup {group_id: $gid, workspace: $ws})
                        MERGE (a:Asset {target: $target, workspace: $ws})
                        MERGE (g)-[:CONTAINS]->(a)
                        """,
                        gid=group_id, ws=workspace_id, target=t,
                    )
        except Exception as e:
            logger.debug("Neo4j upsert_asset_group error: %s", e)

    def delete_target(self, workspace_id: int, target: str) -> None:
        """Remove all nodes and relationships for a target."""
        if not self._driver:
            return
        try:
            with self._driver.session() as session:
                # Delete relationships and orphaned vulnerability nodes
                session.run(
                    """
                    MATCH (a:Asset {target: $target, workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                    DELETE r
                    WITH a, v
                    WHERE NOT (v)<-[:HAS_VULN]-()
                    DELETE v
                    WITH a
                    DELETE a
                    """,
                    target=target,
                    ws=workspace_id,
                )
        except Exception as e:
            logger.debug("Neo4j delete_target error: %s", e)

    def delete_workspace(self, workspace_id: int) -> None:
        """Remove all graph data for a workspace."""
        if not self._driver:
            return
        try:
            with self._driver.session() as session:
                # Remove asset-group relationships
                session.run(
                    "MATCH (g:AssetGroup {workspace: $ws})-[r]-() DELETE r, g",
                    ws=workspace_id,
                )
                # Remove core asset->vuln graph and orphans
                session.run(
                    """
                    MATCH (a:Asset {workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                    DELETE r
                    WITH a, v
                    WHERE NOT (v)<-[:HAS_VULN]-()
                    OPTIONAL MATCH (v)-[rc:VIOLATES]->(c:Compliance)
                    DELETE rc
                    WITH v, c
                    WHERE c IS NOT NULL AND NOT ()<-[:VIOLATES]-(c)
                    DELETE c
                    """,
                    ws=workspace_id,
                )
                # Delete orphaned vulns and their plugin links
                session.run(
                    """
                    MATCH (v:Vulnerability)
                    WHERE NOT ()-[:HAS_VULN]->(v)
                    OPTIONAL MATCH (p:Plugin)-[rd:DETECTED]->(v)
                    DELETE rd, v
                    WITH p
                    WHERE p IS NOT NULL AND NOT (p)-[:DETECTED]->()
                    DELETE p
                    """,
                )
                # Finally remove asset nodes
                session.run(
                    "MATCH (a:Asset {workspace: $ws}) DELETE a",
                    ws=workspace_id,
                )
        except Exception as e:
            logger.debug("Neo4j delete_workspace error: %s", e)

    def sync_from_findings(
        self, workspace_id: int, findings: list, full: bool = True,
    ) -> int:
        """
        Sync findings into the graph.

        full=True  (default): clears workspace data first, then re-inserts everything.
        full=False: incremental — upserts only the supplied findings without clearing.
        Returns count of nodes upserted.
        """
        if not self._driver:
            return 0
        try:
            if full:
                self.delete_workspace(workspace_id)
            count = 0
            for f in findings:
                target = f.get("target", "")
                if not target:
                    continue
                cve = f.get("cve") or None
                fingerprint = f.get("fingerprint") or ""
                # Need at least a CVE or fingerprint to create a vuln node
                if not cve and not fingerprint:
                    continue
                self.upsert_finding(
                    workspace_id=workspace_id,
                    target=target,
                    plugin_id=f.get("plugin_id", ""),
                    cve=cve,
                    risk_score=f.get("risk_score", 0) or 0,
                    fingerprint=fingerprint,
                    title=f.get("title", ""),
                    severity=f.get("severity", "info"),
                    compliance_ids=f.get("compliance_ids"),
                )
                count += 1
            return count
        except Exception as e:
            logger.debug("Neo4j sync error: %s", e)
            return 0

    @property
    def available(self) -> bool:
        return self._driver is not None

    def query_attack_map(self, workspace_id: int, limit: int = 200) -> dict | None:
        """Return nodes + links for the D3 force graph."""
        if not self._driver:
            return None
        try:
            nodes = []
            links = []
            node_ids: set[str] = set()

            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (a:Asset {workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                    RETURN a.target AS target,
                           v.vuln_id AS vuln_id, v.cve AS cve,
                           v.label AS vlabel, v.severity AS sev,
                           r.risk AS risk, r.plugin AS plugin
                    ORDER BY r.risk DESC
                    LIMIT $lim
                    """,
                    ws=workspace_id,
                    lim=limit,
                )

                for record in result:
                    target = record["target"]
                    vuln_id = record["vuln_id"]
                    cve = record["cve"] or ""
                    vlabel = record["vlabel"] or vuln_id
                    risk = record["risk"] or 0
                    plugin = record["plugin"] or ""
                    sev = record["sev"] or ""

                    if target not in node_ids:
                        nodes.append({
                            "id": target, "label": target,
                            "type": "asset", "size": 18,
                        })
                        node_ids.add(target)

                    if vuln_id not in node_ids:
                        # Use stored severity if available, else derive from risk
                        if not sev:
                            sev = (
                                "critical" if risk >= 9
                                else "high" if risk >= 7
                                else "medium" if risk >= 4
                                else "low" if risk > 0
                                else "info"
                            )
                        nodes.append({
                            "id": vuln_id, "label": vlabel, "type": "vuln",
                            "severity": sev, "risk": round(risk, 1),
                            "cve": cve,
                            "size": max(6, min(16, risk * 1.5)),
                        })
                        node_ids.add(vuln_id)

                    links.append({
                        "source": target, "target": vuln_id,
                        "risk": round(risk, 1), "plugin": plugin,
                    })

            # Fetch Plugin -> Vulnerability edges
            p_result = session.run(
                """
                MATCH (p:Plugin)-[:DETECTED]->(v:Vulnerability)
                WHERE v.vuln_id IN $vids
                RETURN p.plugin_id AS pid, v.vuln_id AS vid
                """,
                vids=list(node_ids),
            )
            for rec in p_result:
                pid = f"plugin::{rec['pid']}"
                if pid not in node_ids:
                    nodes.append({
                        "id": pid, "label": rec["pid"],
                        "type": "plugin", "size": 10,
                    })
                    node_ids.add(pid)
                links.append({"source": pid, "target": rec["vid"], "type": "detected"})

            # Fetch Vulnerability -> Compliance edges
            c_result = session.run(
                """
                MATCH (v:Vulnerability)-[:VIOLATES]->(c:Compliance)
                WHERE v.vuln_id IN $vids
                RETURN v.vuln_id AS vid, c.ctrl_id AS ctrl
                """,
                vids=list(node_ids),
            )
            for rec in c_result:
                cid = f"ctrl::{rec['ctrl']}"
                if cid not in node_ids:
                    nodes.append({
                        "id": cid, "label": rec["ctrl"],
                        "type": "compliance", "size": 10,
                    })
                    node_ids.add(cid)
                links.append({"source": rec["vid"], "target": cid, "type": "violates"})

            # Fetch AssetGroup -> Asset edges
            g_result = session.run(
                """
                MATCH (g:AssetGroup {workspace: $ws})-[:CONTAINS]->(a:Asset {workspace: $ws})
                RETURN g.group_id AS gid, g.name AS gname, a.target AS target
                """,
                ws=workspace_id,
            )
            for rec in g_result:
                gid = f"group::{rec['gid']}"
                if gid not in node_ids:
                    nodes.append({
                        "id": gid, "label": rec["gname"] or rec["gid"],
                        "type": "group", "size": 22,
                    })
                    node_ids.add(gid)
                if rec["target"] in node_ids:
                    links.append({"source": gid, "target": rec["target"], "type": "contains"})

            return {"nodes": nodes, "links": links, "source": "neo4j"}
        except Exception as e:
            logger.debug("Neo4j attack-map query error: %s", e)
            return None

    # ── Analytical queries ──────────────────────────────────────────

    def query_shared_vulns(self, workspace_id: int, limit: int = 20) -> list | None:
        """Vulnerabilities shared across the most assets — patch priority."""
        if not self._driver:
            return None
        try:
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (a:Asset {workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                    WITH v, count(DISTINCT a) AS asset_count, max(r.risk) AS max_risk,
                         collect(DISTINCT a.target) AS targets
                    WHERE asset_count > 1
                    RETURN v.vuln_id AS vuln_id, v.cve AS cve, v.label AS label,
                           v.severity AS severity, asset_count, max_risk, targets
                    ORDER BY asset_count DESC, max_risk DESC
                    LIMIT $lim
                    """,
                    ws=workspace_id, lim=limit,
                )
                return [
                    {
                        "vuln_id": r["vuln_id"], "cve": r["cve"] or "",
                        "label": r["label"], "severity": r["severity"],
                        "asset_count": r["asset_count"],
                        "max_risk": round(r["max_risk"] or 0, 1),
                        "targets": r["targets"][:10],  # cap for payload size
                    }
                    for r in result
                ]
        except Exception as e:
            logger.debug("Neo4j shared_vulns error: %s", e)
            return None

    def query_blast_radius(
        self, workspace_id: int, target: str, depth: int = 2,
    ) -> dict | None:
        """From a given asset, find all vulns and other assets sharing those vulns."""
        if not self._driver:
            return None
        try:
            nodes = []
            links = []
            node_ids: set[str] = set()
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (origin:Asset {target: $target, workspace: $ws})
                          -[:HAS_VULN]->(v:Vulnerability)
                          <-[r:HAS_VULN]-(other:Asset {workspace: $ws})
                    RETURN origin.target AS origin, v.vuln_id AS vuln_id,
                           v.label AS vlabel, v.severity AS sev,
                           r.risk AS risk, other.target AS other_target
                    ORDER BY r.risk DESC
                    LIMIT 200
                    """,
                    target=target, ws=workspace_id,
                )
                # Always add the origin
                nodes.append({"id": target, "label": target, "type": "asset", "size": 22, "origin": True})
                node_ids.add(target)

                for rec in result:
                    vid = rec["vuln_id"]
                    other = rec["other_target"]
                    risk = rec["risk"] or 0
                    sev = rec["sev"] or "info"

                    if vid not in node_ids:
                        nodes.append({
                            "id": vid, "label": rec["vlabel"] or vid,
                            "type": "vuln", "severity": sev,
                            "risk": round(risk, 1),
                            "size": max(6, min(14, risk * 1.3)),
                        })
                        node_ids.add(vid)
                    if target not in node_ids:
                        node_ids.add(target)
                    if other and other not in node_ids:
                        nodes.append({"id": other, "label": other, "type": "asset", "size": 14})
                        node_ids.add(other)

                    links.append({"source": target, "target": vid, "risk": round(risk, 1)})
                    if other and other != target:
                        links.append({"source": other, "target": vid, "risk": round(risk, 1)})

            return {"nodes": nodes, "links": links, "origin": target}
        except Exception as e:
            logger.debug("Neo4j blast_radius error: %s", e)
            return None

    def query_stats(self, workspace_id: int) -> dict | None:
        """Aggregate counts for dashboard widgets."""
        if not self._driver:
            return None
        try:
            with self._driver.session() as session:
                r = session.run(
                    """
                    MATCH (a:Asset {workspace: $ws})
                    OPTIONAL MATCH (a)-[:HAS_VULN]->(v:Vulnerability)
                    WITH count(DISTINCT a) AS assets, count(DISTINCT v) AS vulns,
                         collect(v.severity) AS sevs, collect(v.vuln_id) AS vids
                    RETURN assets, vulns,
                           size([s IN sevs WHERE s = 'critical']) AS critical,
                           size([s IN sevs WHERE s = 'high']) AS high,
                           size([s IN sevs WHERE s = 'medium']) AS medium,
                           size([s IN sevs WHERE s = 'low']) AS low,
                           size([s IN sevs WHERE s = 'info']) AS info
                    """,
                    ws=workspace_id,
                ).single()
                if not r:
                    return {"assets": 0, "vulns": 0, "by_severity": {}}
                return {
                    "assets": r["assets"],
                    "vulns": r["vulns"],
                    "by_severity": {
                        "critical": r["critical"], "high": r["high"],
                        "medium": r["medium"], "low": r["low"], "info": r["info"],
                    },
                }
        except Exception as e:
            logger.debug("Neo4j stats error: %s", e)
            return None

    def query_most_vulnerable_assets(
        self, workspace_id: int, limit: int = 20,
    ) -> list | None:
        """Assets ranked by vulnerability count and max risk."""
        if not self._driver:
            return None
        try:
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (a:Asset {workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                    WITH a.target AS target, count(v) AS vuln_count,
                         max(r.risk) AS max_risk,
                         size([v2 IN collect(v) WHERE v2.severity = 'critical']) AS crits
                    RETURN target, vuln_count, max_risk, crits
                    ORDER BY crits DESC, max_risk DESC, vuln_count DESC
                    LIMIT $lim
                    """,
                    ws=workspace_id, lim=limit,
                )
                return [
                    {
                        "target": r["target"],
                        "vuln_count": r["vuln_count"],
                        "max_risk": round(r["max_risk"] or 0, 1),
                        "critical_count": r["crits"],
                    }
                    for r in result
                ]
        except Exception as e:
            logger.debug("Neo4j most_vulnerable error: %s", e)
            return None

    def close(self) -> None:
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass