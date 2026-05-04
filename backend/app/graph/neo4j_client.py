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
            logger.info("Neo4j connected at %s", NEO4J_URI)
        except ImportError:
            logger.warning("neo4j driver not installed — graph features disabled")
            self._driver = None
        except Exception as e:
            logger.warning("Neo4j unavailable (%s) — graph features disabled", e)
            self._driver = None

    def upsert_finding(
        self,
        workspace_id: int,
        target: str,
        plugin_id: str,
        cve: str,
        risk_score: float,
    ) -> None:
        if not self._driver:
            return
        try:
            with self._driver.session() as session:
                session.run(
                    """
                    MERGE (a:Asset {target: $target, workspace: $ws})
                    MERGE (v:Vulnerability {cve: $cve})
                    MERGE (a)-[r:HAS_VULN {plugin: $plugin}]->(v)
                    SET r.risk = $risk, v.cve = $cve
                    """,
                    target=target,
                    ws=workspace_id,
                    cve=cve,
                    plugin=plugin_id,
                    risk=risk_score,
                )
        except Exception as e:
            logger.debug("Neo4j upsert error: %s", e)

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
                session.run(
                    """
                    MATCH (a:Asset {workspace: $ws})-[r:HAS_VULN]->(v:Vulnerability)
                    DELETE r
                    WITH a, v
                    WHERE NOT (v)<-[:HAS_VULN]-()
                    DELETE v
                    WITH a
                    DELETE a
                    """,
                    ws=workspace_id,
                )
        except Exception as e:
            logger.debug("Neo4j delete_workspace error: %s", e)

    def sync_from_findings(self, workspace_id: int, findings: list) -> int:
        """
        Rebuild graph from a list of finding dicts.
        Clears existing workspace data and re-inserts.
        Returns count of nodes created.
        """
        if not self._driver:
            return 0
        try:
            self.delete_workspace(workspace_id)
            count = 0
            for f in findings:
                cve = f.get("cve") or ""
                if not cve.startswith("CVE-"):
                    continue
                target = f.get("target", "")
                if not target:
                    continue
                self.upsert_finding(
                    workspace_id=workspace_id,
                    target=target,
                    plugin_id=f.get("plugin_id", ""),
                    cve=cve,
                    risk_score=f.get("risk_score", 0) or 0,
                )
                count += 1
            return count
        except Exception as e:
            logger.debug("Neo4j sync error: %s", e)
            return 0

    def close(self) -> None:
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass