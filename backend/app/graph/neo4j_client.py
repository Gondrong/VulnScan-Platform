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

    def close(self) -> None:
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
