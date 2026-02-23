from neo4j import GraphDatabase
from app.core.config import settings

class Neo4jClient:
    def __init__(self):
        self.driver = GraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))

    def close(self):
        self.driver.close()

    def upsert_finding(self, workspace_id: int, asset: str, tech: str, cve: str, risk: float):
        with self.driver.session() as s:
            s.run("""
            MERGE (w:Workspace {id:$ws})
            MERGE (a:Asset {ws:$ws, name:$asset})
            MERGE (t:Technology {ws:$ws, name:$tech})
            MERGE (v:Vulnerability {ws:$ws, cve:$cve})
            MERGE (w)-[:OWNS]->(a)
            MERGE (a)-[:RUNS]->(t)
            MERGE (t)-[:HAS_VULN {risk:$risk}]->(v)
            """, ws=workspace_id, asset=asset, tech=tech, cve=cve, risk=risk)
