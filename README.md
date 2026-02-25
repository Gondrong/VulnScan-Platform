# VulnScan Platform

Plugin-based internal vulnerability management platform with:
- Web UI + API (FastAPI + React)
- RBAC + multi-tenant isolation (workspace scoped)
- Credentials (SSH) + Datasets upload (offline feeds)
- Scanning plugins: port scan, multi-protocol banner grab, HTTP fingerprint, web tech detect, favicon hash
- Enrichment: CPE builder, NVD CPE→CVE match, CMS CVE map, CISA KEV prioritization
- Authenticated: SSH inventory + package CVE match (OSV/OVAL-slim style)
- Risk modules: CVSS severity, risk score, SLA, compliance mapping, Neo4j graph modeling (minimal wiring)

Enterprise-grade Risk-Based Vulnerability Management Platform.

Features:
- Plugin-based scanner engine
- Web fingerprint (Wappalyzer-like)
- Multi-protocol banner grabbing
- SSH authenticated inventory
- CVE matching (OSV / NVD CPE)
- CISA KEV prioritization
- Favicon hash fingerprinting
- CMS CVE mapping
- CVSS scoring
- Risk scoring engine
- SLA tracking + MTTR
- Compliance mapping (ISO/NIST/PCI)
- Neo4j attack graph modeling

---

## Requirements

- Docker
- Docker Compose

---

## Run

docker compose up -d --build

Backend:
http://localhost:8080/docs

Neo4j:
http://localhost:7474
user: neo4j
pass: password

---

## Upload Datasets

Place JSON files inside:
data/cve/

Supported dataset kinds:
- osv
- nvd_cpe_cve
- cisa_kev
- favicon_hash_map
- cms_cve_map
- compliance_map

---

## Scan Flow

1. Detect open ports
2. Grab service banners
3. Detect web technologies
4. Build CPE candidates
5. Match CVE (OSV + NVD)
6. Prioritize KEV
7. Compute CVSS + Risk
8. Assign SLA
9. Map Compliance
10. Push to Neo4j attack graph

---

## Risk Formula

Risk = (CVSS × exploit_weight)
     + KEV_bonus
     + asset_criticality
     × confidence

---

## SLA Rules

Critical: 7 days
High: 14 days
Medium: 30 days
Low: 60 days

---

## Graph Query Example

MATCH (a:Asset)-[:USES]->()-[:HAS]->(v)
RETURN a,v

---

## Status

This platform implements:
- Scanner
- Risk engine
- Compliance mapping
- Attack graph modeling
- SLA tracking

Future:
- ML anomaly scoring
- Risk heatmap
- Attack path traversal scoring
- Multi-tenant RBAC hardening
