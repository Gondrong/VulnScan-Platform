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
To running this docker or platform you can run this command:
**┌──(root㉿kali)-[/home/kali/VulnScan Platform]**
**└─# ./bootstrap.sh**

Backend:
http://localhost:8080/docs

Frontend:
http://localhost:5173

**First**, you must running this script to update/fetch datasets.
**┌──(root㉿kali)-[/home/kali/VulnScan Platform]**
**└─#** **./scripts/update_datasets.sh** 
[update] Fetching NVD CVEs from API (last 120 days)...
[update] Date range: 2025-11-02T08:05:31.000 -> 2026-03-02T08:05:31.000

**Second**, after that you can run this script to upload datasets into platform.
**┌──(root㉿kali)-[/home/kali/VulnScan Platform]**
**└─# ./scripts/upload_datasets.sh** 
[upload] Logging in to http://localhost:8080 as admin@local...
[upload] Authenticated ✓
[upload] Uploading nvd_cpe_cve (nvd_auto) -> nvd_cpe_cve.json [9.1M]
[upload]   ✓ nvd_cpe_cve uploaded: {"dataset_id":11,"path":"/data/cve/nvd_cpe_cve_e664b387.json"}
[upload] Uploading cisa_kev (kev_auto) -> cisa_kev.json [764K]
[upload]   ✓ cisa_kev uploaded: {"dataset_id":12,"path":"/data/cve/cisa_kev_56d7fe68.json"}
[upload] Uploading epss (epss_auto) -> epss.json [27M]
[upload]   ✓ epss uploaded: {"dataset_id":13,"path":"/data/cve/epss_e1180839.json"}
[upload] Uploading cms_cve_map (cms_auto) -> cms_cve_map.json [60K]
[upload]   ✓ cms_cve_map uploaded: {"dataset_id":14,"path":"/data/cve/cms_cve_map_8c951641.json"}
[upload] Uploading compliance_map (compliance_auto) -> compliance_map.json [8.0K]
[upload]   ✓ compliance_map uploaded: {"dataset_id":15,"path":"/data/cve/compliance_map_a72dba92.json"}
[upload] Upload done ✅

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

