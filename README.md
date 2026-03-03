# VulnScan Platform
<img width="1901" height="908" alt="image" src="https://github.com/user-attachments/assets/1acb24ed-59cd-43c9-a531-17952b647bae" />
<img width="1581" height="831" alt="image" src="https://github.com/user-attachments/assets/732a62ed-dd61-4a69-a3b8-e2b2dac513a3" />

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

and then you can access platform with this port

Platform:
**http://[YOUR_IP]:5173**

after you access and login the dashboard with:
- Username: admin@local
- Password: admin123

---

## Upload Datasets

**First**, you must running this script to update/fetch datasets.
<img width="812" height="728" alt="image" src="https://github.com/user-attachments/assets/18d527ee-7860-415b-93cc-6c0f43e40c14" />

**Second**, after that you can run this script to upload datasets into platform.
<img width="857" height="248" alt="image" src="https://github.com/user-attachments/assets/69612b22-26ff-407b-b583-b7588786051e" />

Or you can upload your datasets and place JSON files inside:
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




