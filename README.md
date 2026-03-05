# VulnScan Platform
<img width="1918" height="901" alt="image" src="https://github.com/user-attachments/assets/d92a962a-2d08-4389-acbc-8e65699b758e" />


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

List of Embed Plugins:
| No	| Plugins 	| Descriptions  	|
|:-:	|---	|---	|
|  1 	| port_scan  	| discovers open ports  	|
|  2 	| nmap_portscan  	| full port range + service banners  	|
|  3 	| http_fingerprint  	| HTTP headers  	|
|  4 	| banner_grabber  	| service version banners  	|
|  5 	| web_tech  	| CMS/framework detection  	|
|  6 	| favicon_hash  	| technology fingerprinting  	|
|  7 	| dir_crawl  	| directory/file discovery  	|
|  8 	| owasp_scanner  	| OWASP Top 10 active tests  	|
|  9 	| file_inclusion  	| LFI/RFI deep scan  	|
|  10 	| cpe_builder  	| builds CPE strings  	|
|  11	| nvd_match  	| CPE→CVE matching  	|
|  12 	| cms_match  	| CMS-specific CVEs  	|
|  13 	| cisa_kev  	| KEV cross-reference  	|
|  14 	| tls_basic  	| TLS version check  	|
|  15 	| ssh_inventory  	| SSH package collection  	|
|  16 	| local_security  	| distro advisory matching  	|
|  17 	| cve_packages  	| package→CVE matching  	|

---
Asset criticality describe:
|  Level 	|  Label 	|  Risk Multiplier 	|  Use For 	|
|:-:	|---	|:-:	|---	|
|  1 | Low (Development/Test) |  ×0.8 	| Dev servers, sandbox, staging  	|
|  2 | Normal (Standard systems)  	|  ×1.0 	| Internal tools, standard workstations  	|
|  3 | High (Business-critical)  	|  ×1.1 	| Production apps, internal APIs  	|
|  4 | Critical (Customer data / Revenue)  	|  ×1.2 	| Payment systems, databases with PII  	|
|  5 | Maximum (Regulatory / Life-safety)  	|  ×1.3 	| HIPAA/PCI systems, SCADA, public-facing auth  	|

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

## Export Report
|  Location |  Scope | Buttons |
|:-:	|---	|:-:	|
|  Panel header (top) | All hosts combined |  📄 CSV · 📊 HTML · 📋 PDF	| 
|  Inside each host expand | Single host only |  📄 CSV · 📊 HTML · 📋 PDF 	|

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







