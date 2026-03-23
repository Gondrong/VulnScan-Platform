<p align="center">
  <img src="https://github.com/user-attachments/assets/d92a962a-2d08-4389-acbc-8e65699b758e" alt="VulnScan Platform" width="100%" />
</p>

<h1 align="center">VulnScan Platform</h1>

<p align="center">
  <strong>Enterprise Risk-Based Vulnerability Management</strong><br>
  Plugin-driven scanner &bull; Multi-source CVE enrichment &bull; Compliance mapping &bull; Attack graph modeling
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v2.1.1-blue?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/Neo4j-4581C3?style=flat-square&logo=neo4j&logoColor=white" alt="Neo4j" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

---

## Overview

VulnScan Platform is a self-hosted vulnerability management system designed for security teams. It combines automated scanning, multi-source threat intelligence enrichment, risk-based prioritization, and compliance mapping into a single platform.

**Key Capabilities:**
- **24 built-in scanner plugins** with dependency-aware execution pipeline
- **Multi-source CVE enrichment** from NVD, CVE.org, CISA KEV, EPSS, and CMS-specific feeds
- **Risk scoring engine** with CVSS, exploit likelihood, asset criticality, and confidence weighting
- **Compliance mapping** to NIST 800-53, PCI DSS v4, CIS v8, and ISO 27001 controls
- **RBAC + multi-tenant isolation** with workspace-scoped access control
- **Neo4j attack graph modeling** for asset-vulnerability relationship visualization
- **Security Intelligence Browser** for exploring all threat intelligence datasets from the UI

---

## Architecture

```
                     +------------------+
                     |   Web Browser    |
                     |   (port 5173)    |
                     +--------+---------+
                              |
                     +--------+---------+
                     |   FastAPI (8888)  |
                     |   REST API + Auth |
                     +--+-----+------+--+
                        |     |      |
              +---------+  +--+--+  ++----------+
              |            |     |              |
        +-----+----+ +----+---+ +-----+----+ +-+--------+
        |PostgreSQL | | Redis  | |  Neo4j   | |RQ Worker |
        | (5432)    | | (6379) | | (7474)   | | (scans)  |
        +-----------+ +--------+ +----------+ +----------+
```

---

## Scanner Plugins

VulnScan uses a plugin architecture where each plugin declares its dependencies, inputs, and outputs. The engine resolves execution order via topological sort.

| # | Plugin | Category | Description |
|:-:|--------|----------|-------------|
| 1 | `port_scan` | Discovery | TCP port discovery (common ports) |
| 2 | `nmap_portscan` | Discovery | Full port range scan with service detection |
| 3 | `dns_enum` | Discovery | DNS enumeration and subdomain detection |
| 4 | `banner_grabber` | Fingerprint | Multi-protocol service version banners |
| 5 | `http_fingerprint` | Fingerprint | HTTP headers, status codes, and server identification |
| 6 | `web_tech` | Fingerprint | CMS and framework detection (Wappalyzer-style) |
| 7 | `favicon_hash` | Fingerprint | Technology identification via favicon hashing |
| 8 | `deep_fingerprint` | Fingerprint | Technology-specific version detection (REST APIs, changelogs, error pages) |
| 9 | `tls_basic` | Fingerprint | TLS version and certificate analysis |
| 10 | `dir_crawl` | Active Test | Directory and file discovery |
| 11 | `owasp_scanner` | Active Test | OWASP Top 10 active testing (13 categories) |
| 12 | `file_inclusion` | Active Test | LFI/RFI deep scan |
| 13 | `endpoint_prober` | Active Test | Safe HTTP endpoint probes for known CVE patterns |
| 14 | `ssh_inventory` | Authenticated | SSH package inventory collection |
| 15 | `ssh_audit` | Authenticated | SSH configuration and algorithm audit |
| 16 | `local_security` | Authenticated | Distribution security advisory matching |
| 17 | `db_auth_check` | Authenticated | Database authentication audit |
| 18 | `smb_check` | Authenticated | SMB/CIFS security assessment |
| 19 | `cpe_builder` | Enrichment | CPE string generation from detected technologies |
| 20 | `nvd_match` | Enrichment | CPE-to-CVE matching against NVD database |
| 21 | `cve_packages` | Enrichment | Package-to-CVE matching with distro-patch awareness |
| 22 | `cms_match` | Enrichment | CMS-specific CVE matching |
| 23 | `cisa_kev` | Enrichment | CISA Known Exploited Vulnerabilities cross-reference |
| 24 | `cve_verifier` | Enrichment | Cross-references CVE/CWE with OWASP results for confidence adjustment |

---

## Scan Pipeline

```
 1. Port Discovery          ──→  Identify open TCP ports
 2. Service Fingerprinting  ──→  Banner grab + HTTP headers + web tech detection
 3. Deep Fingerprinting     ──→  Technology-specific version extraction
 4. Active Testing          ──→  OWASP tests, directory crawl, endpoint probing
 5. Authenticated Checks    ──→  SSH inventory, package enumeration (if credentials provided)
 6. CPE Construction        ──→  Build CPE identifiers from detected software
 7. CVE Matching            ──→  NVD + CMS + package-level CVE correlation
 8. Verification            ──→  Cross-reference results, distro-patch detection
 9. KEV Prioritization      ──→  Flag actively exploited vulnerabilities
10. Risk Scoring            ──→  CVSS + exploit weight + asset criticality + confidence
11. SLA Assignment          ──→  Remediation deadlines based on severity
12. Compliance Mapping      ──→  Map to NIST 800-53, PCI DSS, CIS, ISO 27001
13. Graph Modeling          ──→  Push relationships to Neo4j
```

---

## Threat Intelligence Datasets

VulnScan enriches scan results using six threat intelligence feeds that can be refreshed directly from the UI:

| Dataset | Source | Description |
|---------|--------|-------------|
| **NVD CPE/CVE** | NIST NVD API | CVE entries with CVSS scores, affected products, and references |
| **CVE.org** | CVE.org API | Multi-source CVSS from CNA and ADP providers |
| **CISA KEV** | CISA KEV Feed | Known Exploited Vulnerabilities with remediation deadlines |
| **EPSS** | FIRST EPSS | Exploit Prediction Scoring with probability percentiles |
| **CMS CVE Map** | Generated | CMS-specific vulnerability mappings (WordPress, Drupal, Joomla, etc.) |
| **Compliance Map** | Generated | Control mappings for NIST 800-53, PCI DSS v4, CIS v8, ISO 27001 |

---

## Risk Scoring

```
Risk = (CVSS x exploit_weight) + KEV_bonus + asset_criticality x confidence
```

### Asset Criticality Levels

| Level | Label | Multiplier | Use Case |
|:-----:|-------|:----------:|----------|
| 1 | Low (Development/Test) | x0.8 | Dev servers, sandbox, staging |
| 2 | Normal (Standard) | x1.0 | Internal tools, standard workstations |
| 3 | High (Business-critical) | x1.1 | Production apps, internal APIs |
| 4 | Critical (Customer data) | x1.2 | Payment systems, databases with PII |
| 5 | Maximum (Regulatory) | x1.3 | HIPAA/PCI systems, SCADA, public-facing auth |

### SLA Targets

| Severity | Remediation Deadline |
|:--------:|:--------------------:|
| Critical | 7 days |
| High | 14 days |
| Medium | 30 days |
| Low | 60 days |

---

## Requirements

- Docker
- Docker Compose

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Gondrong/VulnScan-Platform.git
cd VulnScan-Platform

# 2. Run the bootstrap script
./bootstrap.sh

# 3. Access the platform
# Open http://<YOUR_IP>:5173 in your browser
```

**Default credentials:**

| Field | Value |
|-------|-------|
| Username | `admin@local` |
| Password | `admin123` |

> **Note:** Change the default credentials after first login.

---

## Dataset Management

### Option 1: Refresh from UI (Recommended)

Navigate to **Datasets** in the sidebar and click **Refresh All**. The platform will fetch the latest data from NVD, CISA, EPSS, and CVE.org automatically.

### Option 2: Manual Scripts

```bash
# Fetch datasets from external sources
./scripts/fast_update_datasets.py

# Upload datasets to the platform
./scripts/upload_datasets.sh
```

### Option 3: Manual Upload

Place JSON files in `data/cve/` and upload via the Datasets page.

**Supported dataset kinds:** `nvd_cpe_cve`, `cisa_kev`, `epss`, `cms_cve_map`, `compliance_map`, `cvedetails_cvss`

---

## Export Reports

| Location | Scope | Formats |
|----------|-------|---------|
| Panel header (top) | All hosts combined | CSV, HTML, PDF |
| Per-host section | Single host | CSV, HTML, PDF |
| Bulk selection (checkboxes) | Selected hosts | CSV, HTML, PDF |

---

## Neo4j Graph Queries

```cypher
-- View all assets and their vulnerabilities
MATCH (a:Asset)-[:USES]->()-[:HAS]->(v:Vulnerability)
RETURN a, v

-- Find critical vulnerabilities with KEV flag
MATCH (v:Vulnerability)
WHERE v.severity = 'CRITICAL' AND v.kev = true
RETURN v.cve_id, v.description
```

---

## Changelog

### v2.1.1 (2026-03-23)

**New Features:**
- Security Intelligence Browser with 6 dataset views (NVD, CVE, CISA-KEV, CMS-CVE, EPSS, Compliance) with search, pagination, and expandable detail rows
- One-click dataset refresh from the UI (fetches from NVD, CISA, EPSS, CVE.org)
- Per-host bulk report export via checkboxes in Vulnerabilities by Host
- Scan profile editing (Edit, Clone, Delete) via the UI
- Pagination for Job History (10/page) and Scheduled Scans (5/page)

**Improvements:**
- OWASP scanner false positive reduction with content validators and soft-404 detection
- External scan timeout handling for firewalled targets
- Responsive table layout for smaller screens
- 7 new scanner plugins (dns_enum, deep_fingerprint, endpoint_prober, cve_verifier, ssh_audit, db_auth_check, smb_check)

### v2.1.0 (2026-03-14)

**Scanning Accuracy:**
- Distro-patch detection for Debian/Ubuntu/RHEL backported security fixes
- Expanded CPE mapping (~120 to ~190 entries)
- Active CVE verification via CWE-to-OWASP cross-reference
- Safe HTTP endpoint probes for known CVE patterns
- Technology-specific deep fingerprinting

**Validation States:**
- `validated` — Active test confirmed (uncapped confidence)
- `provisional` — Version-only match (capped at 0.35)
- `likely_patched` — Distro backport detected (capped at 0.10)
- `likely_not_exploitable` — OWASP tested, nothing found (capped at 0.15)
- `probe_negative` — Endpoint probe negative (capped at 0.20)

### v1.0.2 (Initial Release)

- Plugin-based scanner engine with 17 plugins
- CVE matching via NVD CPE and CMS feeds
- CISA KEV prioritization
- Risk scoring with CVSS, exploit weight, and asset criticality
- SLA tracking and compliance mapping
- Neo4j attack graph modeling
- Multi-tenant RBAC with workspace isolation

---

## Roadmap

- [ ] ML-based anomaly scoring
- [ ] Risk heatmap visualization
- [ ] Attack path traversal scoring
- [ ] Multi-tenant RBAC hardening
- [ ] Scheduled auto-refresh for threat intelligence feeds
- [ ] LDAP/SSO integration

---

## License

This project is licensed under the MIT License.
