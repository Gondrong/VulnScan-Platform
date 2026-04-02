<p align="center">
  <img width="1918" height="901" alt="VulnScan Platform" src="https://github.com/user-attachments/assets/d92a962a-2d08-4389-acbc-8e65699b758e" />
</p>

<h1 align="center">VulnScan Platform</h1>
<p align="center">
  <strong>Enterprise Risk-Based Vulnerability Management Platform</strong>
</p>
<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#scanner-plugins">Plugins</a> &bull;
  <a href="#ai-deep-analysis">AI Analysis</a> &bull;
  <a href="#changelog">Changelog</a> &bull;
  <a href="#license">License</a>
</p>

---

## Overview

VulnScan is a self-hosted vulnerability management platform built for security teams. It combines automated scanning with multi-provider AI analysis to find, validate, and prioritize vulnerabilities across your infrastructure.

**Key capabilities:**
- **38 scanner plugins** covering network, web, infrastructure, IoT, and cloud
- **Multi-provider AI analysis** (Azure OpenAI, Claude, Gemini) for finding validation and PoC generation
- **6 threat intelligence feeds** (NVD, CVE.org, CISA KEV, EPSS, CMS-CVE, Compliance)
- **Risk scoring engine** with CVSS, CISA KEV prioritization, and SLA tracking
- **Compliance mapping** to NIST 800-53, PCI DSS v4, CIS v8, and ISO 27001
- **Neo4j attack graph** modeling for visualizing attack paths
- **RBAC + multi-tenant** workspace isolation

---

## Features

| Category | Details |
|----------|---------|
| **Scanning** | Plugin-based engine with dependency resolution and artifact pipeline |
| **Web Security** | OWASP Top 10, SSTI, CRLF injection, Host Header injection, GraphQL, JWT analysis |
| **API Security** | API key/token exposure detection, security headers audit |
| **Infrastructure** | SSH audit, SMB check, SNMP, FTP anonymous, Redis no-auth, Docker API |
| **IoT** | MQTT anonymous access, topic enumeration, publish injection |
| **Cloud** | S3/GCS/Azure blob misconfiguration detection |
| **WAF** | WAF detection and bypass testing |
| **Fingerprinting** | HTTP headers, banners, web tech, favicon hash, deep fingerprint |
| **CVE Matching** | NVD CPE matching, CMS-specific CVEs, package-based CVE detection |
| **Enrichment** | Multi-source CVSS (NVD + CNA/ADP), EPSS exploit probability |
| **Prioritization** | CISA KEV cross-reference, risk scoring, SLA assignment |
| **Compliance** | NIST 800-53, PCI DSS v4, CIS Controls v8, ISO 27001 mapping |
| **Reporting** | CSV, HTML, PDF export per-host or bulk; AI-generated analysis reports |
| **AI Analysis** | Multi-provider deep analysis with finding validation and PoC generation |
| **Datasets** | One-click refresh from NVD, CISA, EPSS, CVE.org feeds |
| **Graph** | Neo4j attack graph with interactive visualization |

---

## Architecture

```
┌─────────────┐  ┌──────────────┐  ┌────────────┐
│  Frontend    │  │   Backend    │  │   Worker    │
│  Vanilla JS  │  │   FastAPI    │  │   RQ + AI   │
│  Port 5173   │  │   Port 8888  │  │             │
└──────┬───────┘  └──────┬───────┘  └──────┬──────┘
       │                 │                 │
       └────────┬────────┴────────┬────────┘
                │                 │
          ┌─────┴─────┐   ┌──────┴──────┐
          │ PostgreSQL │   │    Redis    │
          │  Port 5432 │   │  Port 6379  │
          └───────────┘   └─────────────┘
                │
          ┌─────┴─────┐
          │   Neo4j   │
          │ Port 7474 │
          └───────────┘
```

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy 2.0, Redis + RQ, PostgreSQL 16, Neo4j 5, Vanilla JS SPA

---

## Quick Start

### Requirements

- Docker
- Docker Compose

### Installation

```bash
git clone https://github.com/Gondrong/VulnScan-Platform.git
cd VulnScan-Platform
./bootstrap.sh
```

### Access

| Service | URL |
|---------|-----|
| **Web UI** | `http://YOUR_IP:5173` |
| **API** | `http://YOUR_IP:8888` |
| **Neo4j Browser** | `http://YOUR_IP:7474` |

**Default credentials:**
- Email: `admin@local`
- Password: `admin123`

> Change the default password after first login.

---

## Scanner Plugins

### Network & Discovery (6 plugins)

| # | Plugin | Description |
|:-:|--------|-------------|
| 1 | `port_scan` | TCP port discovery (top 100/1000) |
| 2 | `nmap_portscan` | Full port range + service banners via Nmap |
| 3 | `dns_enum` | Subdomain enumeration + zone transfer |
| 4 | `banner_grabber` | Multi-protocol service version banners |
| 5 | `http_fingerprint` | HTTP server headers + technology disclosure |
| 6 | `tls_basic` | TLS version, cipher strength, certificate expiry |

### Fingerprinting & Detection (4 plugins)

| # | Plugin | Description |
|:-:|--------|-------------|
| 7 | `web_tech` | CMS/framework detection (WordPress, Drupal, React, etc.) |
| 8 | `deep_fingerprint` | Technology-specific version detection |
| 9 | `favicon_hash` | Favicon hash-based service identification |
| 10 | `cpe_builder` | Builds CPE strings from fingerprint data |

### Web Application Security (9 plugins)

| # | Plugin | Description |
|:-:|--------|-------------|
| 11 | `owasp_scanner` | OWASP Top 10 active tests (SQLi, XSS, XXE, CSRF, SSRF, etc.) |
| 12 | `dir_crawl` | Directory and file discovery (80+ paths) |
| 13 | `file_inclusion` | LFI/RFI with advanced bypass techniques |
| 14 | `security_headers` | 7 security headers audit + CORS check + cookie flags (A-F grade) |
| 15 | `jwt_scanner` | JWT alg:none bypass, weak HMAC keys, missing claims |
| 16 | `graphql_scanner` | GraphQL introspection, sensitive fields, depth/batch abuse |
| 17 | `api_key_exposure` | 22 API key patterns (AWS, GitHub, Slack, Stripe, etc.) + .env exposure |
| 18 | `host_header_injection` | Host header manipulation testing |
| 19 | `crlf_injection` | CRLF injection in HTTP headers |

### Infrastructure Security (8 plugins)

| # | Plugin | Description |
|:-:|--------|-------------|
| 20 | `ssh_audit` | Weak key exchange, deprecated ciphers, SSHv1 |
| 21 | `ssh_inventory` | SSH authenticated package collection |
| 22 | `smb_check` | Anonymous/null session, SMBv1 detection |
| 23 | `db_auth_check` | Default credentials for Redis, MongoDB, MySQL, PostgreSQL, Elasticsearch |
| 24 | `snmp_community` | SNMP community string brute force |
| 25 | `ftp_anon` | FTP anonymous access testing |
| 26 | `redis_noauth` | Redis no-auth deep inspection |
| 27 | `docker_api` | Exposed Docker API detection |

### Advanced Testing (4 plugins)

| # | Plugin | Description |
|:-:|--------|-------------|
| 28 | `ssti_scanner` | Server-Side Template Injection (Jinja2, Twig, Freemarker, etc.) |
| 29 | `waf_detection` | WAF detection and bypass testing |
| 30 | `cloud_storage_misconfig` | AWS S3, GCS, Azure Blob misconfiguration |
| 31 | `mqtt_scanner` | MQTT anonymous access, topic enumeration, publish injection |

### CVE Matching & Prioritization (7 plugins)

| # | Plugin | Description |
|:-:|--------|-------------|
| 32 | `nvd_match` | CPE to CVE matching against NVD database |
| 33 | `cms_match` | CMS-specific CVE detection |
| 34 | `cve_packages` | Package-based CVE matching |
| 35 | `cisa_kev` | CISA Known Exploited Vulnerabilities prioritization |
| 36 | `cve_verifier` | Cross-references OWASP findings with CVE CWE categories |
| 37 | `endpoint_prober` | Safe HTTP endpoint probes for known CVE patterns |
| 38 | `local_security` | Linux distro advisory matching |

---

## AI Deep Analysis

VulnScan integrates with multiple AI providers for intelligent vulnerability analysis:

| Provider | Model | Configuration |
|----------|-------|---------------|
| **Azure OpenAI** | GPT-4o / GPT-4.1 | `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_ENDPOINT` |
| **Claude CLI** | Claude Opus / Sonnet | Install Claude Code on server + `CLAUDE_CLI_ENABLED=true` |
| **Google Gemini** | Gemini 2.5 Flash | `GEMINI_API_KEY` |

### Analysis Modes

| Mode | What It Does |
|------|-------------|
| **Validate** | Classifies each finding as True Positive / False Positive / Needs Manual |
| **Full Analysis** | Executive summary, attack chain identification, remediation priority |
| **Full + PoC** | Full analysis + proof-of-concept exploit scripts for confirmed findings |

### Per-Finding PoC Generation

Click "Generate PoC" on any individual finding to get an AI-generated Python exploit script with:
- Step-by-step exploitation code
- Clear comments explaining each step
- Copy button for easy use
- Safety disclaimer

---

## Threat Intelligence Datasets

| Dataset | Source | Records | Auto-Refresh |
|---------|--------|---------|:------------:|
| **NVD** | NIST NVD API | ~200K CVEs | Yes |
| **CVE.org** | CVE.org API (CNA/ADP scores) | ~50K | Yes |
| **CISA KEV** | CISA KEV feed | ~1K | Yes |
| **EPSS** | FIRST EPSS scores | ~200K | Yes |
| **CMS-CVE** | Generated from NVD | ~5K | Yes |
| **Compliance** | Static mapping | ~50 controls | Yes |

**One-click refresh** from the UI or via CLI scripts. Supports offline dataset upload.

### Security Information Browser

Browse all datasets directly from the UI with search, pagination, and expandable detail rows:
- NVD entries with CVSS scoring, affected products, references
- CVE multi-source CVSS comparison
- CISA KEV catalog with remediation deadlines
- EPSS exploit probability scores
- Compliance control mappings

---

## Scan Flow

```
1. Port Discovery        ─→ TCP port scanning (Nmap + async)
2. Service Fingerprint   ─→ Banners, HTTP headers, TLS, web tech
3. Deep Fingerprint      ─→ Version-specific detection, favicon hash
4. CPE Construction      ─→ Build CPE 2.3 URIs from fingerprint data
5. CVE Matching          ─→ NVD + CMS + package-based matching
6. Active Testing        ─→ OWASP, SQLi, XSS, SSTI, CRLF, etc.
7. Infrastructure Audit  ─→ SSH, SMB, SNMP, MQTT, Docker, Redis, etc.
8. Prioritization        ─→ CISA KEV, EPSS, risk scoring
9. Compliance Mapping    ─→ NIST 800-53, PCI DSS, CIS, ISO 27001
10. Attack Graph         ─→ Neo4j graph modeling
```

---

## Risk Scoring

```
Risk = (CVSS * exploit_weight) + KEV_bonus + asset_criticality * confidence
```

### Asset Criticality Levels

| Level | Label | Multiplier | Use For |
|:-----:|-------|:----------:|---------|
| 1 | Low (Dev/Test) | x0.8 | Dev servers, sandbox, staging |
| 2 | Normal | x1.0 | Internal tools, standard workstations |
| 3 | High (Business-critical) | x1.1 | Production apps, internal APIs |
| 4 | Critical (Customer data) | x1.2 | Payment systems, databases with PII |
| 5 | Maximum (Regulatory) | x1.3 | HIPAA/PCI systems, SCADA, public-facing auth |

### SLA Rules

| Severity | Remediation Deadline |
|----------|---------------------|
| Critical | 7 days |
| High | 14 days |
| Medium | 30 days |
| Low | 60 days |

---

## Export & Reporting

| Location | Scope | Formats |
|----------|-------|---------|
| Panel header | All hosts combined | CSV, HTML, PDF |
| Per-host expand | Single host only | CSV, HTML, PDF |
| Bulk selection | Selected hosts | CSV, HTML, PDF |
| AI Analysis | Full analysis report | In-app viewer |

---

## Configuration

### Environment Variables (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing key | `dev-secret-CHANGE-ME` |
| `DATABASE_URL` | PostgreSQL connection | `postgresql+psycopg2://app:app@db:5432/app` |
| `REDIS_URL` | Redis connection | `redis://redis:6379/0` |
| `SCAN_BUDGET_SECONDS` | Max scan duration | `900` (15 min) |
| `NVD_API_KEY` | NVD API key (faster refresh) | (optional) |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI key | (optional) |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint | (optional) |
| `CLAUDE_CLI_ENABLED` | Enable Claude CLI provider | `false` |
| `GEMINI_API_KEY` | Google Gemini key | (optional) |
| `BACKEND_PORT` | API server port | `8888` |
| `FRONTEND_PORT` | Web UI port | `5173` |

---

## Changelog

### v2.2.0 — 2026-03-29

#### New Features

**Multi-Provider AI Deep Analysis**
- AI-powered vulnerability analysis with Azure OpenAI, Claude CLI, and Gemini
- Three analysis modes: Validate, Full Analysis, Full + PoC Generation
- Per-finding "Generate PoC" button for individual exploit script generation
- Analysis history with provider comparison
- Attack chain identification and remediation prioritization

**14 New Scanner Plugins (Tier 1 + Tier 2)**
- API Key/Token Exposure (22 known patterns: AWS, GitHub, Slack, Stripe, etc.)
- JWT Weak Algorithm Scanner (alg:none bypass, weak HMAC key brute force)
- GraphQL Introspection & Security (schema exposure, depth/batch abuse)
- Security Headers Audit (7 headers, CORS, cookies, A-F grading)
- MQTT Scanner (anonymous access, topic enumeration, publish injection)
- SNMP Community String brute force
- FTP Anonymous access testing
- Redis No-Auth deep inspection
- Host Header Injection
- CRLF Injection
- Docker API exposure
- Cloud Storage Misconfiguration (S3, GCS, Azure)
- WAF Detection & Bypass
- SSTI Scanner (Jinja2, Twig, Freemarker, etc.)

**Security Information Browser**
- New "Security Intel" expandable menu with 6 dataset views
- Browse NVD, CVE, CISA-KEV, CMS-CVE, EPSS, Compliance data with search and pagination
- Expandable detail rows for each entry

**Dataset Refresh from UI**
- One-click "Refresh All" to re-fetch datasets from NVD, CISA, EPSS, CVE.org
- Real-time progress banner with per-dataset status
- Background processing via RQ worker

**Plugin Checkbox Grid**
- Profile creation now shows visual checkbox grid instead of raw JSON
- Grouped by category with Select All / Deselect All
- Auto-populates when editing or cloning profiles

**Per-Host Report Generation**
- Checkboxes in "Vulnerabilities by Host" for bulk selection
- Export selected hosts as CSV, HTML, or PDF

**Profile Editing**
- Edit existing scan profiles via PUT endpoint
- Edit, Clone, Delete action buttons per profile

#### Improvements

- Pagination for Job History (10/page), Scheduled Scans (5/page), Profiles (10/page), Credentials (10/page), Datasets (6/page)
- Responsive table layout for small screens
- OWASP scanner: content validators + soft-404 detection to reduce false positives
- External scan timeout handling: increased per-port TCP timeout, added TCP reachability pre-check
- Claude Code CLI installed in Docker worker container for AI analysis

### v2.1.0 — 2026-03-14

- Scanning accuracy: distro-patch detection, active verification, deep fingerprinting
- CVE verifier and endpoint prober plugins
- Validation states with confidence caps
- Bootstrap script with auto-credential detection

### v1.0.0 — 2026-03-05

- Initial release
- 17 scanner plugins
- Risk engine, compliance mapping, SLA tracking
- Neo4j attack graph
- CSV/HTML/PDF export

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built by <a href="https://github.com/Gondrong">Gondrong</a></sub>
</p>
