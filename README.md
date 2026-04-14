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
| Critical | 2 days |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |
| Info | 365 days |

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

## v2.1.4 — 2026-04-14

### New Features

**4 New Scanner Plugins (51 total)**

Tier 4 — Deep injection testing (advanced payloads + WAF bypass)
- Advanced XSS Scanner — reflected + stored XSS with 30+ payloads across HTML, attribute, JavaScript, and URL contexts; polyglot payloads; WAF-bypass via encoding, case, tag-breaking, event handlers
- Deep SQL Injection Scanner — error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), boolean-based blind, time-based blind, UNION-based, stacked queries; WAF-bypass via encoding, case, comment obfuscation
- Deep OS Command Injection Scanner — in-band marker detection and blind time-based detection on Linux and Windows; covers GET params, POST bodies, and headers; WAF-bypass via encoding, newlines, variable expansion

Tier 5 — API-specific scanning (OpenAPI / Swagger / Postman)
- API Security Scanner — new `plugins/api_scanner/` sub-package that ingests OpenAPI 3.x, Swagger 2.x, and Postman v2.1 specs and dispatches endpoints to 15 sub-checks:
  - Injection: `sqli`, `xss`, `ssti`, `cmdi`, `xxe`, `ssrf`, `code_injection`, `type_confusion`
  - Auth / OWASP API Top 10: `jwt_checks`, `bola` (API1), `mass_assignment` (API3)
  - Data exposure: `excessive_data` (API3)
  - Passive: `config_checks`, `spec_hygiene`
  - GraphQL: `graphql` (introspection, batch abuse, depth attacks, field suggestions)
- Shared `spec_parser` (OpenAPI 3.x / Swagger 2 / Postman v2.1) and async `http_client` with **multi-identity auth** (primary + secondary) for BOLA / BFLA comparisons
- Runs in engine mode (part of a normal scan) or standalone via the new API endpoints
- Opt-in (`enabled_by_default=False`) — requires spec upload or explicit enable

Tier 5 — Spec-aware sub-checks (OWASP API Security Top 10 coverage)
- **BOLA** (`bola`, OWASP API1) — two-identity comparison with Jaccard key similarity ≥ 0.8; falls back to numeric ID neighbour-walking when only one identity is configured
- **Mass Assignment / BOPLA** (`mass_assignment`, OWASP API3) — injects `is_admin`, `role`, `balance` into POST/PUT/PATCH bodies and flags only when the server echoes the value
- **Excessive Data Exposure** (`excessive_data`, OWASP API3) — sweeps GET responses for credentials, PII, internal markers; flags schema drift when response fields exceed declared schema by >2×
- **Type Confusion** (`type_confusion`) — wrong-type payloads (`{"$ne": null}`, `["array"]`, long strings); triggers on 5xx or divergent 200s — a precursor pattern to NoSQL operator injection
- **Spec Hygiene** (`spec_hygiene`) — passive analysis: endpoints without auth, missing `securitySchemes`, wildcard CORS, real secrets in examples (Stripe / AWS / JWT / private keys), plain HTTP servers

**New Backend API**
- `POST /scan/api-scanner/jobs` — standalone endpoint for spec-driven API scans
- `POST /scan/api-scanner/parse` — preview the endpoint list before launching a scan
- `GET /scan/api-scanner/checks` — list available sub-checks with category metadata (consumed by the UI)

**API Scanner Hardening**
- SSRF guard on `spec_url` fetches — rejects private / loopback / link-local / multicast / reserved / unspecified addresses (blocks AWS metadata `169.254.169.254`, `127.0.0.1`, RFC1918) and non-http(s) schemes
- 5 MB cap on uploaded spec files and URL-fetched specs (HTTP 413 on oversize)
- RQ `job_timeout` now follows `SCAN_BUDGET_SECONDS + 300` (was `AI_ANALYSIS_TIMEOUT = 600s`)

**Frontend — API Scanner page**
- New collapsible **"Secondary identity (optional)"** section with bearer / API-key / basic inputs for a second test user (required for BOLA / BFLA)
- The 5 new spec-aware checks appear automatically in the Security Checks grid (auto-populated from `/scan/api-scanner/checks`)

**Global Scan Budget**
- New `SCAN_BUDGET_SECONDS` setting (default `900`) — engine tracks wall-clock time and skips remaining plugins when exhausted, emitting one info-level skip finding per skipped plugin
- RQ `job_timeout` now auto-synced to `SCAN_BUDGET_SECONDS + 300s` headroom (was a hard-coded 600s); applied to new jobs and rescans

**Plugin Framework — Soft Dependencies**
- New `soft_depends_on` field on `PluginMeta` — affects execution order (runs after listed plugins) but does NOT auto-enable them
- Used by the new Tier-4 / Tier-5 plugins to run after `owasp.web.scanner` when available, without requiring it

### Improvements

- Default artifact fallback — when a plugin times out or errors, the engine populates empty defaults for that plugin's declared `provides` keys so downstream plugins reading those artifacts don't break
- Profile auto-backfill — if a plugin is missing from an existing profile's selection, the loader falls back to its `enabled_by_default` flag; old profiles now pick up newly-shipped plugins automatically
- Per-plugin cancel check — cancel flag is now checked before each plugin, shortening cancel latency
- New Python dependencies: `requests>=2.31.0`, `paho-mqtt==1.6.1`, `openai>=1.30.0`, `google-generativeai>=0.7.0`, `pyyaml>=6.0`

### Notes

- No breaking changes — existing profiles, jobs, and integrations continue to work unchanged
- Tune `SCAN_BUDGET_SECONDS` in `.env` if you run large or slow scans; the RQ timeout follows it automatically


##

## v2.1.3 — 2026-04-05

### New Features

**9 New Scanner Plugins (47 total)**
- SSL Certificate Transparency — discovers subdomains and expired certs via CT logs (crt.sh)
- Rate Limiting Check — sends 30 rapid requests to login endpoints, detects missing throttling
- Open Redirect — tests URL parameters for unvalidated redirects to external domains
- LDAP Injection — tests LDAP anonymous bind (port 389/636) + LDAP filter injection in web forms
- NoSQL Injection — MongoDB operator injection ($gt, $ne, $regex) for authentication bypass
- SSRF Deep (Cloud Metadata) — injects AWS/GCP/Azure metadata URLs into URL-accepting parameters
- WebSocket Security — discovers WS endpoints, tests unauthenticated access and cross-origin hijacking
- Kubernetes API — probes K8s API (6443), Kubelet (10250/10255), etcd (2379) for unauthenticated access
- Unauthenticated API Access — tests 50+ API paths without auth token, detects broken access control

**One-Click Platform Update**
- Settings → System tab shows current vs latest version from GitHub Releases
- "Update Now" button triggers git pull + docker rebuild automatically
- Notification banner appears when new version is available (checks once per 24 hours)
- Host-level systemd service handles the update (install once with `scripts/install-updater.sh`)
- Auto-preserves user .env config during updates

**Scan Cancel Button**
- Cancel button on running scans in the progress panel
- Stops scan after current plugin completes, auto-deletes the cancelled job
- Redis-based cancel signal between frontend → backend → worker → scan engine

**Integration Redesign**
- Toggle-based UI with 3 states: OFF → ON + editing → ON + saved (connected)
- Microsoft Teams integration (Adaptive Card format via Incoming Webhook)
- Remove/disable button per integration with confirmation
- Message format description shown for each provider
- Per-integration Save and Test buttons (no more "Save All")
- Top findings in notifications increased from 3 to 10

**Plugin Checkbox Grid**
- Profile creation shows visual checkbox grid instead of raw JSON textarea
- Grouped by category with Select All / Deselect All buttons
- GET /scan/plugins API endpoint lists all available plugins with metadata

**AI Deep Analysis — Job Selector**
- Added job selector dropdown to AI analysis bar
- User can choose which specific scan job to analyze (previously always picked the latest)

### Improvements

- Release script (`scripts/release.sh`) — auto-bumps version in all 6 files, commits, tags
- .gitignore — prevents __pycache__, .env, node_modules, data files from being tracked
- Delete job now cleans up related AI analysis records (foreign key fix)
- Stronger PoC generation prompts — exploitation-focused instead of validation
- Dataset cleanup — old timestamped files auto-deleted after refresh
- Claude CLI provider detection via CLAUDE_CLI_ENABLED env var (fixes Docker detection)

### Bug Fixes

- Fixed scan cancel: engine now checks Redis cancel flag between each plugin
- Fixed job deletion: deletes ai_analyses records before findings (FK constraint)
- Fixed AI analysis: job selector prevents analyzing wrong host's findings
- Fixed Docker: Node.js installed with all dependencies (libuv.so fix)
- Fixed updater: git reset --hard handles __pycache__ and untracked file conflicts


##

## v2.1.2 — 2026-04-02

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

##

## v2.1.1 — 2026-03-23

### ✨ New Features

**Security Information Browser**
- New "Security Intel" expandable/collapsible dropdown menu in the sidebar
- Browse all 6 threat intelligence datasets directly from the UI with search and pagination (50 records/page)
- Click any row to expand detailed information (animated slide-down)
- Overview page with 6 clickable cards for quick navigation
- Dataset views:
  - **NVD** — CVE entries with CVSS, affected products (CPE), references
  - **CVE** — Multi-source CVSS scores from CNA and ADP providers
  - **CISA-KEV** — Known Exploited Vulnerabilities with remediation deadlines and ransomware indicators
  - **CMS-CVE** — CMS-specific vulnerabilities (WordPress, Drupal, GitLab, etc.)
  - **EPSS** — Exploit Prediction Scoring with visual probability bars
  - **Compliance** — NIST 800-53, PCI DSS v4, CIS v8, and ISO 27001 control mappings

**Dataset Refresh from UI**
- "Refresh All" button to re-fetch all 6 datasets from their sources (NVD, CISA, EPSS, CVE.org) without leaving the browser
- Real-time progress banner with per-dataset status updates
- Cancel button to abort long-running refreshes
- Background processing via RQ worker

##

## v2.1.0 — 2026-03-14

- Scanning accuracy: distro-patch detection, active verification, deep fingerprinting
- CVE verifier and endpoint prober plugins
- Validation states with confidence caps
- Bootstrap script with auto-credential detection

##

## v1.0.0 — 2026-03-05

- Initial release
- 17 scanner plugins
- Risk engine, compliance mapping, SLA tracking
- Neo4j attack graph
- CSV/HTML/PDF export

##
---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built by <a href="https://github.com/Gondrong">Gondrong</a></sub>
</p>
