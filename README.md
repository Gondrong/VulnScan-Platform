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
- **51 scanner plugins** covering network, web, infrastructure, IoT, cloud, and API (OpenAPI/Swagger/Postman)
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

## v3.0.0 — 2026-05-03

### New Features

**Authenticated Web Scanning** (headline feature)

- New `web.auth` plugin establishes an authenticated HTTP session that downstream web plugins (OWASP scanner + injection plugins) consume via the `web.auth_session` artifact. Five auth modes supported: form login (with auto-CSRF harvest), bearer token, HTTP Basic, static cookies, static request headers.
- Credentials live in the existing encrypted Credentials store and are decrypted at scan time only — they never appear in `options_json`.
- Plugin count: **53 total** (was 51 in v2.1.4).

**Login Form Inspector**

- `POST /scan/web-auth/inspect` fetches the target login page, parses HTML forms, ranks them by likelihood of being the login form, and returns username/password/CSRF candidates so the UI can pre-fill field-name dropdowns.
- Detects reCAPTCHA / hCaptcha / Cloudflare Turnstile and warns the user.
- Detects JS-rendered SPA logins (large page, few static inputs) and recommends bearer/cookie auth.
- SSRF-guarded against internal/loopback/metadata IPs.

**Web Auth on the New Scan dialog** (architectural shift)

- Web Authentication panel **moved out of the Profile modal** and onto the New Scan dialog — auth is target-specific, not profile-shared.
- Smart credential suggestions: when login form has email-typed username field, credentials with `@` in the username are sorted to the top with a "✓ matches email field" badge.
- Empty-state CTA when no credentials exist.
- **Save as credential** checkbox creates a permanent credential from inline values.
- **Auto-delete after scan** — ephemeral credential workflow for one-off pentests. Credential is created, used for one scan, then deleted in the worker's `finally:` block on any outcome (done / failed / cancelled).
- Three-card layout for form login: form-field mapping → credentials → success/failure detection.

**Test Login**

- `POST /scan/web-auth/test-login` runs the configured auth flow once and returns success/cookies/error before launching the long scan.
- Inline result panel on the New Scan dialog. Cookie/header **names** returned but not values — safe to log.

**Threat Intelligence page** (new top-level menu)

- New "Intelligence" sidebar section with the **Threat Intel** entry.
- Fuses NVD + EPSS + CISA KEV by CVE-ID into a single CVE-centric view.
- Composite **threat score (0–100)**: 40% CVSS + 35% EPSS percentile + 15% KEV bonus + 10% recency on KEV-add date.
- Filter chips: severity, "CISA KEV only", "Ransomware-known", EPSS ≥ threshold, free-text search.
- Sort by threat score / CVSS / EPSS / KEV due date / KEV added.
- Detail drawer per CVE: severity card, exploitation card, description, CISA KEV notes, vendor/product, affected CPEs (up to 50), references.
- Four stat tiles: CVEs in catalog / KEV listed / KEV due in 7 days / Ransomware-known.
- New endpoints: `GET /threat-intel/cves`, `GET /threat-intel/cves/{id}`, `GET /threat-intel/stats`, `POST /threat-intel/refresh`.
- Per-workspace in-memory cache (5-min TTL), auto-invalidates when datasets refresh.

**Threat Intel Dashboard band**

- New band on the main Dashboard with 4 mini-tiles (New KEV 7d / KEV due 7d / Ransomware-known / High EPSS ≥50%).
- Each tile clickable → opens Threat Intel page.
- Auto-hides when no feeder datasets are loaded.

**UDP Port Scanner**

- New `udp_portscan` plugin probes top-35 UDP ports with protocol-specific payloads (DNS, NTP, SNMP, NetBIOS-NS, mDNS, SSDP, IKE, memcached, BACnet, IPMI).
- Severity-graded findings for risky exposed services (memcached UDP=critical, IPMI=high, BACnet=high, NFS=high, NetBIOS=medium).
- Disabled by default — UDP scans are slow on tight budgets.

**Infrastructure-as-Code Scanner**

- New sub-package `plugins/iac_scanner/` for IaC static analysis.
- Accepts ZIP archive or single config file (5 MB cap, 2000 files / 2 MB each, path-traversal safe).
- 30+ rules across six IaC formats:
  - **Terraform** — hardcoded secrets, public S3 ACL, open security groups (0.0.0.0/0), public RDS
  - **Dockerfile** — no USER directive, `:latest` tag, USER root, ADD remote URL, secret ENV/ARG, `curl|sh`
  - **Kubernetes** — privileged, hostNetwork/PID/IPC, runAsUser:0, allowPrivilegeEscalation, CAP_SYS_ADMIN, default namespace, missing limits
  - **docker-compose** — privileged services, host network, `docker.sock` mount, latest tag
  - **CloudFormation** — public S3, missing BucketEncryption, open SGs, public RDS, StorageEncrypted=false
  - **Helm values.yaml** — reuses K8s rules
- New endpoints: `POST /scan/iac/jobs`, `POST /scan/iac/parse`, `GET /scan/iac/kinds`.

**User password management**

- `PUT /settings/users/me/password` — any authenticated user can change their own password (verifies current password + 6-char minimum).
- `PUT /settings/users/{user_id}/password` — admin-only password reset for any workspace user.
- Frontend `settingsApi.changePassword()` and `settingsApi.resetPassword()`.

### Improvements

**Integrations overhaul** (Slack / Teams / Webhook / Email)

- Test buttons now work without saving first (the disabled-until-saved gate is gone — fixes the v2.x silent-failure UX).
- 422 errors render readably — `api.js` flattens FastAPI's array-of-validation-errors into `"loc: msg"` strings instead of `[object Object]`.
- Generic webhook URL field uses `url` (matches notifier), separate from Slack/Teams `webhook_url`.
- Webhook auth header field renamed `auth_header` → `secret`.
- Email field names corrected: `smtp_password` → `smtp_pass`, `from_addr` → `from_email`, `to_addrs` → `to_email`.
- New `DELETE /integrations/{provider}` endpoint and Remove button in the modal.
- Test endpoint accepts an optional body — falls back to saved config if not supplied.
- Per-provider client-side validation pre-checks before round-trip.

**Auth session resilience**

- Form login now POSTs to the form's actual `<form action="…">` URL (passed as `action_url`), not blindly to `login_url`. Older sites where these differ now work correctly (WordPress, Django, ASP.NET WebForms).
- CSRF tokens auto-harvested across more patterns: `csrfmiddlewaretoken`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `nonce`, `csrf*`, `xsrf*`.

**API client hardening**

- ThreatIntel UI normalizes API responses with strict type checks (`Number.isFinite`, `Array.isArray`) — guards against partial responses, reverse-proxy-injected HTML, etc.

### Bug Fixes

- Form login no longer fails silently when the form's `action` URL differs from `login_url` (POST now uses the correct URL).
- Integrations Test button is no longer a no-op on first click.
- FastAPI 422 validation errors now render as readable text instead of `[object Object]`.
- Threat Intel page no longer goes blank if the API returns an unexpected response shape.

### Migration Notes

- **No DB migrations required** — all changes use the existing `meta_json` columns.
- **Profile-modal Web Auth removed** — saved profile-level `web_auth` blocks still work (the engine reads them), but UI for editing now lives on the New Scan dialog.
- **Email integrations** saved before v3.0 need their password re-entered (field renamed `smtp_password` → `smtp_pass`).
- **Threat Intel** requires NVD + EPSS + CISA KEV datasets — refresh from Configuration → Datasets to populate.

### Roadmap (deferred to v3.1+)

- Scheduled authenticated scans (needs `ScanSchedule.meta_json` migration).
- "Find affected assets" cross-reference from CVE → workspace findings.
- SQLite-indexed Threat Intel for production scale.
- Playwright-based SPA login support.
- Top-level React error boundary.

##

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
