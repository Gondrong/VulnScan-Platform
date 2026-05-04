<p align="center">
  <img width="1918" height="987" alt="VulnScan Platform" src="https://github.com/user-attachments/assets/5ce0c292-e8f9-4f5a-8fc4-0d8e25c43dd0" />

</p>

<h1 align="center">VulnScan Platform</h1>
<p align="center">
  <strong>Risk-Based Vulnerability Management — self-hosted, AI-augmented, MIT-licensed</strong>
</p>
<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#scanner-plugins">Plugins</a> &bull;
  <a href="#threat-intelligence">Threat Intel</a> &bull;
  <a href="#authenticated-web-scanning">Authenticated Scans</a> &bull;
  <a href="#iac-scanner">IaC Scanner</a> &bull;
  <a href="#ai-deep-analysis">AI Analysis</a> &bull;
  <a href="#changelog">Changelog</a>
</p>

---

## Overview

VulnScan is a self-hosted Risk-Based Vulnerability Management (RBVM) platform built for security teams. It combines automated scanning with multi-provider AI analysis to **find**, **validate**, **prioritize**, and **remediate** vulnerabilities across networks, web apps, APIs, IoT, cloud infrastructure, and infrastructure-as-code.

**v3.0 highlights** *(2026-05-03)* — see [Changelog](#changelog) for full notes.

| | |
|---|---|
| 🔐 **Authenticated web scanning** | Five auth modes (form, bearer, basic, cookie, header) with auto-CSRF harvest, per-target credential picker, and a one-shot **Test Login** pre-flight |
| 🔍 **Login form inspector** | Paste login URL → parses HTML form → auto-fills field names; detects reCAPTCHA / hCaptcha / Turnstile / SPA-rendered logins |
| 🎯 **Threat Intel page** | New top-level menu fusing NVD + EPSS + CISA KEV per CVE with composite threat scoring (CVSS + EPSS + KEV bonus + recency) |
| 🏗️ **IaC scanner** | Static analysis across Terraform, Dockerfile, Kubernetes, docker-compose, CloudFormation, Helm — 30+ rules |
| 📡 **UDP scanner** | Top-35 UDP ports with protocol-specific probes (DNS, NTP, SNMP, IKE, memcached, BACnet, IPMI) |
| 🗑️ **Ephemeral credentials** | Save creds at scan launch and auto-delete when the scan finishes — for one-off pentests |

**Key capabilities:**
- **53 scanner plugins** spanning network / web / infrastructure / IoT / cloud / API
- **Multi-provider AI analysis** (Azure OpenAI, Claude CLI, Gemini) for finding validation, attack-chain analysis, and PoC generation
- **6 threat intelligence feeds** (NVD, CVE.org, CISA KEV, EPSS, CMS-CVE, Compliance) with one-click refresh
- **Composite threat-score prioritization** beyond CVSS-only — uses EPSS percentile, KEV listing, and ransomware status
- **Compliance mapping** to NIST 800-53, PCI DSS v4, CIS Controls v8, ISO 27001
- **Neo4j attack graph** for visualizing exploit paths
- **RBAC + multi-tenant** workspace isolation
- **No phone-home, no telemetry, no third-party data residency**

---

## Features

| Category | Details |
|----------|---------|
| **Scan engine** | Plugin-based, dependency-resolved, artifact pipeline; per-plugin timeouts; global scan budget |
| **Network** | TCP port discovery (top 100 / 1000 / full), Nmap-style banners, **UDP** with protocol probes, DNS enum, TLS analysis, CT logs |
| **Web application** | OWASP Top 10 (2025), advanced XSS, deep SQLi, deep OS command injection, SSTI, LFI/RFI, CRLF, host-header, SSRF, open-redirect, LDAP/NoSQL injection |
| **Authenticated web** | Form login + CSRF, bearer, basic, cookie, header — with login-form inspector + Test Login pre-flight |
| **API security** | OpenAPI / Swagger / Postman ingestion + 15 sub-checks (BOLA, mass-assignment, excessive-data, type-confusion, spec-hygiene, GraphQL) |
| **Infrastructure** | SSH audit, SMB, SNMP, FTP anonymous, Redis no-auth, Docker API, Kubernetes API |
| **IoT** | MQTT anonymous access, topic enumeration, publish injection |
| **Cloud** | S3 / GCS / Azure Blob misconfiguration |
| **IaC** *(v3.0)* | Terraform, Dockerfile, Kubernetes, docker-compose, CloudFormation, Helm — 30+ rules |
| **CVE matching** | NVD CPE matching, CMS-specific CVEs, package-based CVE detection, endpoint probes |
| **Threat Intel** *(v3.0)* | Unified CVE view fusing NVD + EPSS + CISA KEV with composite threat score |
| **Enrichment** | Multi-source CVSS (NVD + CNA/ADP), EPSS exploit probability, ransomware-known flag |
| **Prioritization** | CISA KEV cross-reference, EPSS percentile, asset criticality, SLA tracking |
| **Compliance** | NIST 800-53, PCI DSS v4, CIS Controls v8, ISO 27001 mapping with framework presets |
| **Reporting** | CSV / HTML / PDF — per host, bulk, or AI-generated narrative reports |
| **AI Analysis** | Multi-provider validation, attack chain identification, per-finding PoC scripts |
| **Datasets** | One-click refresh from NVD / CISA / EPSS / CVE.org; offline upload supported |
| **Graph** | Neo4j attack-path visualization |
| **Integrations** | Slack, Microsoft Teams, generic webhook, SMTP email — with Test buttons that actually work |

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Frontend   │     │   Backend    │     │   Worker    │
│  React SPA  │────▶│   FastAPI    │────▶│   RQ + AI   │
│  Port 5173  │     │   Port 8888  │     │             │
└──────┬──────┘     └──────┬───────┘     └──────┬──────┘
       │                   │                    │
       └─────────┬─────────┴─────────┬──────────┘
                 │                   │
           ┌─────┴──────┐      ┌─────┴──────┐
           │ PostgreSQL │      │   Redis    │
           │  Port 5432 │      │  Port 6379 │
           └────────────┘      └────────────┘
                 │
           ┌─────┴──────┐
           │   Neo4j    │
           │  Port 7474 │
           └────────────┘
```

**Tech stack:** Python 3.11 · FastAPI · SQLAlchemy 2.0 · Redis + RQ · PostgreSQL 16 · Neo4j 5 · React + Vite

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
> ⚠️ If your server/linux via VMWare you must change the value from "dev": "vite" to "dev": "node node_modules/vite/bin/vite.js" at frontend/package.json. if not, your frontend not visible

### Access

| Service | URL |
|---------|-----|
| **Web UI** | `http://YOUR_IP:5173` |
| **API** | `http://YOUR_IP:8888` |
| **Neo4j Browser** | `http://YOUR_IP:7474` |

**Default credentials:**
- Email: `admin@local`
- Password: `admin123`

> ⚠️ Change the default password after first login (Settings → Users → Change password).

### After install

1. **Configuration → Datasets → Refresh All** — pulls NVD + CISA KEV + EPSS feeds (faster with `NVD_API_KEY` set in `.env`)
2. Visit **Threat Intel** to confirm the catalog populated
3. Create a scan profile under **Profiles**, then launch a scan from **Scan Jobs**

---

## Application Menu

| Section | Page | Purpose |
|---------|------|---------|
| **Overview** | Dashboard | Posture overview, recent activity, Threat Intel band |
| **Scanning** | Assets | Asset folders + scan history rollups |
|  | Scan Jobs | Live + historical jobs with progress tracking |
|  | Profiles | Reusable scanner configurations (plugins + SSH credentials) |
|  | Reports | Generated reports + report templates |
| **Intelligence** *(v3.0)* | Threat Intel | Fused NVD+EPSS+KEV CVE view with threat scoring |
| **Configuration** | Credentials | Encrypted storage for SSH keys, passwords, API tokens |
|  | Datasets | Manage NVD / KEV / EPSS / CVE.org / Compliance feeds |
|  | Settings | General, users, integrations, SLA presets, allowlist |

---

## Scanner Plugins

**53 plugins total**, opt-in via profile selection. Plugins use a dependency-resolved pipeline so e.g. CPE matching runs after fingerprinting.

### Network & Discovery (8)

| Plugin | Description |
|--------|-------------|
| `port_scan` | TCP port discovery (top 100/1000) |
| `nmap_portscan` | Full port range + service banners via Nmap |
| `udp_portscan` *(v3.0)* | Top-35 UDP ports with protocol-specific probes |
| `dns_enum` | Subdomain enumeration + zone transfer |
| `banner_grabber` | Multi-protocol service version banners |
| `http_fingerprint` | HTTP server headers + technology disclosure |
| `tls_basic` | TLS version, cipher strength, certificate expiry |
| `ssl_ct` | SSL Certificate Transparency log discovery |

### Fingerprinting (4)

| Plugin | Description |
|--------|-------------|
| `web_tech` | CMS/framework detection (WordPress, Drupal, React, etc.) |
| `deep_fingerprint` | Technology-specific version detection |
| `favicon_hash` | Favicon hash-based service identification |
| `cpe_builder` | Builds CPE 2.3 strings from fingerprint data |

### Web Application Security (21)

| Plugin | Description |
|--------|-------------|
| `owasp_scanner` | OWASP Top 10 (2025) active tests (SQLi, XSS, XXE, CSRF, SSRF, etc.) |
| `advanced_xss` | Reflected + stored XSS, 30+ payloads, polyglot, WAF bypass |
| `deep_sqli` | Error/boolean/time-blind/UNION/stacked SQLi with WAF bypass |
| `deep_cmdi` | OS command injection, in-band + blind time-based, Linux + Windows |
| `dir_crawl` | Directory and file discovery (80+ paths) |
| `file_inclusion` | LFI/RFI with advanced bypass techniques |
| `security_headers` | 7-header audit + CORS + cookie flags (A–F grade) |
| `jwt_scanner` | JWT alg:none bypass, weak HMAC keys, missing claims |
| `graphql_scanner` | GraphQL introspection, sensitive fields, depth/batch abuse |
| `api_key_exposure` | 22 API key patterns (AWS, GitHub, Slack, Stripe, etc.) + .env |
| `host_header_injection` | Host header manipulation testing |
| `crlf_injection` | CRLF injection in HTTP headers |
| `ssti_scanner` | Server-Side Template Injection (Jinja2, Twig, Freemarker, etc.) |
| `waf_detection` | WAF detection and bypass testing |
| `rate_limit_check` | Rapid-request burst on login endpoints |
| `open_redirect` | Unvalidated redirects to external domains |
| `ldap_injection` | LDAP anonymous bind + filter injection |
| `nosql_injection` | MongoDB operator injection ($gt, $ne, $regex) for auth bypass |
| `ssrf_deep` | Cloud metadata SSRF (AWS / GCP / Azure) |
| `websocket_check` | WS endpoint discovery, unauthenticated access, cross-origin hijack |
| `unauth_api` | 50+ common API paths tested without auth token |

### Authentication (1)

| Plugin | Description |
|--------|-------------|
| `web_auth` *(v3.0)* | Establishes authenticated HTTP session for downstream web plugins |

### Infrastructure Security (9)

| Plugin | Description |
|--------|-------------|
| `ssh_audit` | Weak key exchange, deprecated ciphers, SSHv1 |
| `ssh_inventory` | SSH-authenticated package collection |
| `smb_check` | Anonymous/null session, SMBv1 detection |
| `db_auth_check` | Default credentials for Redis, MongoDB, MySQL, PostgreSQL, Elasticsearch |
| `snmp_community` | SNMP community string brute force |
| `ftp_anon` | FTP anonymous access testing |
| `redis_noauth` | Redis no-auth deep inspection |
| `docker_api` | Exposed Docker API detection |
| `k8s_api` | Kubernetes API (6443), Kubelet (10250/10255), etcd (2379) |

### IoT (1)

| Plugin | Description |
|--------|-------------|
| `mqtt_scanner` | MQTT anonymous access, topic enumeration, publish injection |

### Cloud (1)

| Plugin | Description |
|--------|-------------|
| `cloud_storage_misconfig` | AWS S3, GCS, Azure Blob misconfiguration |

### API Security (1 — sub-package with 15 sub-checks)

| Plugin | Description |
|--------|-------------|
| `api_scanner` | OpenAPI / Swagger / Postman ingestion + dispatch to: `sqli`, `xss`, `ssti`, `cmdi`, `xxe`, `ssrf`, `code_injection`, `type_confusion`, `jwt_checks`, `bola`, `mass_assignment`, `excessive_data`, `config_checks`, `spec_hygiene`, `graphql` |

### CVE Matching & Prioritization (7)

| Plugin | Description |
|--------|-------------|
| `nvd_match` | CPE → CVE matching against NVD database |
| `cms_match` | CMS-specific CVE detection |
| `cve_packages` | Package-based CVE matching (after `ssh_inventory`) |
| `cisa_kev` | CISA Known Exploited Vulnerabilities prioritization |
| `cve_verifier` | Cross-references OWASP findings with CVE CWE categories |
| `endpoint_prober` | Safe HTTP endpoint probes for known CVE patterns |
| `local_security` | Linux distro advisory matching |

### Standalone scanners (not engine plugins)

These run as separate scan types via dedicated endpoints, not as part of a normal scan pipeline:

| Scanner | Endpoint | Purpose |
|---------|----------|---------|
| **API Scanner** | `POST /scan/api-scanner/jobs` | Standalone OpenAPI/Swagger/Postman scan |
| **IaC Scanner** *(v3.0)* | `POST /scan/iac/jobs` | Static analysis of Terraform / Docker / K8s / CFN / Helm bundles |

---

## Threat Intelligence

VulnScan ships **two complementary threat-intel surfaces**:

### 1. Threat Intel page *(new in v3.0)*

A unified CVE-centric view at **Intelligence → Threat Intel** that fuses NVD + EPSS + CISA KEV per CVE.

**Composite threat score (0–100)**

```
40% × CVSS/10
+ 35% × EPSS percentile
+ 15% × KEV bonus (with +3 ransomware kicker)
+ 10% × recency bonus on KEV-add date (≤7d=10, ≤30d=7, ≤90d=4)
```

**Filters:** severity, "CISA KEV only", "Ransomware-known", EPSS ≥ threshold, free-text search
**Sort by:** threat score / CVSS / EPSS / KEV due date / KEV added date
**Detail drawer:** severity card, exploitation card, description, CISA KEV notes, vendor/product, affected CPEs, references

**Stat tiles:** CVEs in catalog · CISA KEV listed · KEV due in 7 days · Ransomware-known

### 2. Dataset Browser

Raw browsing of all 6 threat intel datasets at **Configuration → Datasets**.

| Dataset | Source | Records | Auto-Refresh |
|---------|--------|---------|:------------:|
| **NVD** | NIST NVD API | ~200K CVEs | ✓ |
| **CVE.org** | CVE.org API (CNA/ADP scores) | ~50K | ✓ |
| **CISA KEV** | CISA KEV feed | ~1K | ✓ |
| **EPSS** | FIRST EPSS scores | ~200K | ✓ |
| **CMS-CVE** | Generated from NVD | ~5K | ✓ |
| **Compliance** | Static mapping | ~50 controls | ✓ |

One-click refresh from the UI, or via CLI scripts under `scripts/`. Supports offline dataset upload for air-gapped environments.

---

## Authenticated Web Scanning

*(New in v3.0 — see [Changelog](#changelog) for full notes.)*

Configure per-scan from the **New Scan** dialog when scan type = **Web App**.

**Five auth modes:**

| Mode | When to use |
|------|-------------|
| **Form login** | Standard HTML login forms (most apps) |
| **Bearer token** | OAuth2 / JWT tokens |
| **HTTP Basic** | Legacy intranet apps |
| **Static cookie(s)** | Pre-existing session you've captured |
| **Static header(s)** | API-key or custom-header schemes |

**Login Form Inspector:** click `Inspect` next to the login URL → the platform fetches the page, parses HTML forms, ranks them, auto-fills username/password/CSRF field names. Detects reCAPTCHA, hCaptcha, Cloudflare Turnstile, and JS-rendered SPA logins (with warnings).

**Test Login pre-flight:** one-shot button before launching the full scan. Returns success / cookies / error so you can debug auth before a 30-minute scan.

**Credential lifecycle:**

- **Saved:** picked from the encrypted Credentials store; never appears in `options_json`
- **Inline:** type once for one-off use
- **Save as credential:** create from inline values for next time
- **Auto-delete after scan:** ephemeral workflow — credential is created, used, deleted in worker `finally:` block (any outcome)

**Smart suggestions:** when the inspected form has an email-typed username field, credentials whose username contains `@` are sorted to the top with a "✓ matches email field" badge.

---

## IaC Scanner

*(New in v3.0.)* Static analysis of Infrastructure-as-Code bundles.

**Endpoints**

```
POST /scan/iac/parse        # preview the file inventory
POST /scan/iac/jobs         # launch the scan
GET  /scan/iac/kinds        # list supported formats
```

**Upload:** ZIP archive (5 MB cap, 2000 files / 2 MB each, path-traversal-safe) or single config file.

**Supported formats and rule highlights:**

| Format | Rules |
|--------|-------|
| **Terraform** | Hardcoded secrets, public S3 ACL, open security groups (0.0.0.0/0), public RDS |
| **Dockerfile** | No USER directive, `:latest` tag, USER root, ADD remote URL, secret ENV/ARG, `curl\|sh` |
| **Kubernetes** | Privileged, hostNetwork/PID/IPC, runAsUser:0, allowPrivilegeEscalation, CAP_SYS_ADMIN, default namespace, missing limits |
| **docker-compose** | Privileged services, host network, `/var/run/docker.sock` mount, latest tag |
| **CloudFormation** | Public S3, missing BucketEncryption, open SGs, public RDS, StorageEncrypted=false |
| **Helm values.yaml** | Reuses K8s rules |

**30+ rules total**, each with severity, framework tag (CIS / NIST), and remediation guidance.

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
|------|--------------|
| **Validate** | Classifies each finding as True Positive / False Positive / Needs Manual |
| **Full Analysis** | Executive summary, attack chain identification, remediation priority |
| **Full + PoC** | Full analysis + proof-of-concept exploit scripts for confirmed findings |

### Per-Finding PoC Generation

Click "Generate PoC" on any individual finding to get an AI-generated Python exploit script with step-by-step exploitation code, comments, copy button, and safety disclaimer.

---

## Scan Flow

```
1. Web Auth          ─→ Establish authenticated session (if configured)
2. Port Discovery    ─→ TCP / UDP port scanning
3. Service Fingerprint ─→ Banners, HTTP headers, TLS, web tech
4. Deep Fingerprint  ─→ Version-specific detection, favicon hash
5. CPE Construction  ─→ Build CPE 2.3 URIs from fingerprint data
6. CVE Matching      ─→ NVD + CMS + package-based matching
7. Active Testing    ─→ OWASP, SQLi, XSS, SSTI, CRLF, etc. (with auth session)
8. Infrastructure    ─→ SSH, SMB, SNMP, MQTT, Docker, Redis, K8s
9. Prioritization    ─→ CISA KEV, EPSS, threat-score, risk scoring
10. Compliance       ─→ NIST 800-53, PCI DSS, CIS, ISO 27001
11. Attack Graph     ─→ Neo4j graph modeling
12. Cleanup          ─→ Ephemeral credentials deleted (if configured)
```

---

## Risk Scoring

```
Risk = (CVSS × exploit_weight) + KEV_bonus + asset_criticality × confidence
```

The **Threat Intel page** uses a richer composite score that also factors in EPSS percentile and recency.

### Asset Criticality Levels

| Level | Label | Multiplier | Use For |
|:-----:|-------|:----------:|---------|
| 1 | Low (Dev/Test) | ×0.8 | Dev servers, sandbox, staging |
| 2 | Normal | ×1.0 | Internal tools, standard workstations |
| 3 | High (Business-critical) | ×1.1 | Production apps, internal APIs |
| 4 | Critical (Customer data) | ×1.2 | Payment systems, databases with PII |
| 5 | Maximum (Regulatory) | ×1.3 | HIPAA/PCI systems, SCADA, public-facing auth |

### SLA Presets

Configurable under **Settings → SLA Policies**. Built-in presets:

| Preset | Critical | High | Medium | Low |
|--------|---------|------|--------|-----|
| **Custom** (default) | 2d | 7d | 30d | 90d |
| **PCI DSS 4.0** | 1d | 7d | 30d | 90d |
| **HIPAA** | 7d | 30d | 60d | 90d |
| **SOC 2 Type II** | 7d | 30d | 60d | 180d |
| **ISO 27001** | 14d | 30d | 60d | 180d |
| **CISA KEV (BOD 22-01)** | per CISA due-date | 14d | 30d | 90d |

---

## Export & Reporting

| Location | Scope | Formats |
|----------|-------|---------|
| Reports page | Per-scan-job | CSV, HTML, PDF |
| Per-host expand | Single host only | CSV, HTML, PDF |
| Bulk selection | Multiple hosts | CSV, HTML, PDF |
| AI Analysis | Full analysis report | In-app viewer + export |
| Report Templates | Customizable section list, severity filter, branding | Per-template |

---

## Integrations

| Provider | Purpose | Config |
|----------|---------|--------|
| **Slack** | Webhook notifications on scan complete / critical findings | Incoming webhook URL |
| **Microsoft Teams** | Adaptive Card webhook notifications | Incoming webhook URL |
| **Generic Webhook** | POST events to your own HTTP endpoint | URL + optional bearer secret |
| **Email (SMTP)** | Email alerts for findings above threshold | SMTP host, port, user, pass, from, to |

All integrations support **per-provider Test buttons** that send a real test message before saving. v3.0 fixed the silent-failure UX bug from v2.x.

---

## Configuration

### Environment Variables (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing key (also used for credential encryption) | `dev-secret-CHANGE-ME` |
| `DATABASE_URL` | PostgreSQL connection | `postgresql+psycopg2://app:app@db:5432/app` |
| `REDIS_URL` | Redis connection | `redis://redis:6379/0` |
| `SCAN_BUDGET_SECONDS` | Max wall-clock duration per scan | `900` (15 min) |
| `SCAN_TIMEOUT_SECONDS` | Default per-plugin timeout | `60` |
| `ALLOWLIST` | CIDR ranges / domain suffixes allowed for internal scans | `*` |
| `NVD_API_KEY` | NVD API key (5× faster dataset refresh) | (optional) |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI key | (optional) |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint | (optional) |
| `CLAUDE_CLI_ENABLED` | Enable Claude CLI provider | `false` |
| `GEMINI_API_KEY` | Google Gemini key | (optional) |
| `BACKEND_PORT` | API server port | `8888` |
| `FRONTEND_PORT` | Web UI port | `5173` |

### Updating

VulnScan ships a **one-click update** under **Settings → System**. The host-level updater service (install once via `scripts/install-updater.sh`) handles `git pull` + `docker compose build` + `up -d` while preserving `.env`.

For manual updates:

```bash
git pull
docker compose build
docker compose up -d
# Hard-refresh the browser to bust the cached JS bundle
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete history.

### Recent releases

- **v3.0.0 — 2026-05-03** — Authenticated web scanning, login form inspector, Threat Intel page, IaC scanner, UDP scanner, ephemeral credentials, integrations rewrite, password management
- **v2.1.4 — 2026-04-14** — Tier-4/5 plugins (advanced XSS, deep SQLi, deep CMDi), API scanner sub-package, global scan budget, soft dependencies
- **v2.1.3 — 2026-04-05** — 9 new plugins (CT logs, rate limit, open redirect, LDAP/NoSQL injection, deep SSRF, WebSocket, K8s API, unauth API), one-click platform update, scan cancel, Teams integration
- **v2.1.2 — 2026-04-02** — Multi-provider AI Deep Analysis, 14 new plugins, Security Information Browser, dataset refresh from UI
- **v2.1.0 — 2026-03-14** — Distro-patch detection, validation states with confidence caps, bootstrap script
- **v1.0.0 — 2026-03-05** — Initial release (17 plugins, risk engine, compliance mapping, Neo4j graph, CSV/HTML/PDF export)

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built by <a href="https://github.com/Gondrong">Gondrong</a></sub>
</p>
