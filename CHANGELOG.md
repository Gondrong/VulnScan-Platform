# Changelog

All notable changes to VulnScan Platform are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Earlier versions (v1.0.0 – v2.1.3) are also documented in `README.md`.

---
## v3.0.4 — 2026-07-29

### Security Hardening

**Bcrypt Password Hashing (replaces SHA256)**

- Replaced all SHA256 password hashing with **bcrypt** (`bcrypt>=4.1.0`) — SHA256 without salt is trivially reversible via rainbow tables; bcrypt uses per-password salts and adaptive cost factor.
- New centralized module `app/core/password.py` with three functions: `hash_password()`, `verify_password()`, `needs_rehash()`.
- **Automatic migration**: existing SHA256 hashes are transparently upgraded to bcrypt on next successful login — no manual password reset required, no downtime.
- All password operations updated: login (`routes_auth.py`), user creation (`routes_settings.py`), password change, and admin password reset.
- Default admin user created at startup now uses bcrypt.

**CORS Origin Restriction**

- Default `CORS_ORIGINS` changed from `"*"` (allow all) to `"http://localhost:5173,http://localhost:8888"`.
- New `CORS_ORIGINS` entry in `.env` for easy configuration.
- Backend logs a warning at startup if CORS is still set to `"*"`.
- Production deployments should set `CORS_ORIGINS` to their specific domain(s).

**Rate Limiting on Login Endpoint**

- New Redis-backed sliding-window rate limiter (`app/core/rate_limit.py`) applied to `POST /auth/login`.
- Default: **5 requests per 60 seconds per IP** — blocks brute-force and credential-stuffing attacks.
- Returns HTTP `429 Too Many Requests` with `Retry-After` header when exceeded.
- **Fail-open**: if Redis is unavailable, login continues to work (no lockout risk).
- Tracks requests via Redis sorted sets with automatic key expiry.

### Added

**React Error Boundary**

- New `ErrorBoundary` component (`frontend/src/components/ErrorBoundary.jsx`) wraps the entire `<App/>` in `main.jsx`.
- Catches unhandled JavaScript errors and renders a fallback UI with error details and a "Reload page" button instead of a blank white screen.
- Styled to match the app's dark/light/dim theme using CSS variables.
- Resolves the roadmap item "Top-level React error boundary" from v3.0.0.

### Changed

- `requirements.txt` — added `bcrypt>=4.1.0`.
- `main.py` — removed inline `_hash()` function; imports `hash_password` from `app.core.password`.
- `frontend/src/main.jsx` — moved `responsive.css` import to top-level; wrapped `<App/>` with `<ErrorBoundary>`.

### Migration notes

- **No DB migration required** — bcrypt hashes are stored in the same `password_hash` column (bcrypt hashes start with `$2b$`, SHA256 are 64-char hex — the verifier auto-detects).
- **Backward compatible** — users with old SHA256 hashes can still log in; their hash is silently upgraded to bcrypt on next login.
- **CORS change** — if you access VulnScan from a non-localhost URL, add your origin to `CORS_ORIGINS` in `.env` (comma-separated). Set to `*` to restore the old behavior (not recommended).
- Run `docker compose up -d --build` to apply.

---
## v3.0.3 — 2026-06-19

### Added

**7 External Pentest Tool Integrations**

Integrated industry-standard pentesting tools directly into the Docker runtime. All tools run automatically on every scan — zero user configuration required.

| Tool | Version | Plugin ID | Description |
|------|---------|-----------|-------------|
| **Nmap** | 7.95 | `ext.nmap` | Real nmap binary with `-sV` service/version detection. Merges results with built-in port scanner. Provides `net.open_ports` + `net.service_banners` artifacts for all downstream plugins |
| **Nuclei** | 3.3.7 | `ext.nuclei` | ProjectDiscovery template-based scanning — 8000+ community templates for CVEs, misconfigurations, and exposures. Auto-scans non-standard ports discovered by nmap |
| **testssl.sh** | 3.2 | `ext.testssl` | Deep TLS/SSL audit — tests for Heartbleed, ROBOT, POODLE, CRIME, BREACH, DROWN, FREAK, Logjam, Sweet32, Lucky13, weak ciphers, cert chain issues, HSTS. Far more comprehensive than the built-in `tls.basic` plugin |
| **ffuf** | 2.1.0 | `ext.ffuf` | Fast web fuzzer for directory/file discovery with bundled SecLists wordlists (35k entries). Auto-detects sensitive paths (.env, .git, wp-config, backup files, admin panels, config files). Results feed into `recon.directories` for downstream plugins |
| **subfinder** | 2.6.7 | `ext.subfinder` | Passive subdomain enumeration via 20+ sources (crt.sh, Shodan, VirusTotal, SecurityTrails) without sending traffic to the target. Only runs for domain targets (skips IPs). Produces `recon.subdomains` artifact |
| **httpx** | 1.6.9 | `ext.httpx` | HTTP probing + technology detection. Probes subdomains from subfinder and open ports from nmap. Detects CMS platforms, exposed admin panels (Jenkins, phpMyAdmin, Kibana), and tech stack |
| **sqlmap** | 1.10.6 | `ext.sqlmap` | Advanced SQL injection with 100+ bypass techniques (boolean-blind, time-blind, error-based, UNION, stacked queries). Runs in safe non-destructive mode. Tests URLs discovered by ffuf and dir_crawl |

**Intelligent Execution Pipeline**

Tools are ordered by dependency resolution so each tool's output feeds the next:

```
nmap (ports) → subfinder (subdomains) → httpx (probe live services)
            → testssl.sh (TLS audit on discovered TLS ports)
            → ffuf (directory fuzzing) → nuclei (template scanning)
                                       → sqlmap (SQLi on discovered URLs)
```

**Bundled Wordlists**
- `/opt/wordlists/common.txt` — 4,750 common web paths
- `/opt/wordlists/raft-medium-directories.txt` — 30,000 directory names from SecLists

**Profile Options for External Tools**

Each tool accepts per-scan configuration via profile `options_json`:

```json
{
  "nmap": {"mode": "top1000", "timing": "T4"},
  "nuclei": {"severity": "critical,high", "tags": "cve", "exclude_tags": "dos"},
  "ffuf": {"threads": 40, "rate": 100, "wordlist": "/opt/wordlists/common.txt"},
  "subfinder": {"timeout": 30, "recursive": false},
  "httpx": {"threads": 25, "rate": 50},
  "sqlmap": {"level": 1, "risk": 1, "crawl": 2, "threads": 3}
}
```

**NVD API Retry Logic**
- Added `_ds_fetch_url_retry()` with exponential backoff (10s → 20s → 40s, max 3 retries) for NVD dataset refresh.
- Retries only on transient errors: HTTP 429, 500, 502, 503, 504, timeouts, and connection errors.
- Permanent errors (e.g. 403 Forbidden) fail immediately without retry.
- Applied to both the first-page fetch and all subsequent paginated requests.
- Prevents dataset refresh failures due to temporary NVD API outages.

### Changed

- **Plugin count:** 53 → 60 (7 new external tool plugins)
- **Dockerfile:** Added testssl.sh, ffuf, subfinder, httpx, sqlmap installations + SecLists wordlists
- **Plugin loader:** Registered all 7 external tool modules with correct dependency ordering

---
## v3.0.2 — 2026-05-14

### Added

**Credential Editing**
- New `PUT /credentials/{cred_id}` backend endpoint — updates name, kind, username, secret type, secret, and passphrase individually (all fields optional; secret left unchanged if omitted).
- Frontend Edit button (pencil icon) on each credential row in the Credentials table.
- The existing New Credential modal now supports edit mode: fields pre-filled, secret field shows "(leave blank to keep current)" and is optional, title and button text adapt automatically.

**Automatic Updater Service Installation**
- `bootstrap.sh` now automatically installs the `vulnscan-updater.service` systemd unit during first-time setup, enabling one-click platform updates from Settings → System without a separate manual step.
- Skips gracefully if the service is already active, if not running as root/sudo, or if systemd is not available.

### Changed

**Scanner False-Positive Prevention — Dynamic Parameter Pre-Checks**

Added a pre-check pattern across 14 scanner plugins. Before running heuristic detection (boolean-blind, time-blind, response-diffing), the scanner now verifies that the parameter actually influences the server's response. If the response is identical regardless of value, heuristic detection is skipped — eliminating an entire class of false positives.

*High-priority plugins (response-diffing / timing heuristics):*
- **`web.deep_sqli`** — Dynamic pre-check gates boolean-blind and UNION-based sections; baseline validation requires boolean difference to exceed `natural_variation * 2 + 50` or show asymmetric distance from baseline.
- **`web.advanced_xss`** — Second-marker confirmation for both GET and POST reflected XSS; verifies reflection is genuinely input-dependent before testing payloads.
- **`web.deep_cmdi`** — Dynamic pre-check after baseline; time-based blind sections (Linux + Windows) gated behind `param_is_dynamic`; in-band marker detection left ungated.
- **`web.nosql_injection`** — Baseline stability check with alternate credentials; auth-bypass detection now requires `baseline_stable` and response delta exceeding `natural_len_variation * 2 + 50`.
- **`api.scanner.sqli`** — Dynamic pre-check; boolean-blind gated behind `param_is_dynamic` with baseline validation (same pattern as `deep_sqli`).
- **`api.scanner.cmdi`** — Dynamic pre-check; blind time-based section gated behind `param_is_dynamic`.

*Medium-priority plugins (indicator matching / similarity heuristics):*
- **`api.scanner.bola`** — Two-identity check now verifies endpoint is ID-dependent (different IDs must return different data); neighbor-walk verifies endpoint rejects implausible IDs before declaring IDOR.
- **`api.scanner.xss`** — Second-marker confirmation before payload testing.
- **`web.ssrf_deep`** — Baseline body saved; cloud metadata indicators only counted if absent from the endpoint's normal response.
- **`api.scanner.ssrf`** — Same baseline-filtered indicator matching.
- **`web.open_redirect`** — Benign probe URL sent first; parameter must trigger a redirect with input-controlled Location header before testing evil payloads.

*Low-priority plugins (implicit safeguards strengthened):*
- **`web.ssti.scanner`** — Per-parameter baseline; expected math result (e.g. "49") must not already be present in baseline response.
- **`api.scanner.ssti`** — `param_is_dynamic` check skips static parameters entirely.
- **`api.scanner.code_injection`** — `param_is_dynamic` gates time-based detection; math-based and in-band detection retain existing `expected not in bl.body` guard.
- **`web.ldap_injection`** — Baseline LDAP error pattern check; skips payload loop if endpoint naturally contains LDAP error strings.

**AI Analysis Prompts Overhaul**
- Shared `_SCANNER_CONTEXT` block injected into all system prompts: explains VulnScan's data format (`plugin_id` namespaces, `key=value` evidence parsing, confidence calibration, `is_kev` meaning) and documents 6 common false-positive patterns.
- `_serialize_finding` — increased evidence (300→600), description (500→800), and remediation (200→500) character limits; added `references` field.
- `_truncate_findings` — now sorts by severity then descending confidence; summary items include confidence scores.
- **Validate mode** — new 6-step validation methodology (evidence audit → technology coherence → confidence calibration → cross-correlation → context plausibility → severity adjustment).
- **Full analysis mode** — kill-chain-based attack chain guidance (initial access → lateral movement → impact); 4-factor remediation prioritization with `rationale` field.
- **Full + exploit mode** — three-phase PoC structure requirement (recon → exploit → verify); vulnerability-specific PoC guidance per plugin class (SQLi technique matching, XSS context escape, auth bypass, info disclosure, TLS/crypto, SSRF).
- **Single-finding PoC mode** — complete rewrite with field-by-field evidence parsing instructions per vulnerability type; structured phase headers (`[*] Recon`, `[*] Exploit`, `[*] Verify`) and PASS/FAIL summary requirement.
- **User prompts** — now include KEV count and high-confidence finding count as metadata; evidence pre-parsed into structured key-value dict for PoC prompts.

### Fixed

**Claude CLI "Reached max turns" Error**
- `ClaudeCLIProvider` and `GenericCLIProvider` (claude style) increased `--max-turns` from `1` to `5` — the `full_exploit` prompt was triggering internal tool use that exhausted the single allowed turn, returning `"Error: Reached max turns (1)"` instead of analysis JSON.
- Both providers now detect CLI error messages on stdout (strings starting with `"Error:"` under 200 chars) and raise `RuntimeError` immediately instead of passing them to the JSON parser.

---
## v3.0.1 — 2026-05-07

### Added
**Neo4j Attack Graph — Major Overhaul**
- Rebuilt the graph engine with auto-indexing on startup, new node types (Plugin, Compliance, AssetGroup), and relationships (DETECTED, VIOLATES, CONTAINS) for richer attack path modeling.
- Added five new analytical queries: Attack Map visualization, Shared Vulnerabilities for patch prioritization, Blast Radius analysis per asset, workspace-level graph statistics, and Most Vulnerable Assets ranking.
- Non-CVE findings are now included in the graph using fingerprint-based identification.
- Added incremental sync mode (`full=false`) so graph updates no longer require a full rebuild.
- New graph API endpoints: `GET /shared-vulns`, `GET /blast-radius/{target}`, `GET /stats`, `GET /most-vulnerable`.

**Notification Preferences System**
- Added workspace-level notification preferences API (`GET/PUT /notifications`, `POST /notifications/reset`) supporting per-event channel configuration for critical findings, CISA KEV matches, scan completion, scan failure, new asset discovery, and weekly digest across email, Slack, and webhook channels.
- Wired scan failure notifications into the worker pipeline with automatic delivery via configured integrations.

**AI Provider Management**
- Added `AiProviderConfig` database model and migration for storing multi-provider AI configurations with encrypted API keys.
- Rebuilt the Settings AI panel with full CRUD: add, delete, enable/disable, and test providers with type-specific metadata and model suggestions for OpenAI, Claude, Gemini, Azure OpenAI, and OpenAI-compatible endpoints.

**Frontend — Attack Graph Page**
- New Attack Graph page with D3 force-graph visualization accessible from the sidebar.
- Settings page now supports deep-linking to specific tabs via `initialTab` prop.

### Changed
**RBAC Improvements**
- Credentials API now enforces role-based access (`admin`/`analyst`/`viewer`) instead of generic authentication.
- Frontend UI actions (add, edit, delete, refresh) are now gated behind `canEdit()` and `isAdmin()` role checks throughout.

**Scan Job Tracking**
- Scan jobs now record `created_by_user_id` and display the creator's username in job listings and detail views.

**Dataset Refresh Hardening**
- Added `vendor_advisories` as a new dataset kind with full refresh pipeline support.
- Threat intelligence cache is now automatically invalidated when feeder datasets are modified or deleted.
- Protected canonical dataset files from accidental deletion and added file existence verification before disabling old records.
- Increased refresh lock timeout from 30 to 60 minutes and improved CVE.org batch checkpoint logic.

**Settings & Frontend Enhancements**
- Settings page filters sections by user role with `minRole` properties.
- New Notification Preferences panel with auto-save toggles and reset-to-defaults.
- SLA policy panel now supports adding/removing notification channels per severity level.

### Fixed
- Dataset refresh double-fire bug fixed using ref-based deduplication.
- Added `restart: unless-stopped` to database, Redis, and Neo4j containers for improved reliability.

---

## v3.0.0 — 2026-05-03

### Added

**Authenticated Web Scanning** — new top-level capability

- New `web.auth` plugin (53 plugins total, up from 51) that establishes an authenticated HTTP session for downstream scanners. Supports **five auth modes**: form login (with auto-CSRF harvest), bearer token, HTTP Basic, static cookies, static request headers.
- Shared `app/scanner/auth_session.py` helper performs the actual login flow.
- Shared `app/scanner/login_inspector.py` parses login pages.
- Result is published to the `web.auth_session` artifact; the OWASP scanner now soft-depends on `web.auth` and applies the resulting cookies/headers to its `httpx.AsyncClient`. Other web plugins inherit the same session.
- Credentials live in the existing encrypted Credentials store and are decrypted at scan time only — they never appear in `options_json`.

**Login Form Inspector**

- `POST /scan/web-auth/inspect` fetches a login page and returns ranked forms with field types, CSRF candidates, and warnings (reCAPTCHA / hCaptcha / Cloudflare Turnstile / JS-rendered SPA hints).
- SSRF-guarded against private / loopback / link-local / metadata IPs.
- Form action URLs are auto-resolved (form action ≠ login URL is now handled correctly — common in WordPress, Django, ASP.NET WebForms).

**Web Auth on the New Scan dialog** (architectural shift)

- Web Authentication panel **moved** from the Profile modal to the New Scan dialog — it's target-specific, not profile-shared. The Profile modal now owns only the scanner config (plugins + SSH credential).
- **Smart credential suggestions**: when the inspected form's username field is `type="email"`, credentials whose username contains `@` are sorted to the top with a "✓ matches email field" badge.
- **Empty-state CTA** when no credentials exist.
- **Save as credential** checkbox creates a permanent credential from inline values.
- **Auto-delete after scan** — ephemeral credential workflow for one-off pentests. Credential is created at scan launch and deleted in the worker's `finally:` block on any outcome (done / failed / cancelled).
- New `web_auth_credential_ephemeral` field on `POST /scan/jobs`.

**Test Login**

- `POST /scan/web-auth/test-login` runs the auth flow once against the target and returns `{success, cookie_names, header_names, evidence, error}` so users can verify credentials before kicking off a long scan.
- Inline result panel on the New Scan dialog. Cookie/header names are returned but **not values** — safe to log.

**Threat Intelligence page** (new top-level menu)

- New "Intelligence" sidebar section with the **Threat Intel** entry, sitting between Scanning and Configuration.
- Fuses NVD + EPSS + CISA KEV by CVE-ID into a single CVE-centric view.
- **Composite threat score (0–100)** = 40% CVSS + 35% EPSS percentile + 15% KEV bonus + 10% recency bonus on KEV-add date.
- Filter chips: severity, CISA KEV only, ransomware-known, EPSS ≥ threshold, free-text search.
- Sort by threat score / CVSS / EPSS / KEV due date / KEV added.
- Detail drawer per CVE: severity card, exploitation card, description, CISA notes, vendor/product, affected CPEs (up to 50), references.
- Four stat tiles: CVEs in catalog / KEV listed / KEV due in 7 days / Ransomware-known.
- New endpoints: `GET /threat-intel/cves`, `GET /threat-intel/cves/{id}`, `GET /threat-intel/stats`, `POST /threat-intel/refresh`.
- Per-workspace in-memory cache (5-min TTL), auto-invalidates when datasets rotate.

**Threat Intel Dashboard band**

- New band on the main Dashboard with 4 mini-tiles (New KEV 7d / KEV due 7d / Ransomware-known / High EPSS ≥50%).
- Each tile is clickable and navigates to the Threat Intel page.
- Auto-hides when no feeder datasets are loaded.

**UDP Port Scanner** — new plugin

- `udp_portscan` probes top-35 UDP ports (DNS, NTP, SNMP, NetBIOS, mDNS, SSDP, IKE, memcached, BACnet, IPMI, etc.) with protocol-specific payloads.
- Severity-graded findings for risky exposed services: memcached UDP=critical, IPMI=high, BACnet=high, NFS=high, NetBIOS=medium.
- Disabled by default — opt-in per profile.

**Infrastructure-as-Code Scanner** — new sub-package

- `app/scanner/plugins/iac_scanner/` (parser + rules + orchestrator).
- New endpoints: `POST /scan/iac/jobs`, `POST /scan/iac/parse`, `GET /scan/iac/kinds`.
- Accepts ZIP archive or single config file (5 MB cap, 2000 files / 2 MB each, path-traversal safe).
- 30+ rules across six IaC formats:
  - **Terraform** — hardcoded secrets, public S3 ACL, open security groups (0.0.0.0/0), public RDS.
  - **Dockerfile** — no USER, `:latest` tag, USER root, ADD remote URL, secret ENV/ARG, `curl|sh`.
  - **Kubernetes** — privileged, hostNetwork/PID/IPC, runAsUser:0, allowPrivilegeEscalation, CAP_SYS_ADMIN, default namespace, missing limits.
  - **docker-compose** — privileged services, host network, `/var/run/docker.sock` mount, latest tag.
  - **CloudFormation** — public S3, missing BucketEncryption, open SGs, public RDS, StorageEncrypted=false.
  - **Helm values.yaml** — reuses K8s rules.

**User password management**

- `PUT /settings/users/me/password` — any authenticated user can change their own password (verifies current password + 6-char minimum).
- `PUT /settings/users/{user_id}/password` — admin-only password reset for any workspace user.
- Frontend `settingsApi.changePassword()` and `settingsApi.resetPassword()`.
- Updates `users.updated_at` timestamp on change.

### Changed

**Integrations overhaul** (Slack / Teams / Webhook / Email)

- Test buttons no longer disabled until the integration is saved (was the silent-failure bug from v2.x).
- 422 validation errors now render as readable strings — `api.js` flattens FastAPI's array-of-errors into `"loc: msg; loc: msg"` instead of `[object Object]`.
- Generic webhook URL field renamed `webhook_url` → `url` (matches notifier).
- Webhook auth header field renamed `auth_header` → `secret`.
- Email field names corrected to match the notifier: `smtp_password` → `smtp_pass`, `from_addr` → `from_email`, `to_addrs` → `to_email`.
- New `DELETE /integrations/{provider}` endpoint and Remove button in the modal.
- Test endpoint accepts an optional body — falls back to saved config when not supplied.
- Per-provider client-side validation pre-checks before round-trip.

**Scanner engine**

- Form login now POSTs to the form's actual `<form action="…">` URL (passed as `action_url` in the auth config), not blindly to `login_url`. Older sites where action ≠ login URL now work.
- `_set_default_artifacts` extended to cover the new `web.auth_session`, `net.open_udp_ports`, and `net.udp_service_responses` keys.

**Threat Intel cache**

- `_swap_dataset` in the worker now invalidates the Threat Intel cache when NVD / KEV / EPSS get rotated.

**API client hardening**

- Threat Intel UI normalizes API responses with strict type checks (`Number.isFinite`, `Array.isArray`) — guards against partial responses, reverse-proxy-injected HTML, and other unexpected shapes.

### Fixed

- Form login authentication failing silently when the form's `action` URL differs from the `login_url` (e.g., WordPress's `/wp-login.php` posting to itself with redirects).
- Integrations Test button click being a no-op the first time (button was `disabled` until the integration was saved).
- 422 errors from FastAPI rendering as `[object Object]` in error toasts.
- Threat Intel page going blank if the API returned an unexpected response shape (`results.total.toLocaleString()` crashed when `total` was undefined).

### Migration notes

- **No DB migrations required** — all changes use the existing `meta_json` columns.
- **Profile-modal Web Auth removed** — saved profile-level `web_auth` blocks still work (the engine reads them), but UI for editing now lives on the New Scan dialog.
- **Email integrations** saved before v3.0 need their password re-entered (field renamed `smtp_password` → `smtp_pass`).
- **Threat Intel** requires NVD + EPSS + CISA KEV datasets — refresh from Configuration → Datasets to populate.

### Roadmap (deferred to v3.1+)

- Scheduled authenticated scans (needs `ScanSchedule.meta_json` migration).
- "Find affected assets" cross-reference from CVE → workspace findings (needs CPE-to-asset matcher).
- SQLite-indexed Threat Intel for production scale (currently in-memory).
- Playwright-based SPA login support.
- Top-level React error boundary.

---

## v2.1.4 — 2026-04-14

### Added

**4 new scanner plugins (51 total)**

Tier 4 — Deep injection testing (advanced payloads + WAF bypass)
- **Advanced XSS Scanner** (`web.advanced_xss`) — reflected + stored XSS with 30+ payloads across HTML, attribute, JavaScript, and URL contexts; polyglot payloads; WAF-bypass via encoding, case, tag-breaking, and event handlers.
- **Deep SQL Injection Scanner** (`web.deep_sqli`) — error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), boolean-based blind, time-based blind, UNION-based, and stacked queries; WAF-bypass via encoding, case, and comment obfuscation.
- **Deep OS Command Injection Scanner** (`web.deep_cmdi`) — in-band marker detection and blind time-based detection across Linux and Windows; covers GET params, POST bodies, and headers; WAF-bypass via encoding, newlines, and variable expansion.

Tier 5 — API-specific scanning (OpenAPI / Swagger / Postman)
- **API Security Scanner** (`api.scanner`) — new `plugins/api_scanner/` sub-package that ingests OpenAPI/Swagger/Postman specs and dispatches endpoints to 15 dedicated sub-checks:
  - Injection: `sqli`, `xss`, `ssti`, `cmdi`, `xxe`, `ssrf`, `code_injection`, `type_confusion`
  - Auth / OWASP API Top 10: `jwt_checks`, `bola` (API1), `mass_assignment` (API3)
  - Data exposure: `excessive_data` (API3)
  - Passive: `config_checks` (CORS, methods, verbose errors, rate limits), `spec_hygiene` (missing auth, wildcard CORS, real secrets in examples, plain HTTP)
  - GraphQL: `graphql` (introspection, batch abuse, depth attacks, field suggestions)
  - `spec_parser` — OpenAPI 3.x / Swagger 2.x / Postman v2.1 ingestion
  - `http_client` — shared async HTTP client with multi-identity support (primary + secondary auth for BOLA)
  - Can run in engine mode (normal scan) or standalone via the new API endpoint. Opt-in (`enabled_by_default=False`) — requires spec upload or explicit enable.

Tier 5 — Spec-aware API sub-checks (added in this release's follow-up)
- **`bola`** — OWASP API1 (Broken Object-Level Authorization). Two-identity comparison: for each endpoint with an object-id-shaped param, fetch with primary and secondary auth, flag when both succeed with high JSON-key similarity (Jaccard ≥ 0.8). Falls back to numeric ID neighbour-walking when only one identity is configured.
- **`mass_assignment`** — OWASP API3 (BOPLA). Injects `is_admin`, `role`, `verified`, `balance` into POST/PUT/PATCH bodies; emits a finding only when the server **echoes** the injected value, confirming unfiltered model binding.
- **`excessive_data`** — OWASP API3. Sweeps GET responses for sensitive keys (`password*`, `*_hash`, `ssn`, `credit_card`, `private_key`, `*_token`, `internal_*`, `cvv`, …) and flags schema drift when response field count exceeds declared schema by >2×.
- **`type_confusion`** — Wrong-type payloads per declared type (`["array"]` for integer, `{"$ne": null}` for boolean, object-for-string). Triggers on 5xx (unhandled type reached application code) or substantively divergent 200s — a precursor pattern to NoSQL operator injection.
- **`spec_hygiene`** — Passive pre-scan analysis (no requests). Flags endpoints declared without auth, missing `securitySchemes`, wildcard CORS in the spec, real-looking secrets in example values (Stripe `sk_live_`, AWS `AKIA`, JWT-shaped, private-key blocks), and plain-HTTP `servers[]` entries.

**New backend API**
- `POST /scan/api-scanner/jobs` — standalone API-scanner endpoint driven by an uploaded OpenAPI/Swagger/Postman spec (routed via `app/api/routes_api_scanner.py`).
- `POST /scan/api-scanner/parse` — preview-only spec parser returning the endpoint list before launching a scan.
- `GET /scan/api-scanner/checks` — returns the list of available sub-checks with category metadata; the frontend auto-populates its checkbox grid from this response.

**API Scanner safety hardening**
- **SSRF guard** on `spec_url` fetches — rejects private / loopback / link-local / multicast / reserved / unspecified addresses (blocks AWS metadata `169.254.169.254`, `127.0.0.1`, RFC1918 ranges) and non-http(s) schemes.
- **5 MB cap** on both uploaded spec files and fetched URLs — oversized specs return HTTP 413 instead of OOM-ing the worker.
- **RQ `job_timeout`** now follows `SCAN_BUDGET_SECONDS + 300` for API-scanner jobs (previously hard-coded to `AI_ANALYSIS_TIMEOUT` = 600s).
- **Multi-identity HTTP client** — `ApiHttpClient` gained `secondary_auth_config` + `request_as(identity=…)` to power BOLA / BFLA two-identity comparisons.

**Frontend — API Scanner page (`frontend/index.html`)**
- New collapsible **"Secondary identity (optional)"** section in the API Scanner configuration panel, with bearer / API-key / basic inputs for a second test user. `launchApiScan()` forwards the credentials as `config.secondary_auth` to the backend.
- The 5 new spec-aware checks appear automatically as checkboxes in the "Security Checks" grid (auto-populated from `GET /scan/api-scanner/checks`).

### Changed — Scanner engine

- **Global scan budget** — new `SCAN_BUDGET_SECONDS` setting (default `900`). The engine tracks wall-clock time and skips remaining plugins when the budget is exhausted, emitting an informational finding per skipped plugin rather than letting RQ kill the whole job.
- **RQ `job_timeout` auto-synced** to `SCAN_BUDGET_SECONDS + 300s` headroom (was a hard-coded 600s). Applied to both new jobs and rescans.
- **Default artifact fallback** — when a plugin times out or errors, `_set_default_artifacts()` populates empty values for that plugin's declared `provides` keys so downstream plugins reading those artifacts don't break.
- **Per-plugin cancel check** — cancel flag is now checked *before* each plugin (not only between plugins), shortening cancel latency.

### Changed — Plugin framework

- **`soft_depends_on`** added to `PluginMeta`. Soft deps affect execution order (the plugin runs *after* them) but do **not** auto-enable them. Used by the new Tier-4/Tier-5 plugins to run after `owasp.web.scanner` when available, without requiring it.
- **Profile auto-backfill** — if a plugin is missing from an existing profile's `plugin_selection_json`, the loader falls back to its `enabled_by_default` flag. Existing profiles now pick up newly-shipped plugins automatically on the next scan.

### Changed — Dependencies

Added to `backend/requirements.txt`:
- `requests>=2.31.0`
- `paho-mqtt==1.6.1`
- `openai>=1.30.0`
- `google-generativeai>=0.7.0`
- `pyyaml>=6.0`

### Notes

- No breaking changes; existing profiles, jobs, and integrations continue to work unchanged.
- Tune `SCAN_BUDGET_SECONDS` in `.env` if you run large or slow scans; the RQ timeout now follows it automatically.

---

## v2.1.3 — 2026-04-05

**9 new scanner plugins (47 total)** — SSL Certificate Transparency, Rate Limiting Check, Open Redirect, LDAP Injection, NoSQL Injection, SSRF Deep (cloud metadata), WebSocket Security, Kubernetes API, Unauthenticated API Access.

**One-click platform update** — Settings → System shows current vs. latest GitHub release; "Update Now" triggers git pull + docker rebuild via host-level systemd service (`scripts/install-updater.sh`); `.env` preserved across updates.

**Scan cancel** — Cancel button on running scans; Redis-based signal between frontend → backend → worker → scan engine; stops after current plugin completes.

**Integration redesign** — Toggle-based UI (OFF / ON editing / ON saved); Microsoft Teams (Adaptive Card); per-integration Save/Test; top-findings in notifications 3 → 10.

**Plugin checkbox grid** — Visual grid in profile creation instead of raw JSON; `GET /scan/plugins` endpoint lists metadata.

**AI Deep Analysis — Job Selector** — Choose which scan job to analyze (previously always the latest).

**Fixes** — Scan cancel checks Redis flag between plugins; job deletion removes AI analyses first (FK constraint); Node.js Docker `libuv.so` fix; updater handles `__pycache__` and untracked-file conflicts.

---

## v2.1.2 — 2026-04-02

**Multi-provider AI Deep Analysis** — Azure OpenAI, Claude CLI, Gemini; modes: Validate, Full Analysis, Full + PoC; per-finding "Generate PoC"; analysis history; attack-chain identification.

**14 new scanner plugins (Tier 1 + Tier 2)** — API Key/Token Exposure, JWT Weak Algorithm, GraphQL Introspection, Security Headers (A–F grading), MQTT, SNMP community brute, FTP anonymous, Redis no-auth, Host Header Injection, CRLF Injection, Docker API, Cloud Storage Misconfiguration (S3/GCS/Azure), WAF Detection, SSTI.

**Security Information Browser** — 6 dataset views (NVD, CVE, CISA-KEV, CMS-CVE, EPSS, Compliance) with search, pagination, expandable rows.

**Dataset refresh from UI** — One-click "Refresh All" with progress banner; background RQ processing.

**Per-host report generation** — Bulk host selection → CSV/HTML/PDF export.

**Profile editing** — `PUT /scan/profiles/{id}`; Edit/Clone/Delete actions per profile.

**Improvements** — Pagination across Jobs/Schedules/Profiles/Credentials/Datasets; responsive table layout; OWASP scanner content validators + soft-404 detection; external scan timeout tuning; Claude CLI installed in Docker worker.

---

## v2.1.1 — 2026-03-23

**Security Information Browser (initial)** — Sidebar "Security Intel" dropdown; 6-dataset browser (NVD, CVE, CISA-KEV, CMS-CVE, EPSS, Compliance) with search and 50-row pagination; expandable detail rows; overview page with 6 cards.

**Dataset refresh from UI (initial)** — "Refresh All" re-fetches from NVD, CISA, EPSS, CVE.org; real-time progress banner; cancel; RQ-backed.

---

## v2.1.0 — 2026-03-14

- Scanning accuracy: distro-patch detection, active verification, deep fingerprinting.
- `cve_verifier` and `endpoint_prober` plugins.
- Validation states with confidence caps.
- `bootstrap.sh` with auto-credential detection.

---

## v1.0.0 — 2026-03-05

Initial public release.
