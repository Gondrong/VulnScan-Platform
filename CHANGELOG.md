# Changelog

All notable changes to VulnScan Platform are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Earlier versions (v1.0.0 – v2.1.3) are also documented in `README.md`.

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
