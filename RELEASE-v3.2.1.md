## VulnScan Platform v3.2.1

Dataset refresh had stopped completing — and when it did finish, it produced a
dataset that was quietly missing CVEs.

The active NVD dataset held **49,794 of 52,760 CVEs**. Nearly 3,000 CVEs were
absent, and nothing in the UI suggested anything was wrong: the dataset looked
normal, the refresh looked like it had worked.

### What was happening

| Looked fine | Actually |
|---|---|
| Refresh running | Every page after the first timed out — NVD can no longer serve `resultsPerPage=2000` within any sane timeout |
| "failed after retries" | `IncompleteRead` never derived from the exception types the retry handler caught, so those pages were never retried at all |
| Dataset installed | Pages that failed were skipped, and the remainder was swapped in as if complete |

### Fixed

**Page size and timeout.** Measured from the platform host: a 2000-item page did
not finish in 155s; a 200-item page took 9.8s. Page size is now 200, timeout
120s. Bigger pages were measured and are slower overall — 200/500/1000 items
took 5.5s/16.2s/38.1s.

**`IncompleteRead` is retried.** It derives from `http.client.HTTPException`,
not `URLError`/`OSError`, so it slipped past the retry loop entirely. In one
full refresh, retrying recovered **28 pages** — about 10% of all requests.

**A partial fetch is now a failure.** The refresh reports how many pages and
CVEs it got and leaves the previous dataset in place, instead of installing a
dataset that silently omits thousands of CVEs.

**Interrupted refreshes resume.** NVD throttles sustained paging — measured at
7.9s per page early in a run and ~61s per page thereafter, steady for hours — so
a full refresh takes about 4.5 hours against a 2-hour job timeout and could
never finish. Each page is now written to disk as it arrives, with a manifest
recording its query window, so a run that is cut short continues from the first
missing page. Memory use drops accordingly: 265 pages no longer pile up in RAM.

**Neo4j now reports its real state.** The healthcheck called `curl`, which the
`neo4j:5` image does not ship, so every probe failed with `curl: not found` and
the container sat at `unhealthy` from first boot — 28,771 consecutive failures
on the running instance, while Neo4j served normally the whole time. The cost
was real rather than cosmetic: `depends_on: condition: service_healthy` can
never resolve for a probe that cannot pass, so start order was never honoured.
The probe now uses `wget`.

### Security — CVE-2026-111497

A malformed Brotli stream can write past an internal decoder buffer: memory
disclosure, a crash, or remote code execution. CVSS 4.0 **9.2**, remote and
unauthenticated. Affects Brotli 1.0.3 through 1.2.0.

- `libbrotli1` → Debian's patched `1.1.0-2+deb13u1`. This also covers the
  bundled `curl`, the one component here that actually decodes Brotli from scan
  targets — it links libbrotli and sends `Accept-Encoding: br`.
- Node.js **20 → 24.22.1**. Node 20 reached end of life in March 2026 and has no
  fixed release at all; its final build predates the October 2026 security
  releases by seven months.
- The Python scanner was never exposed: `httpx` advertises only
  `gzip, deflate` and no Brotli module is installed. `nuclei`, `httpx`, `ffuf`
  and `subfinder` do not link libbrotli.

**Neither fix is visible in a version string.** A patched Node 24.22.1 still
reports `process.versions.brotli == 1.2.0`, and the patched Debian package still
reads as 1.1.0 — both inside the vulnerable range. Version-range matching alone
calls them vulnerable. Confirming the fixes meant reading the Debian changelog
and, for Node, verifying the 2026-10-20 cherry-pick is an ancestor of v24.22.1
but not of v24.22.0.

### Added

**Scheduled dataset refresh** — `GET`/`PUT /settings/dataset-refresh`
(`enabled`, `interval_hours` 1–168), **off by default**. Without it, CVE data
was only as fresh as the last time someone pressed the button. The Datasets page
carries the control: a toggle plus an interval picker, readable by viewers and
editable by analysts and admins, matching the route's own roles. The interval is
counted from the last backend start rather than against the clock, so a restart
shifts the schedule — the UI states this instead of implying a fixed time of day.

### Result

| | before | after |
|---|---|---|
| NVD dataset | 49,794 entries | **52,879 entries** |
| Completeness | 2,966 CVEs missing, silently | verified `52879/52879` |
| Refresh | never completed | completes across two passes |

Roughly 3,000 CVEs that were never being matched are now in the dataset.

### Upgrade

```bash
git pull
docker compose build backend worker-ai worker-scan worker-data frontend
docker compose up -d
```

New optional settings, all with defaults: `NVD_PAGE_SIZE` (200),
`NVD_PAGE_TIMEOUT` (120), `NVD_RESUME_MAX_AGE_HOURS` (48).

A full refresh spans two triggers. At an 8-hour schedule the dataset lands about
once a day; at 24 hours it takes two to three days to catch up, then stays
current. Scheduling is off after upgrading — enable it deliberately.

### Known limitations

- The manifest is written only after page 1 succeeds, so a run killed while
  page 1 is still retrying starts over.
- NVD's ~61s per page is the observed cost of sustained paging from the host;
  this release does not tune it away.

Full detail in [CHANGELOG.md](CHANGELOG.md#v321--2026-10-26).
