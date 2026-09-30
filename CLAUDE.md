# CLAUDE.md

Working notes for this repository. Everything here is something that is **not**
obvious from reading the code, and that has cost real debugging time.

## What this is

Self-hosted Risk-Based Vulnerability Management platform. FastAPI + RQ workers +
PostgreSQL + Redis + Neo4j, React/Vite frontend, 71 scanner plugins, multi-provider
AI analysis. See `README.md` for features, `CHANGELOG.md` for history.

## Deploying

**Every service that builds from `./backend` has its own image.** `backend`,
`worker-ai`, `worker-scan` and `worker-data` are separate images built from the
same context. Building one leaves the others on the previous build:

```bash
docker compose build backend worker-ai worker-scan worker-data
docker compose up -d
```

Backend runs with `--reload` and the source is bind-mounted, so Python edits take
effect without a rebuild. Rebuild only for dependency or Dockerfile changes.

The frontend runs the Vite dev server; `.jsx` edits apply via HMR. `vite.config.js`
is **not** hot-reloaded — restart the frontend container for those.

Restarting `backend` briefly breaks the frontend's proxy: the SPA polls every
2 seconds, so users see a burst of errors for ~10s. Say so before restarting.

## Configuration invariants

Three ordered hierarchies. Inverting any of them causes failures that look like
something else entirely.

```
SCAN_TIMEOUT_SECONDS  <  SCAN_BUDGET_SECONDS  <  SCAN_JOB_TIMEOUT  <  SCAN_STALE_AFTER_SECONDS
     per request              engine budget         RQ SIGKILL            watchdog

AI_CLI_TIMEOUT  <  AI_ANALYSIS_TIMEOUT  <  AI_STALE_AFTER_SECONDS
   per call           RQ job budget             watchdog
```

A watchdog threshold below the RQ timeout kills work that is still legitimately
running. An RQ timeout below the engine budget SIGKILLs the work-horse, and a
SIGKILLed process writes no status — the row sits at `running` forever.

`AI_BATCH_SIZE` (default 30) must stay at or below `prompts.MAX_FULL_DETAIL`.
Above it, findings past the limit are sent as title-only summaries with no
evidence, and the model validates them on the title alone.

## Claude CLI provider

`CLAUDE_CONFIG_DIR` is the **Claude CLI's own** environment variable, and `.env`
is passed into the containers via `env_file`. It must be the *container* path
(`/root/.claude`). Use `CLAUDE_PROFILE_DIR` for the host path that gets mounted.
Giving `CLAUDE_CONFIG_DIR` a host path makes the CLI store its profile relative
to its working directory instead of in the mount.

Leave `CLAUDE_CODE_OAUTH_TOKEN` **empty** when authenticating by profile login. A
stale token there overrides a perfectly valid profile, and every call fails 401.

The subscription refresh token lasts ~28 days. Renewing needs a real TTY:

```bash
docker compose exec -it worker-ai claude     # then /login
```

This cannot be done from inside Claude Code — there is no TTY, and the CLI falls
back to `--print` mode and asks for stdin.

## AI provider gotchas

For OpenAI-compatible providers (OpenRouter, Ollama, LM Studio), `endpoint` is the
**base URL**. The SDK appends the route itself; pasting a full
`.../v1/chat/completions` URL yields a doubled path and a bare 404.
`routes_ai._normalize_endpoint()` strips it on save.

Reasoning models bill their reasoning trace against `max_tokens`
(`AI_MAX_TOKENS`, default 16384). Too low and the reply comes back empty or cut
mid-JSON with `finish_reason=length` — GLM 5.3 Flash did this on every 30-finding
batch at 8192. `OpenAIProvider` raises `EmptyResponseError` for both cases, and
the batch is recorded in `failed_batches` rather than silently yielding
default verdicts. Compare models only at the same `AI_MAX_TOKENS` and batch size.

Providers added through the UI are addressed as `db:<row id>`, not by type, so two
providers of the same type stay distinguishable. Bare types still resolve, for
settings saved before row-addressing — they pick the most recently added row.

## Scanner plugins

Plugin `run()` methods are `async`. **Never call a blocking primitive directly
inside one** — `socket.create_connection`, `ssl` handshakes, `subprocess.run`,
`time.sleep`. A blocking call freezes the event loop, which means the engine's
`asyncio.wait_for` timer cannot fire and its per-plugin timeout becomes
unenforceable. Wrap them in `asyncio.to_thread`.

External tools (`ext.nuclei`, `ext.ffuf`, `ext.sqlmap`) sit at steps 47–64 of 69.
When a scan dies there it is usually not the tool's fault — accumulated delay from
earlier in the run lands on whatever happens to be executing.

## Database

Startup migrations in `main.py` are raw idempotent DDL, run on every boot. They
`SET lock_timeout` first: a queued `ACCESS EXCLUSIVE` lock blocks *every*
subsequent reader of that table, so one long-running transaction elsewhere plus a
restart is enough to freeze the whole application.

Related: never hold a transaction across long work. After `db.commit()` SQLAlchemy
expires loaded objects, and touching one re-opens a transaction that then sits
`idle in transaction` for the duration. Copy what you need into plain values and
commit before the slow part.

## Conventions

- Error handlers must be able to run: do not touch a variable that may be unbound,
  and `db.rollback()` before writing an error after a DB failure.
- `except Exception` at `debug` level hides bugs for months. Real failures belong
  at `warning`.
- Blocking DB writes inside async middleware or callbacks need `run_in_threadpool`
  or `asyncio.to_thread`; they block the event loop and hold a pool connection.
- `.env` is not tracked. Do not commit it, and do not print secret values.
