import os
from pydantic import BaseModel, field_validator


# ── AI timeout hierarchy ──────────────────────────────────────────────────
# These three MUST stay ordered:
#     AI_CLI_TIMEOUT  <  AI_ANALYSIS_TIMEOUT  <  AI_STALE_AFTER_SECONDS
#
#   AI_CLI_TIMEOUT         budget for a SINGLE provider call (CLI subprocess).
#                          The validate_then_exploit mode makes two calls in one
#                          job, so the default is half the job budget.
#   AI_ANALYSIS_TIMEOUT    RQ job_timeout. RQ SIGKILLs the work horse here, so
#                          it must exceed the provider budget — otherwise the
#                          task dies before its except-block can record why.
#   AI_STALE_AFTER_SECONDS the scheduler watchdog. Must exceed the RQ timeout,
#                          or it fails analyses that are still legitimately
#                          running (this is what produced the bogus
#                          "stuck for over 15 minutes" errors).
_AI_ANALYSIS_TIMEOUT = int(os.getenv("AI_ANALYSIS_TIMEOUT", "2700"))
# Per provider call. No longer derived from "two calls per job": findings are
# analysed in batches, so the call count varies with scan size. The engine
# refuses to start a batch it cannot finish inside the job budget instead.
_AI_CLI_TIMEOUT = int(os.getenv("AI_CLI_TIMEOUT", "0")) or 600
_AI_STALE_AFTER = int(os.getenv("AI_STALE_AFTER_SECONDS", "0")) or (_AI_ANALYSIS_TIMEOUT + 600)

# Self-correct a misordered configuration rather than failing scans at runtime.
# Two calls plus overhead must still fit inside the RQ job budget.
# At least one call plus overhead must fit, or nothing can ever run.
if _AI_CLI_TIMEOUT + 300 > _AI_ANALYSIS_TIMEOUT:
    _AI_CLI_TIMEOUT = max(60, _AI_ANALYSIS_TIMEOUT - 300)
if _AI_STALE_AFTER <= _AI_ANALYSIS_TIMEOUT:
    _AI_STALE_AFTER = _AI_ANALYSIS_TIMEOUT + 600


class Settings(BaseModel):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-CHANGE-ME")
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql+psycopg2://app:app@localhost:5432/app"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Comma-separated CIDR ranges + domain suffixes
    ALLOWLIST: str = os.getenv(
        "ALLOWLIST",
        "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8,.internal.local,.local",
    )

    # ── Agentic active exploitation (Mode B) ────────────────────────────────
    # Master switch for the most dangerous capability: an AI agent that crafts
    # its own payloads against a live target. OFF by default and server-level on
    # purpose — enabling it requires editing .env, not a click in the browser.
    # Even when on, every attacking action still needs per-action human approval,
    # the target must be in the DB-managed exploit allowlist (fail-closed), and
    # the execution layer enforces target-pinning + the destructive deny-list.
    ENABLE_AGENTIC_EXPLOIT: bool = os.getenv("ENABLE_AGENTIC_EXPLOIT", "false").strip().lower() in ("1", "true", "yes", "on")
    # Bounds for an exploit session (anti-runaway / anti-flood).
    EXPLOIT_MAX_ACTIONS: int = int(os.getenv("EXPLOIT_MAX_ACTIONS", "40"))
    EXPLOIT_MAX_TURNS_PER_RUN: int = int(os.getenv("EXPLOIT_MAX_TURNS_PER_RUN", "12"))
    EXPLOIT_SESSION_DEADLINE: int = int(os.getenv("EXPLOIT_SESSION_DEADLINE", "7200"))
    EXPLOIT_MIN_SECONDS_BETWEEN_ACTIONS: float = float(os.getenv("EXPLOIT_MIN_SECONDS_BETWEEN_ACTIONS", "1.0"))
    EXPLOIT_MAX_RESPONSE_BYTES: int = int(os.getenv("EXPLOIT_MAX_RESPONSE_BYTES", str(64 * 1024)))

    # ── VAPT Pentest Pipeline ───────────────────────────────────────────────
    # Master switch for the full VAPT pipeline (auto-verify → post-exploit →
    # chain execution). OFF by default — requires editing .env. Even when on,
    # every action still needs per-action human approval, the target must be
    # in the exploit allowlist, and exploit_guard validates everything.
    ENABLE_PENTEST: bool = os.getenv("ENABLE_PENTEST", "false").strip().lower() in ("1", "true", "yes", "on")
    PENTEST_MAX_ACTIONS: int = int(os.getenv("PENTEST_MAX_ACTIONS", "100"))
    PENTEST_MAX_TURNS_PER_RUN: int = int(os.getenv("PENTEST_MAX_TURNS_PER_RUN", "15"))
    PENTEST_SESSION_DEADLINE: int = int(os.getenv("PENTEST_SESSION_DEADLINE", "14400"))  # 4h
    PENTEST_MIN_SECONDS_BETWEEN_ACTIONS: float = float(os.getenv("PENTEST_MIN_SECONDS_BETWEEN_ACTIONS", "1.0"))
    PENTEST_AUTO_APPROVE_SAFE: bool = os.getenv("PENTEST_AUTO_APPROVE_SAFE", "false").strip().lower() in ("1", "true", "yes", "on")

    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "15"))
    # Global scan budget: maximum wall-clock time for the entire scan (all plugins).
    # Must be LESS than RQ job_timeout to allow graceful completion.
    # Default 900s (15 min) with RQ job_timeout=1200s (20 min) gives 5 min headroom.
    SCAN_BUDGET_SECONDS: int = int(os.getenv("SCAN_BUDGET_SECONDS", "900"))
    # RQ job_timeout for a scan. Must exceed the engine's own worst case:
    # (budget - reserve) + one last plugin at the 20% cap + post-processing
    # (saving findings, compliance mapping, graph upserts). RQ SIGKILLs the
    # work-horse at this point, and a SIGKILLed scan loses every finding it
    # had collected, so the margin is deliberately generous.
    SCAN_JOB_TIMEOUT: int = int(os.getenv("SCAN_JOB_TIMEOUT", "0")) or (
        int(os.getenv("SCAN_BUDGET_SECONDS", "900")) + 600
    )
    # Stale-scan watchdog. RQ SIGKILLs the work-horse at SCAN_JOB_TIMEOUT, and a
    # SIGKILLed process cannot write its own status — the row would sit at
    # "running" forever. Must exceed SCAN_JOB_TIMEOUT so a job that is still
    # legitimately running is never touched.
    SCAN_STALE_AFTER_SECONDS: int = int(os.getenv("SCAN_STALE_AFTER_SECONDS", "0")) or (
        (int(os.getenv("SCAN_JOB_TIMEOUT", "0")) or
         int(os.getenv("SCAN_BUDGET_SECONDS", "900")) + 600) + 300
    )
    # Source-code scans are not network scans: the agentic review reads hundreds
    # or thousands of files with an LLM and legitimately runs for an hour or more.
    # They get their own, far larger RQ timeout, and the stale watchdog honours it
    # for scan_type == "source_code" instead of the network SCAN_STALE_AFTER_SECONDS.
    CODE_SCAN_JOB_TIMEOUT: int = int(os.getenv("CODE_SCAN_JOB_TIMEOUT", "7200"))   # 2h
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "/data/reports")

    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")

    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@local")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
    DEFAULT_WORKSPACE: str = os.getenv("DEFAULT_WORKSPACE", "default")

    # Reverse proxies whose X-Forwarded-For header may be trusted. Anything
    # arriving from outside these ranges has its XFF ignored, because a client
    # can set that header to whatever it likes. Defaults cover the Docker
    # bridge networks and loopback, which is where the bundled Vite proxy and
    # docker-proxy sit.
    # Keep this to the actual proxy hops only. Adding a client network (e.g.
    # 192.168.0.0/16 here) would let any LAN user forge X-Forwarded-For and
    # rotate rate-limit buckets at will.
    TRUSTED_PROXIES: str = os.getenv(
        "TRUSTED_PROXIES", "127.0.0.0/8,::1/128,172.16.0.0/12"
    )

    # CORS: comma-separated origins, or "*" for all (NOT recommended in production)
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8888")

    # ── Platform Update ────────────────────────────────────────────
    GITHUB_REPO: str = os.getenv("GITHUB_REPO", "Gondrong/VulnScan-Platform")
    PLATFORM_VERSION: str = os.getenv("PLATFORM_VERSION", "3.3.1")

    # ── AI Providers ──────────────────────────────────────────────
    AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    AZURE_OPENAI_API_KEY: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    AZURE_OPENAI_DEPLOYMENT: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1-mini")
    AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")

    CLAUDE_CLI_PATH: str = os.getenv("CLAUDE_CLI_PATH", "claude")
    CLAUDE_CLI_MODEL: str = os.getenv("CLAUDE_CLI_MODEL", "claude-opus-4-6")
    CLAUDE_CLI_ENABLED: bool = os.getenv("CLAUDE_CLI_ENABLED", "false").lower() in ("true", "1", "yes")

    # Anthropic API — alternative to CLI when host CPU can't run Bun (no AVX)
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-5")

    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    AI_ANALYSIS_TIMEOUT: int = _AI_ANALYSIS_TIMEOUT
    AI_CLI_TIMEOUT: int = _AI_CLI_TIMEOUT
    AI_STALE_AFTER_SECONDS: int = _AI_STALE_AFTER

    # Findings per provider call. Keep at or below prompts.MAX_FULL_DETAIL (30)
    # so every finding in a batch is sent with full detail: beyond that the
    # prompt builder degrades findings to title-only summaries, and past
    # MAX_FULL_DETAIL + MAX_SUMMARY it drops them entirely.
    AI_BATCH_SIZE: int = int(os.getenv("AI_BATCH_SIZE", "30"))

    # Output-token budget per batch call. For reasoning models (GLM, Qwen via
    # OpenRouter) the reasoning trace is billed against this same budget: at
    # 8192, GLM 5.3 Flash spent 6.6k-8.6k tokens reasoning over a 30-finding
    # validate batch and was cut off (finish_reason=length) before answering.
    AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "16384"))

    # Investigate mode: batch validation first, then one agentic session per
    # finding that the batch passes left in doubt.
    # Batch validation passes before the queue is built. With 2, findings the
    # passes disagree on are investigated too. Whether one model disagrees
    # with itself often enough to pay for the second pass has not been
    # measured yet — the 12% disagreement seen earlier was Qwen against GLM.
    AI_INVESTIGATE_PHASE_A_RUNS: int = max(1, min(2, int(os.getenv("AI_INVESTIGATE_PHASE_A_RUNS", "2"))))
    # Turn budget per investigation session. A tool call costs a turn.
    AI_INVESTIGATE_MAX_TURNS: int = max(2, int(os.getenv("AI_INVESTIGATE_MAX_TURNS", "10")))
    # Cap on sessions per analysis; beyond it the queue is cut by KEV, then
    # severity, and the rest keep their batch verdict.
    AI_INVESTIGATE_MAX_FINDINGS: int = max(1, int(os.getenv("AI_INVESTIGATE_MAX_FINDINGS", "20")))

    # GeoIP — path to GeoLite2-City.mmdb for IP → City/Country resolution
    GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb")

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_not_empty(cls, v: str) -> str:
        if not v or len(v) < 8:
            raise ValueError("SECRET_KEY must be at least 8 characters")
        return v

    def cors_origins_list(self) -> list[str]:
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def available_ai_providers(self) -> list[dict]:
        """Return list of configured AI providers."""
        import shutil
        providers = []
        if self.AZURE_OPENAI_ENDPOINT and self.AZURE_OPENAI_API_KEY:
            providers.append({
                "id": "azure_openai",
                "name": "Azure OpenAI",
                "model": self.AZURE_OPENAI_DEPLOYMENT,
            })
        if self.CLAUDE_CLI_ENABLED or shutil.which(self.CLAUDE_CLI_PATH):
            providers.append({
                "id": "claude_cli",
                "name": "Claude CLI",
                "model": self.CLAUDE_CLI_MODEL,
            })
        if self.ANTHROPIC_API_KEY:
            providers.append({
                "id": "claude_api",
                "name": "Claude (API)",
                "model": self.ANTHROPIC_MODEL,
            })
        if self.GEMINI_API_KEY:
            providers.append({
                "id": "gemini",
                "name": "Gemini",
                "model": self.GEMINI_MODEL,
            })
        return providers


settings = Settings()

