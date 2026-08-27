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
_AI_CLI_TIMEOUT = int(os.getenv("AI_CLI_TIMEOUT", "0")) or max(60, (_AI_ANALYSIS_TIMEOUT - 300) // 2)
_AI_STALE_AFTER = int(os.getenv("AI_STALE_AFTER_SECONDS", "0")) or (_AI_ANALYSIS_TIMEOUT + 600)

# Self-correct a misordered configuration rather than failing scans at runtime.
# Two calls plus overhead must still fit inside the RQ job budget.
# Two calls plus ~300s of DB/parse overhead must still fit the RQ job budget.
if _AI_CLI_TIMEOUT * 2 + 300 > _AI_ANALYSIS_TIMEOUT:
    _AI_CLI_TIMEOUT = max(60, (_AI_ANALYSIS_TIMEOUT - 300) // 2)
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
    PLATFORM_VERSION: str = os.getenv("PLATFORM_VERSION", "3.1.0")

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

