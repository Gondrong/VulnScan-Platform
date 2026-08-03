import os
from pydantic import BaseModel, field_validator


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
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "/data/reports")

    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")

    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@local")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
    DEFAULT_WORKSPACE: str = os.getenv("DEFAULT_WORKSPACE", "default")

    # CORS: comma-separated origins, or "*" for all (NOT recommended in production)
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8888")

    # ── Platform Update ────────────────────────────────────────────
    GITHUB_REPO: str = os.getenv("GITHUB_REPO", "Gondrong/VulnScan-Platform")
    PLATFORM_VERSION: str = os.getenv("PLATFORM_VERSION", "3.0.5")

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

    AI_ANALYSIS_TIMEOUT: int = int(os.getenv("AI_ANALYSIS_TIMEOUT", "600"))

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

