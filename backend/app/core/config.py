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

    # CORS: comma-separated origins, or "*" for all
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")

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


settings = Settings()
