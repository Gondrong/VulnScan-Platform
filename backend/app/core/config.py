import os
from pydantic import BaseModel

class Settings(BaseModel):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://app:app@localhost:5432/app")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    ALLOWLIST: str = os.getenv("ALLOWLIST", "127.0.0.1/32")
    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "8"))
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "/data/reports")

    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")

    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@local")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
    DEFAULT_WORKSPACE: str = os.getenv("DEFAULT_WORKSPACE", "default")

settings = Settings()