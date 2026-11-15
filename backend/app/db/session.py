import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://app:app@db:5432/app",
)

# Sizing matters here: the default pool is 5 + 10 overflow with a 30-second
# pool_timeout, so once the pool is exhausted every request that needs a
# session simply hangs for 30 seconds. That is what a "slow login" looked
# like. Bigger pool, and fail fast instead of hanging when it is drained.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
    pool_timeout=int(os.environ.get("DB_POOL_TIMEOUT", "10")),
    pool_recycle=1800,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
