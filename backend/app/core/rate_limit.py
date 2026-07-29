"""
Redis-backed sliding-window rate limiter for FastAPI.

Usage as a dependency:

    from app.core.rate_limit import rate_limit

    @router.post("/login")
    def login(
        _rl=Depends(rate_limit(max_requests=5, window_seconds=60)),
        ...
    ):
        ...
"""

import logging
import time
from typing import Callable

from fastapi import Depends, HTTPException, Request

from app.core.config import settings

logger = logging.getLogger("vulnscan.ratelimit")


def _get_redis():
    """Lazy Redis connection (best-effort — degrades gracefully)."""
    import redis as _redis

    return _redis.from_url(settings.REDIS_URL, decode_responses=True)


def rate_limit(
    max_requests: int = 5,
    window_seconds: int = 60,
    key_prefix: str = "rl",
) -> Callable:
    """Return a FastAPI dependency that enforces per-IP rate limiting.

    Uses a Redis sorted-set sliding window. If Redis is unavailable, the
    request is allowed (fail-open) so the login endpoint stays functional.
    """

    def _dependency(request: Request):
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        redis_key = f"{key_prefix}:{request.url.path}:{client_ip}"
        now = time.time()
        window_start = now - window_seconds

        try:
            r = _get_redis()
            pipe = r.pipeline()
            # Remove expired entries
            pipe.zremrangebyscore(redis_key, "-inf", window_start)
            # Count remaining entries in the window
            pipe.zcard(redis_key)
            # Add current request
            pipe.zadd(redis_key, {str(now): now})
            # Set key expiry so it auto-cleans
            pipe.expire(redis_key, window_seconds + 10)
            results = pipe.execute()
            request_count = results[1]

            if request_count >= max_requests:
                retry_after = int(window_seconds - (now - window_start))
                logger.warning(
                    "Rate limit exceeded for %s on %s (%d/%d in %ds)",
                    client_ip, request.url.path, request_count,
                    max_requests, window_seconds,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many requests. Try again in {retry_after}s.",
                    headers={"Retry-After": str(retry_after)},
                )
        except HTTPException:
            raise
        except Exception as e:
            # Redis unavailable — fail open
            logger.debug("Rate limiter unavailable: %s", e)

    return _dependency
