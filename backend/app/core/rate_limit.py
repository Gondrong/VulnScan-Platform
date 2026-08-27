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
from app.core.net import client_ip

logger = logging.getLogger("vulnscan.ratelimit")


_client = None


def _get_redis():
    """Lazily-built, cached Redis client (best-effort — degrades gracefully).

    Building a fresh client per request creates a new connection pool each
    time and never closes it.
    """
    global _client
    if _client is None:
        import redis as _redis

        _client = _redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _client


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
        ip = client_ip(request)
        redis_key = f"{key_prefix}:{request.url.path}:{ip}"
        now = time.time()
        window_start = now - window_seconds

        try:
            r = _get_redis()
            pipe = r.pipeline()
            # Drop entries that have aged out of the window, then count.
            pipe.zremrangebyscore(redis_key, "-inf", window_start)
            pipe.zcard(redis_key)
            request_count = pipe.execute()[1]

            if request_count >= max_requests:
                # Deliberately do NOT record this attempt. Counting rejected
                # requests keeps the window permanently topped up for as long
                # as the client keeps retrying, turning a 60-second throttle
                # into an indefinite lockout — which is exactly how a slow
                # login turns into "cannot log in at all".
                oldest = r.zrange(redis_key, 0, 0, withscores=True)
                if oldest:
                    retry_after = max(1, int(window_seconds - (now - oldest[0][1])) + 1)
                else:
                    retry_after = window_seconds
                logger.warning(
                    "Rate limit exceeded for %s on %s (%d/%d in %ds), retry in %ds",
                    ip, request.url.path, request_count,
                    max_requests, window_seconds, retry_after,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many requests. Try again in {retry_after}s.",
                    headers={"Retry-After": str(retry_after)},
                )

            # Allowed — now record it.
            pipe = r.pipeline()
            pipe.zadd(redis_key, {str(now): now})
            pipe.expire(redis_key, window_seconds + 10)
            pipe.execute()
        except HTTPException:
            raise
        except Exception as e:
            # Redis unavailable — fail open
            logger.debug("Rate limiter unavailable: %s", e)

    return _dependency
