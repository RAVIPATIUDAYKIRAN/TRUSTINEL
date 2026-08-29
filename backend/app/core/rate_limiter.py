import logging
import time
from typing import Callable, Dict, List, Optional
from fastapi import Request, Response

from app.config.settings import settings
from app.database.session import redis_client
from app.middleware.exceptions import RateLimitException

logger = logging.getLogger("trustinel.rate_limiter")


class InMemoryRateLimitTracker:
    """
    Bounded in-memory fallback sliding window rate limit tracker used when
    Redis connection is unavailable. Caps maximum memory entries.
    """
    _MAX_ENTRIES = 2000

    def __init__(self):
        self._store: Dict[str, List[float]] = {}

    def check_and_increment(self, key: str, max_requests: int, window_seconds: int) -> tuple[int, int]:
        now = time.time()
        cutoff = now - window_seconds

        # Memory cleanup if max entries threshold exceeded
        if len(self._store) >= self._MAX_ENTRIES:
            stale_keys = [k for k, timestamps in self._store.items() if not timestamps or timestamps[-1] < cutoff]
            for k in stale_keys:
                self._store.pop(k, None)

        timestamps = self._store.get(key, [])
        # Prune expired timestamps
        timestamps = [t for t in timestamps if t > cutoff]
        timestamps.append(now)
        self._store[key] = timestamps

        count = len(timestamps)
        oldest = timestamps[0]
        ttl = max(1, int(window_seconds - (now - oldest)))
        return count, ttl

    def clear(self):
        self._store.clear()


in_memory_tracker = InMemoryRateLimitTracker()


class RateLimiter:
    """
    FastAPI dependency for rate limiting client requests using Redis
    with bounded in-memory sliding window fallback.
    """
    def __init__(self, tag: str, get_limit: Callable[[], int]):
        self.tag = tag
        self.get_limit = get_limit

    async def __call__(self, request: Request, response: Response) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return

        max_limit = self.get_limit()
        if max_limit <= 0:
            return

        window_seconds = getattr(settings, "RATE_LIMIT_WINDOW_SECONDS", 60)
        
        # Client IP extraction with X-Forwarded-For fallback
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        elif request.client and request.client.host:
            client_ip = request.client.host
        else:
            client_ip = "127.0.0.1"

        cache_key = f"trustinel:rate_limit:{self.tag}:{client_ip}"
        count: Optional[int] = None
        ttl: int = window_seconds

        # 1. Attempt Redis primary counter increment
        try:
            count = await redis_client.incr(cache_key)
            if count == 1:
                await redis_client.expire(cache_key, window_seconds)
            redis_ttl = await redis_client.ttl(cache_key)
            if redis_ttl > 0:
                ttl = redis_ttl
            in_memory_tracker.check_and_increment(cache_key, max_limit, window_seconds)
        except Exception as exc:
            logger.warning(
                f"[TRUSTINEL] Redis rate limit error for key '{cache_key}': {exc}. "
                "Falling back to bounded in-memory rate limiter."
            )
            count = None

        # 2. In-memory fallback if Redis call failed
        if count is None:
            count, ttl = in_memory_tracker.check_and_increment(cache_key, max_limit, window_seconds)

        now_ts = int(time.time())
        reset_time = now_ts + max(1, ttl)

        # 3. Handle Rate Limit Exceeded (HTTP 429)
        if count > max_limit:
            retry_after = max(1, ttl)
            headers = {
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(max_limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_time),
            }
            logger.warning(
                f"[TRUSTINEL] Rate limit exceeded for IP '{client_ip}' on '{self.tag}'. "
                f"Count: {count}/{max_limit}. Retry after: {retry_after}s."
            )
            raise RateLimitException(
                detail=f"Rate limit exceeded for endpoint '{self.tag}'. Please try again in {retry_after} seconds.",
                retry_after_seconds=retry_after,
                headers=headers,
            )

        # 4. Attach rate limit telemetry headers to allowed response
        remaining = max(0, max_limit - count)
        response.headers["X-RateLimit-Limit"] = str(max_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
