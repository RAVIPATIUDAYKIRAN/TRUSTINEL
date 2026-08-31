import logging
import time
from typing import Dict, Optional, Tuple
from fastapi import Depends, Header, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.database.session import get_db_session, redis_client
from app.middleware.exceptions import APIException
from app.models.api_key import APIKey
from app.services.api_key_service import ApiKeyService

logger = logging.getLogger("trustinel.core.api_key_auth")

in_memory_key_rate_tracker: Dict[str, list] = {}


async def get_authenticated_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    session: AsyncSession = Depends(get_db_session)
) -> APIKey:
    """
    FastAPI dependency that extracts and validates the X-API-Key header.
    Returns the authenticated APIKey ORM model instance if valid.
    Raises generic HTTP 401 Unauthorized for missing/invalid/revoked/expired keys.
    """
    if not x_api_key or not x_api_key.strip():
        raise APIException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key credential.",
            error_code="UNAUTHORIZED"
        )

    api_key_obj = await ApiKeyService.authenticate_api_key(session, x_api_key.strip())
    if not api_key_obj:
        raise APIException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key credential.",
            error_code="UNAUTHORIZED"
        )

    return api_key_obj


class ApiKeyRateLimiter:
    """
    FastAPI dependency enforcing independent per-key rate limiting based on key tier (STANDARD vs ENTERPRISE).
    Injects rate limit headers into the response.
    """

    def __init__(self, action_name: str = "api_key_quota") -> None:
        self.action_name = action_name

    async def __call__(
        self,
        request: Request,
        response: Response,
        api_key_obj: APIKey = Depends(get_authenticated_api_key)
    ) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return

        # Determine rate limit quota per tier
        tier_upper = (api_key_obj.tier or "STANDARD").upper()
        if tier_upper == "ENTERPRISE":
            limit = settings.ENTERPRISE_RATE_LIMIT_PER_MINUTE
        else:
            limit = settings.STANDARD_RATE_LIMIT_PER_MINUTE

        window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS
        now = time.time()
        key_id = api_key_obj.id

        # Redis rate limiter key using key_id (never plaintext key)
        redis_key = f"trustinel:rate:key:{key_id}:{self.action_name}"

        current_count = 0
        try:
            pipe = redis_client.pipeline()
            pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
            pipe.zadd(redis_key, {str(now): now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, window_seconds + 5)
            exec_res = await pipe.execute()
            current_count = exec_res[2]
        except Exception as exc:
            logger.warning(f"[TRUSTINEL API Key Rate Limiter Redis Error] KeyID='{key_id}': {exc}. Using in-memory fallback.")
            timestamps = in_memory_key_rate_tracker.get(key_id, [])
            timestamps = [ts for ts in timestamps if ts > now - window_seconds]
            timestamps.append(now)
            in_memory_key_rate_tracker[key_id] = timestamps
            current_count = len(timestamps)

        remaining = max(0, limit - current_count)
        reset_seconds = window_seconds

        # Append RateLimit headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_seconds)

        if current_count > limit:
            retry_after = window_seconds
            response.headers["Retry-After"] = str(retry_after)
            logger.warning(f"[TRUSTINEL API Key Rate Limit Exceeded] KeyID='{key_id}', Tier='{tier_upper}', Limit={limit}")
            raise APIException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for API key ({tier_upper} tier limit: {limit} requests/min).",
                error_code="RATE_LIMIT_EXCEEDED",
                headers={"Retry-After": str(retry_after)}
            )
