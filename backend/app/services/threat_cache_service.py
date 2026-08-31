import json
import logging
import time
from typing import Any, Dict, Optional
from app.database.session import redis_client

logger = logging.getLogger("trustinel.services.threat_cache")

DEFAULT_CACHE_TTL_SECONDS = 600  # 10 minutes


class InMemoryThreatCache:
    """
    Bounded in-memory fallback cache tracker used when Redis connection is unavailable.
    """
    _MAX_ENTRIES = 1000

    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, str]] = {}

    def get(self, key: str) -> Optional[str]:
        now = time.time()
        if key in self._store:
            expire_at, data = self._store[key]
            if now < expire_at:
                return data
            else:
                self._store.pop(key, None)
        return None

    def set(self, key: str, data: str, ttl_seconds: int) -> None:
        now = time.time()
        expire_at = now + ttl_seconds
        # Clean up stale entries if store capacity reached
        if len(self._store) >= self._MAX_ENTRIES:
            stale_keys = [k for k, (exp, _) in self._store.items() if now >= exp]
            for k in stale_keys:
                self._store.pop(k, None)
        self._store[key] = (expire_at, data)

    def delete_prefix(self, prefix: str) -> int:
        keys_to_del = [k for k in self._store if k.startswith(prefix)]
        for k in keys_to_del:
            self._store.pop(k, None)
        return len(keys_to_del)

    def clear(self) -> None:
        self._store.clear()


in_memory_threat_cache = InMemoryThreatCache()


class ThreatCacheService:
    """
    Service handling threat intelligence result caching and invalidation across Redis
    with bounded in-memory fallback for high reliability.
    """

    def __init__(self, default_ttl: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self.default_ttl = default_ttl

    def _build_key(self, module: str, domain: str) -> str:
        clean_domain = domain.strip().lower()
        return f"trustinel:threat_cache:{module}:{clean_domain}"

    async def get_module_result(self, module: str, domain: str) -> Optional[Dict[str, Any]]:
        key = self._build_key(module, domain)
        try:
            raw_data = await redis_client.get(key)
            if raw_data:
                logger.debug(f"[TRUSTINEL Cache Hit Redis] '{key}'")
                return json.loads(raw_data)
        except Exception as exc:
            logger.warning(f"[TRUSTINEL Cache Redis Error] '{key}': {exc}. Falling back to in-memory cache.")

        # Fallback to in-memory store
        raw_fallback = in_memory_threat_cache.get(key)
        if raw_fallback:
            logger.debug(f"[TRUSTINEL Cache Hit Memory] '{key}'")
            return json.loads(raw_fallback)

        return None

    async def set_module_result(self, module: str, domain: str, data: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        key = self._build_key(module, domain)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        json_str = json.dumps(data, default=str)

        try:
            await redis_client.set(key, json_str, ex=ttl)
            logger.debug(f"[TRUSTINEL Cache Set Redis] '{key}' (TTL={ttl}s)")
        except Exception as exc:
            logger.warning(f"[TRUSTINEL Cache Set Redis Error] '{key}': {exc}. Writing to in-memory cache.")

        in_memory_threat_cache.set(key, json_str, ttl)

    async def invalidate_domain_cache(self, domain: str) -> int:
        clean_domain = domain.strip().lower()
        prefix = f"trustinel:threat_cache:"
        count = 0

        # Modules to invalidate
        modules = ["reputation", "phishing", "ssl", "headers"]
        for mod in modules:
            key = self._build_key(mod, clean_domain)
            try:
                res = await redis_client.delete(key)
                if res:
                    count += res
            except Exception as exc:
                logger.warning(f"[TRUSTINEL Cache Invalidate Redis Error] '{key}': {exc}")
            count += in_memory_threat_cache.delete_prefix(key)

        logger.info(f"[TRUSTINEL Cache Invalidated] Domain '{clean_domain}', invalidated entries: {count}")
        return count
