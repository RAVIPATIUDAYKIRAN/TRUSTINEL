import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from redis.asyncio import Redis, from_url
from app.config.settings import settings

from sqlalchemy.pool import NullPool

logger = logging.getLogger("trustinel.database")

# SQLAlchemy Async Engine and Session
engine_kwargs = {
    "echo": False,
    "future": True,
    "pool_pre_ping": True,
}
if getattr(settings, "ENVIRONMENT", "development") in ["testing", "development"]:
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_size"] = getattr(settings, "DB_POOL_SIZE", 10)
    engine_kwargs["max_overflow"] = getattr(settings, "DB_MAX_OVERFLOW", 20)
    engine_kwargs["pool_timeout"] = getattr(settings, "DB_POOL_TIMEOUT", 30.0)

engine = create_async_engine(
    settings.DATABASE_URL,
    **engine_kwargs
)

async_session = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Redis Connection setup
redis_client: Redis = from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_connections() -> None:
    logger.info("Closing database and redis engine connections...")
    try:
        await engine.dispose()
    except Exception:
        pass
    try:
        await redis_client.close()
    except Exception:
        pass
