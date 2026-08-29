import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from redis.asyncio import Redis, from_url
from app.config.settings import settings

logger = logging.getLogger("trustinel.database")

# SQLAlchemy Async Engine and Session
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    pool_size=getattr(settings, "DB_POOL_SIZE", 10),
    max_overflow=getattr(settings, "DB_MAX_OVERFLOW", 20),
    pool_timeout=getattr(settings, "DB_POOL_TIMEOUT", 30.0)
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
    await engine.dispose()
    await redis_client.close()
