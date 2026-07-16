from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis
from app.database.session import get_db_session, redis_client


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to obtain an asynchronous database session.
    """
    async for session in get_db_session():
        yield session


async def get_redis() -> Redis:
    """
    Dependency to obtain the Redis client connection.
    """
    return redis_client
