import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import sys

from fastapi import FastAPI, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text

from app.config.settings import settings
from app.core.logging import setup_logging
from app.database.session import engine, redis_client, close_connections
from sqlalchemy.exc import SQLAlchemyError
from app.middleware.exceptions import (
    APIException,
    api_exception_handler,
    validation_exception_handler,
    sqlalchemy_exception_handler,
    global_exception_handler,
    RequestIDMiddleware
)

# Set up logging before app creation
setup_logging()
logger = logging.getLogger("trustinel.main")

from app.api.scan import router as scan_router
from app.api.analytics import router as analytics_router
from app.api.reputation import router as reputation_router
from app.api.ssl import router as ssl_router
from app.api.phishing import router as phishing_router
from app.api.headers import router as headers_router
from app.api.batch import router as batch_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Starting up TRUSTINEL backend...")
    
    # Test DB Connection on Startup
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Startup check: Database connection successful.")
    except Exception as e:
        logger.error(f"Startup check: Database connection failed: {e}")
        
    # Test Redis Connection on Startup
    try:
        await redis_client.ping()
        logger.info("Startup check: Redis connection successful.")
    except Exception as e:
        logger.error(f"Startup check: Redis connection failed: {e}")

    yield

    # Shutdown actions
    logger.info("Shutting down TRUSTINEL backend...")
    await close_connections()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="TRUSTINEL Project Foundation API",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None
)

# Exception handlers registration
app.add_exception_handler(APIException, api_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)

# Middlewares setup
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=settings.CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
app.include_router(scan_router)
app.include_router(analytics_router, prefix="/api/v1")
app.include_router(reputation_router, prefix="/api/v1")
app.include_router(ssl_router, prefix="/api/v1")
app.include_router(phishing_router, prefix="/api/v1")
app.include_router(headers_router, prefix="/api/v1")
app.include_router(batch_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
async def health_check(response: Response):
    """
    Perform checks on backing services (PostgreSQL, Redis).
    Returns detailed connectivity status and latency.
    """
    db_status = "connected"
    db_latency = 0.0
    redis_status = "connected"
    redis_latency = 0.0
    overall_status = "healthy"

    # Ping Database
    try:
        start_time = time.perf_counter()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_latency = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception as e:
        logger.error(f"Health Check: Database connection failed: {e}")
        db_status = "error: connection failed"
        overall_status = "unhealthy"

    # Ping Redis
    try:
        start_time = time.perf_counter()
        await redis_client.ping()
        redis_latency = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception as e:
        logger.error(f"Health Check: Redis connection failed: {e}")
        redis_status = "error: connection failed"
        overall_status = "unhealthy"

    if overall_status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "database": {
                "status": db_status,
                "latency_ms": db_latency
            },
            "redis": {
                "status": redis_status,
                "latency_ms": redis_latency
            }
        }
    }


@app.get("/version", tags=["System"])
async def version_info():
    """
    Return basic metadata about the application environment and release.
    """
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "api_version": "v1",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    }
