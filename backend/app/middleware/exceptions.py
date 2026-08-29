import logging
from typing import Dict, Optional
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("trustinel.exceptions")


class APIException(Exception):
    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_code: str = "BAD_REQUEST",
        headers: Optional[Dict[str, str]] = None
    ):
        self.detail = detail
        self.status_code = status_code
        self.error_code = error_code
        self.headers = headers or {}
        super().__init__(detail)


class DatabaseException(APIException):
    def __init__(self, detail: str = "Database connection error"):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="DATABASE_ERROR"
        )


class RedisException(APIException):
    def __init__(self, detail: str = "Redis cache connection error"):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="REDIS_ERROR"
        )


class InvalidURLException(APIException):
    def __init__(self, detail: str = "Invalid or malformed URL."):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="INVALID_URL"
        )


class SSRFBlockedException(APIException):
    def __init__(self, detail: str = "The requested URL is not allowed."):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="URL_NOT_ALLOWED"
        )


class RateLimitException(APIException):
    def __init__(
        self,
        detail: str = "Rate limit exceeded. Please try again later.",
        retry_after_seconds: int = 60,
        headers: Optional[Dict[str, str]] = None
    ):
        self.retry_after_seconds = retry_after_seconds
        merged_headers = {"Retry-After": str(retry_after_seconds)}
        if headers:
            merged_headers.update(headers)
        super().__init__(
            detail=detail,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE_LIMIT_EXCEEDED",
            headers=merged_headers
        )


async def api_exception_handler(request: Request, exc: APIException) -> JSONResponse:
    logger.error(f"API Error handling request {request.url.path}: {exc.detail}")
    content = {
        "detail": exc.detail,
        "error_code": exc.error_code,
        "status_code": exc.status_code
    }
    if isinstance(exc, RateLimitException):
        content["retry_after_seconds"] = exc.retry_after_seconds

    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        headers=exc.headers if exc.headers else None
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.error(f"Validation Error handling request {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
            "error_code": "VALIDATION_ERROR",
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY
        }
    )


async def sqlalchemy_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"SQLAlchemy Database Exception on request {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": "Database service temporarily unavailable.",
            "error_code": "DATABASE_ERROR",
            "status_code": status.HTTP_503_SERVICE_UNAVAILABLE
        }
    )


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(f"Unhandled exception handling request {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred.",
            "error_code": "INTERNAL_SERVER_ERROR",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    )


import time
from app.core.logging import sanitize_correlation_id, set_correlation_id, get_correlation_id


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        incoming_id = request.headers.get("X-Request-ID")
        correlation_id = sanitize_correlation_id(incoming_id)
        set_correlation_id(correlation_id)

        start_time = time.perf_counter()
        logger.info(
            f"Request started: {request.method} {request.url.path}",
            extra={"event": "request_started", "method": request.method, "path": request.url.path}
        )

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.info(
                f"Request completed: {request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)",
                extra={
                    "event": "request_completed",
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms
                }
            )
            response.headers["X-Request-ID"] = correlation_id
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                f"Unhandled request exception: {request.method} {request.url.path}: {exc}",
                extra={
                    "event": "unhandled_exception",
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                    "exception_class": exc.__class__.__name__
                }
            )
            if isinstance(exc, APIException):
                response = await api_exception_handler(request, exc)
            elif isinstance(exc, RequestValidationError):
                response = await validation_exception_handler(request, exc)
            elif isinstance(exc, SQLAlchemyError):
                response = await sqlalchemy_exception_handler(request, exc)
            else:
                response = await global_exception_handler(request, exc)

            response.headers["X-Request-ID"] = correlation_id
            return response
