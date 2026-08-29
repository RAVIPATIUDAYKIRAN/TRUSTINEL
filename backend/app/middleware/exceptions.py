import logging
from typing import Dict, Optional
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware

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


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Add basic logging of requests
        logger.info(f"Request: {request.method} {request.url.path}")
        response = await call_next(request)
        logger.info(f"Response status: {response.status_code}")
        return response
