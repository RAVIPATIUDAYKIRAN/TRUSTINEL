import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.database.session import get_db_session
from app.middleware.exceptions import APIException
from app.schemas.api_key import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyMetadata,
    ApiKeyListResponse,
    ApiKeyRevokeResponse,
)
from app.services.api_key_service import ApiKeyService

logger = logging.getLogger("trustinel.api.api_keys")

router = APIRouter(prefix="/api-keys", tags=["API Key Management"])


@router.post(
    "",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RateLimiter("create_api_key", lambda: settings.RATE_LIMIT_POST_SCAN))],
    summary="Create a new API key",
    description="Generates a new cryptographically secure API key with a tier assignment (STANDARD or ENTERPRISE). Plaintext API key is returned ONCE in this response and is NEVER stored or exposed again."
)
async def create_api_key(
    payload: ApiKeyCreateRequest,
    session: AsyncSession = Depends(get_db_session)
):
    if not payload.name or not payload.name.strip():
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key name must be provided.",
            error_code="INVALID_INPUT"
        )

    return await ApiKeyService.create_api_key(session, payload)


@router.get(
    "",
    response_model=ApiKeyListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("list_api_keys", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="List API key metadata",
    description="Lists API key metadata records. Full plaintext keys and key hashes are NEVER returned."
)
async def list_api_keys(
    owner: Optional[str] = Query(None, description="Optional owner filter"),
    session: AsyncSession = Depends(get_db_session)
):
    return await ApiKeyService.list_api_keys(session, owner=owner)


@router.get(
    "/{key_id}",
    response_model=ApiKeyMetadata,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_api_key", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get API key metadata",
    description="Retrieves metadata for a specific API key by ID. Plaintext key and key_hash are NEVER returned."
)
async def get_api_key(
    key_id: str,
    session: AsyncSession = Depends(get_db_session)
):
    metadata = await ApiKeyService.get_api_key_metadata(session, key_id)
    if not metadata:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API Key '{key_id}' not found.",
            error_code="API_KEY_NOT_FOUND"
        )
    return metadata


@router.delete(
    "/{key_id}",
    response_model=ApiKeyRevokeResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("revoke_api_key", lambda: settings.RATE_LIMIT_POST_SCAN))],
    summary="Revoke an API key",
    description="Revokes an active API key by marking it inactive and setting the revocation timestamp. A revoked key fails future authentication immediately."
)
async def revoke_api_key(
    key_id: str,
    session: AsyncSession = Depends(get_db_session)
):
    res = await ApiKeyService.revoke_api_key(session, key_id)
    if not res:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API Key '{key_id}' not found.",
            error_code="API_KEY_NOT_FOUND"
        )
    return res
