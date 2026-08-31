import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.core.rate_limiter import RateLimiter
from app.database.session import get_db_session
from app.middleware.exceptions import APIException
from app.schemas.webhook import (
    WebhookCreateRequest,
    WebhookCreateResponse,
    WebhookMetadata,
    WebhookListResponse,
    WebhookDeliveryLog,
)
from app.services.webhook_service import WebhookService

logger = logging.getLogger("trustinel.api.webhooks")

router = APIRouter(prefix="/webhooks", tags=["Webhook Management"])


@router.post(
    "",
    response_model=WebhookCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RateLimiter("create_webhook", lambda: settings.RATE_LIMIT_POST_SCAN))],
    summary="Register a new webhook destination",
    description="Registers a new webhook destination URL and event subscriptions. Validates target URL against SSRF protections and returns a plaintext HMAC signing secret ONCE upon creation."
)
async def create_webhook(
    payload: WebhookCreateRequest,
    session: AsyncSession = Depends(get_db_session)
):
    if not payload.name or not payload.name.strip():
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook name must be provided.",
            error_code="INVALID_INPUT"
        )

    if not payload.events:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook must subscribe to at least one event type.",
            error_code="INVALID_INPUT"
        )

    return await WebhookService.create_webhook(session, payload)


@router.get(
    "",
    response_model=WebhookListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("list_webhooks", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="List webhook destinations",
    description="Lists registered webhook metadata records. Plaintext HMAC secrets are NEVER returned."
)
async def list_webhooks(
    owner: Optional[str] = Query(None, description="Optional owner filter"),
    session: AsyncSession = Depends(get_db_session)
):
    return await WebhookService.list_webhooks(session, owner=owner)


@router.get(
    "/{webhook_id}",
    response_model=WebhookMetadata,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_webhook", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="Get webhook metadata",
    description="Retrieves metadata for a specific webhook by ID. Plaintext secrets are NEVER returned."
)
async def get_webhook(
    webhook_id: str,
    session: AsyncSession = Depends(get_db_session)
):
    metadata = await WebhookService.get_webhook_metadata(session, webhook_id)
    if not metadata:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found.",
            error_code="WEBHOOK_NOT_FOUND"
        )
    return metadata


@router.delete(
    "/{webhook_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("delete_webhook", lambda: settings.RATE_LIMIT_POST_SCAN))],
    summary="Delete a webhook destination",
    description="Deletes a registered webhook destination and removes associated delivery logs."
)
async def delete_webhook(
    webhook_id: str,
    session: AsyncSession = Depends(get_db_session)
):
    deleted = await WebhookService.delete_webhook(session, webhook_id)
    if not deleted:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found.",
            error_code="WEBHOOK_NOT_FOUND"
        )
    return {"message": f"Webhook '{webhook_id}' deleted successfully.", "webhook_id": webhook_id}


@router.get(
    "/{webhook_id}/deliveries",
    response_model=List[WebhookDeliveryLog],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter("get_webhook_deliveries", lambda: settings.RATE_LIMIT_GET_SCAN))],
    summary="List webhook delivery audit logs",
    description="Retrieves delivery audit log records for a webhook destination."
)
async def list_webhook_deliveries(
    webhook_id: str,
    session: AsyncSession = Depends(get_db_session)
):
    metadata = await WebhookService.get_webhook_metadata(session, webhook_id)
    if not metadata:
        raise APIException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found.",
            error_code="WEBHOOK_NOT_FOUND"
        )
    return await WebhookService.list_deliveries(session, webhook_id)
