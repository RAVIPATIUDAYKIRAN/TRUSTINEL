import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.core.url_security import URLSecurityValidator
from app.middleware.exceptions import APIException
from app.models.webhook import WebhookConfig, WebhookDelivery
from app.schemas.webhook import (
    WebhookCreateRequest,
    WebhookCreateResponse,
    WebhookMetadata,
    WebhookListResponse,
    WebhookDeliveryLog,
    WebhookEventType,
)

logger = logging.getLogger("trustinel.services.webhook")

SECRET_PREFIX_HEADER = "whsec_"


def generate_webhook_secret() -> Tuple[str, str, str]:
    """
    Generates a cryptographically secure Webhook HMAC signing secret.
    Format: whsec_<48_hex_chars>
    Returns: (plaintext_secret, secret_prefix, secret_hash)
    """
    random_secret = secrets.token_hex(24)
    plaintext_secret = f"{SECRET_PREFIX_HEADER}{random_secret}"
    secret_prefix = f"{SECRET_PREFIX_HEADER}{random_secret[:4]}"
    secret_hash = hashlib.sha256(plaintext_secret.encode("utf-8")).hexdigest()
    return plaintext_secret, secret_prefix, secret_hash


def hash_webhook_secret(plaintext_secret: str) -> str:
    """
    Computes the SHA-256 digest of a plaintext webhook secret.
    """
    return hashlib.sha256(plaintext_secret.strip().encode("utf-8")).hexdigest()


class WebhookService:
    """
    Service layer handling webhook destination management, SSRF validation,
    secret hashing, listing, deletion, and delivery audit history.
    """

    @staticmethod
    async def validate_webhook_destination(target_url: str) -> str:
        """
        Validates target URL syntax and DNS resolution against SSRF protections.
        Blocks local hostnames, loopback, private IP ranges, metadata endpoints, and HTTP in production.
        """
        cleaned_url = URLSecurityValidator.validate_url_syntax(target_url)

        # In production mode, reject HTTP webhooks (only HTTPS allowed)
        if settings.is_production and cleaned_url.lower().startswith("http://"):
            raise APIException(
                status_code=400,
                detail="In production environment, webhook target URLs must use HTTPS.",
                error_code="INVALID_WEBHOOK_URL"
            )

        # Extract hostname and perform SSRF IP validation
        from urllib.parse import urlparse
        parsed = urlparse(cleaned_url)
        if parsed.hostname:
            await URLSecurityValidator.validate_hostname_resolution(parsed.hostname)

        return cleaned_url

    @classmethod
    async def create_webhook(
        cls,
        session: AsyncSession,
        request: WebhookCreateRequest
    ) -> WebhookCreateResponse:
        validated_url = await cls.validate_webhook_destination(request.target_url)

        plaintext_secret, secret_prefix, secret_hash = generate_webhook_secret()
        events_str = ",".join([e.value for e in request.events])

        now = datetime.now(timezone.utc)
        webhook_record = WebhookConfig(
            name=request.name.strip(),
            target_url=validated_url,
            secret_hash=secret_hash,
            secret_prefix=secret_prefix,
            is_enabled=True,
            events=events_str,
            owner=request.owner.strip() if request.owner else "default_owner",
            failure_count=0,
            created_at=now
        )

        session.add(webhook_record)
        await session.commit()
        await session.refresh(webhook_record)

        logger.info(f"[TRUSTINEL Webhook Created] ID='{webhook_record.id}', URL='{validated_url}', Events='{events_str}'")

        return WebhookCreateResponse(
            webhook_id=webhook_record.id,
            name=webhook_record.name,
            target_url=webhook_record.target_url,
            secret=plaintext_secret,  # RETURNED ONCE UPON CREATION ONLY
            secret_prefix=secret_prefix,
            events=request.events,
            is_enabled=webhook_record.is_enabled,
            created_at=webhook_record.created_at
        )

    @staticmethod
    async def list_webhooks(
        session: AsyncSession,
        owner: Optional[str] = None
    ) -> WebhookListResponse:
        stmt = select(WebhookConfig)
        if owner:
            stmt = stmt.where(WebhookConfig.owner == owner)
        stmt = stmt.order_by(WebhookConfig.created_at.desc())

        result = await session.execute(stmt)
        records = result.scalars().all()

        metadata_list = [
            WebhookMetadata(
                webhook_id=rec.id,
                name=rec.name,
                target_url=rec.target_url,
                secret_prefix=rec.secret_prefix,
                events=[WebhookEventType(e.strip()) for e in rec.events.split(",") if e.strip()],
                is_enabled=rec.is_enabled,
                failure_count=rec.failure_count,
                created_at=rec.created_at,
                last_delivery_at=rec.last_delivery_at
            )
            for rec in records
        ]

        return WebhookListResponse(
            total_count=len(metadata_list),
            webhooks=metadata_list
        )

    @staticmethod
    async def get_webhook_metadata(
        session: AsyncSession,
        webhook_id: str
    ) -> Optional[WebhookMetadata]:
        stmt = select(WebhookConfig).where(WebhookConfig.id == webhook_id)
        result = await session.execute(stmt)
        rec = result.scalar_one_or_none()

        if not rec:
            return None

        return WebhookMetadata(
            webhook_id=rec.id,
            name=rec.name,
            target_url=rec.target_url,
            secret_prefix=rec.secret_prefix,
            events=[WebhookEventType(e.strip()) for e in rec.events.split(",") if e.strip()],
            is_enabled=rec.is_enabled,
            failure_count=rec.failure_count,
            created_at=rec.created_at,
            last_delivery_at=rec.last_delivery_at
        )

    @staticmethod
    async def delete_webhook(
        session: AsyncSession,
        webhook_id: str
    ) -> bool:
        stmt = select(WebhookConfig).where(WebhookConfig.id == webhook_id)
        result = await session.execute(stmt)
        rec = result.scalar_one_or_none()

        if not rec:
            return False

        await session.delete(rec)
        await session.commit()

        logger.info(f"[TRUSTINEL Webhook Deleted] ID='{webhook_id}'")
        return True

    @staticmethod
    async def list_deliveries(
        session: AsyncSession,
        webhook_id: str
    ) -> List[WebhookDeliveryLog]:
        stmt = (
            select(WebhookDelivery)
            .where(WebhookDelivery.webhook_id == webhook_id)
            .order_by(WebhookDelivery.created_at.desc())
        )
        result = await session.execute(stmt)
        records = result.scalars().all()

        return [
            WebhookDeliveryLog(
                delivery_id=rec.id,
                webhook_id=rec.webhook_id,
                event_id=rec.event_id,
                event_type=WebhookEventType(rec.event_type),
                attempt_count=rec.attempt_count,
                status=rec.status,
                response_status_code=rec.response_status_code,
                error_message=rec.error_message,
                created_at=rec.created_at,
                delivered_at=rec.delivered_at
            )
            for rec in records
        ]
