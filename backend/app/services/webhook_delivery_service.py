import asyncio
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import redis_client
from app.models.webhook import WebhookConfig, WebhookDelivery
from app.schemas.webhook import WebhookEventPayload, WebhookEventType

logger = logging.getLogger("trustinel.services.webhook_delivery")

MAX_DELIVERY_ATTEMPTS = 3  # Maximum 3 TOTAL attempts (1 initial + 2 retries)
HTTP_TIMEOUT_SECONDS = 5.0
DEDUP_TTL_SECONDS = 86400  # 24 hours


def sign_payload(secret: str, payload_bytes: bytes) -> str:
    """
    Computes HMAC-SHA256 signature for a webhook JSON payload.
    Header format: sha256=<hex_digest>
    """
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


class WebhookDeliveryService:
    """
    Service responsible for dispatching webhook security events, signing payloads with HMAC-SHA256,
    preventing duplicate event delivery via Redis deduplication, and executing bounded delivery attempts
    (maximum 3 total attempts: 1 initial attempt + 2 retries).
    """

    @staticmethod
    async def is_event_duplicate(event_id: str) -> bool:
        """
        Checks Redis idempotency key to prevent duplicate event dispatch.
        """
        dedup_key = f"trustinel:webhook:event_dedup:{event_id}"
        try:
            is_set = await redis_client.set(dedup_key, "1", nx=True, ex=DEDUP_TTL_SECONDS)
            return not is_set
        except Exception as exc:
            logger.warning(f"[TRUSTINEL Webhook Delivery Dedup Warning] Redis check failed: {exc}")
            return False

    @classmethod
    async def dispatch_event(
        cls,
        session: AsyncSession,
        event_type: WebhookEventType,
        domain: str,
        data: Dict[str, Any],
        signing_secret: Optional[str] = "whsec_default_signing_secret_key"
    ) -> List[WebhookDelivery]:
        session.expire_on_commit = False
        event_id = str(uuid.uuid4())

        if await cls.is_event_duplicate(event_id):
            logger.warning(f"[TRUSTINEL Webhook Delivery] Duplicate event blocked: EventID='{event_id}'")
            return []

        # Find active webhooks subscribed to this event type
        stmt = select(WebhookConfig).where(WebhookConfig.is_enabled == True)
        result = await session.execute(stmt)
        webhooks = result.scalars().all()

        matching_webhooks = [
            wh for wh in webhooks
            if event_type.value in [e.strip() for e in wh.events.split(",") if e.strip()]
        ]

        if not matching_webhooks:
            logger.info(f"[TRUSTINEL Webhook Delivery] No active webhooks registered for event '{event_type.value}'")
            return []

        now = datetime.now(timezone.utc)
        payload_obj = WebhookEventPayload(
            event_id=event_id,
            event_type=event_type,
            version="1.0",
            occurred_at=now,
            domain=domain,
            data=data
        )

        payload_bytes = json.dumps(payload_obj.model_dump(), default=str).encode("utf-8")
        signature_header = sign_payload(signing_secret or "whsec_default_signing_secret_key", payload_bytes)

        deliveries: List[WebhookDelivery] = []

        for wh in matching_webhooks:
            delivery = WebhookDelivery(
                webhook_id=wh.id,
                event_id=event_id,
                event_type=event_type.value,
                attempt_count=1,
                status="PENDING",
                created_at=now
            )
            session.add(delivery)
            await session.commit()
            await session.refresh(delivery)

            # Execute delivery with bounded retries (max 3 total attempts)
            await cls._execute_delivery_attempts(session, wh, delivery, payload_bytes, signature_header)
            try:
                await session.refresh(delivery)
            except Exception:
                pass
            deliveries.append(delivery)

        return deliveries

    @classmethod
    async def _execute_delivery_attempts(
        cls,
        session: AsyncSession,
        webhook: WebhookConfig,
        delivery: WebhookDelivery,
        payload_bytes: bytes,
        signature_header: str
    ) -> None:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "TRUSTINEL-Webhook/1.0",
            "X-TRUSTINEL-Signature": signature_header,
            "X-TRUSTINEL-Event-ID": delivery.event_id,
            "X-TRUSTINEL-Event-Type": delivery.event_type,
        }

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            for attempt in range(1, MAX_DELIVERY_ATTEMPTS + 1):
                delivery.attempt_count = attempt
                try:
                    resp = await client.post(webhook.target_url, content=payload_bytes, headers=headers)
                    delivery.response_status_code = resp.status_code

                    if resp.status_code >= 200 and resp.status_code < 300:
                        delivery.status = "SUCCESS"
                        delivery.delivered_at = datetime.now(timezone.utc)
                        delivery.error_message = None
                        webhook.last_delivery_at = delivery.delivered_at
                        webhook.failure_count = 0
                        await session.commit()
                        await session.refresh(delivery)
                        logger.info(f"[TRUSTINEL Webhook Delivery Success] WebhookID='{webhook.id}', Status={resp.status_code}, Attempt={attempt}")
                        return

                    elif resp.status_code >= 400 and resp.status_code < 500 and resp.status_code != 429:
                        # Non-retryable client error (e.g. 400, 404)
                        delivery.status = "FAILED"
                        delivery.error_message = f"HTTP {resp.status_code} client error"
                        webhook.failure_count += 1
                        await session.commit()
                        await session.refresh(delivery)
                        logger.warning(f"[TRUSTINEL Webhook Delivery Non-Retryable Failure] WebhookID='{webhook.id}', Status={resp.status_code}")
                        return
                    else:
                        # Retryable server error or rate limit (5xx or 429)
                        delivery.error_message = f"HTTP {resp.status_code} retryable response"

                except Exception as exc:
                    delivery.error_message = f"Network or HTTP error: {exc}"
                    logger.warning(f"[TRUSTINEL Webhook Delivery Attempt {attempt} Failed] WebhookID='{webhook.id}': {exc}")

                # If maximum attempts reached (3 total attempts), mark as FAILED
                if attempt >= MAX_DELIVERY_ATTEMPTS:
                    delivery.status = "FAILED"
                    webhook.failure_count += 1
                    await session.commit()
                    logger.error(
                        f"[TRUSTINEL Webhook Delivery Exhausted] WebhookID='{webhook.id}', Max Attempts={MAX_DELIVERY_ATTEMPTS}"
                    )
                    return
                await asyncio.sleep(0.05 * attempt)
