import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, Integer, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class WebhookConfig(Base):
    """
    SQLAlchemy ORM model representing a registered webhook configuration.
    Plaintext secrets (whsec_...) are NEVER stored. Only SHA-256 secret_hash is persisted.
    """
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="Human-readable webhook destination label"
    )
    target_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        doc="Validated destination URL for webhook POST delivery"
    )
    secret_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="SHA-256 digest of the plaintext HMAC secret"
    )
    secret_prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="Safe prefix for visual secret identification (e.g. whsec_a8f3)"
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        doc="Active status flag"
    )
    events: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        doc="Comma-separated event subscriptions (e.g. PHISHING_DETECTED,DOMAIN_HIGH_RISK)"
    )
    owner: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="default_owner"
    )
    failure_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    last_delivery_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deliveries: Mapped[list["WebhookDelivery"]] = relationship(
        "WebhookDelivery",
        back_populates="webhook",
        cascade="all, delete-orphan"
    )


class WebhookDelivery(Base):
    """
    SQLAlchemy ORM model representing a webhook delivery audit record.
    Tracks status, attempt count (max 3 total), status codes, and timing.
    """
    __tablename__ = "webhook_deliveries"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    webhook_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("webhooks.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    event_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        doc="Total delivery attempts executed (maximum 3 total)"
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PENDING",
        index=True,
        doc="Delivery status: PENDING, SUCCESS, FAILED"
    )
    response_status_code: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    delivered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    next_retry_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    webhook: Mapped["WebhookConfig"] = relationship(
        "WebhookConfig",
        back_populates="deliveries"
    )
