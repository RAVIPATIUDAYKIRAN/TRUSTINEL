import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class APIKey(Base):
    """
    SQLAlchemy ORM Model representing an API key for enterprise rate limit tiering & authentication.
    The plaintext API key is NEVER stored. Only the SHA-256 key_hash is persisted.
    """
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    key_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        doc="SHA-256 digest of the plaintext API key"
    )
    key_prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="Safe prefix for visual key identification (e.g. trn_live_a8f3)"
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="Human-readable name/label for the API key"
    )
    owner: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="default_owner",
        doc="Owner identifier or organization"
    )
    tier: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="STANDARD",
        doc="API rate limiting tier: STANDARD or ENTERPRISE"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        doc="Active status flag"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
