import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, String, Text, Enum, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import ScanStatus

if TYPE_CHECKING:
    from app.models.trust_report import TrustReport
    from app.models.scan_history import ScanHistory


class WebsiteScan(Base):
    """
    ORM Model representing a target website scan execution.
    """
    __tablename__ = "website_scans"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        doc="Unique identifier for the website scan."
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="The complete URL requested for scan."
    )
    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        doc="The extracted domain/hostname of the target URL."
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        nullable=False,
        default=ScanStatus.PENDING,
        doc="The lifecycle state of the scan."
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc="Timestamp when the scan transaction started."
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        doc="Timestamp when the scan transaction status was updated."
    )

    # Relationships
    trust_report: Mapped[Optional["TrustReport"]] = relationship(
        back_populates="website_scan",
        uselist=False,
        cascade="all, delete-orphan",
        doc="The trust assessment report generated for this scan."
    )
    history_entries: Mapped[List["ScanHistory"]] = relationship(
        back_populates="website_scan",
        cascade="all, delete-orphan",
        doc="The historical event milestones recorded for this scan."
    )
