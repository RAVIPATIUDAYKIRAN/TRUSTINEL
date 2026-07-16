import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.website_scan import WebsiteScan


class ScanHistory(Base):
    """
    ORM Model logging historical transitions and actions throughout a scan lifespan.
    """
    __tablename__ = "scan_history"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        doc="Unique identifier for the history event entry."
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("website_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Foreign Key referencing the parent website scan."
    )
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="Action executed on the scan, e.g. SCAN_INITIATED, REPORT_GENERATED, SCAN_FAILED."
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        doc="Result status state of the logged action."
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc="Timestamp when the action was recorded."
    )

    # Relationships
    website_scan: Mapped["WebsiteScan"] = relationship(
        back_populates="history_entries",
        doc="The website scan metadata linked to this history record."
    )
