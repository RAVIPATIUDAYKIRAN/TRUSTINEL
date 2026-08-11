import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, Text, Enum, CheckConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import RiskLevel

if TYPE_CHECKING:
    from app.models.website_scan import WebsiteScan


class TrustReport(Base):
    """
    ORM Model representing the evaluation report produced by the scanning service.
    """
    __tablename__ = "trust_reports"
    __table_args__ = (
        CheckConstraint("trust_score >= 0 AND trust_score <= 100", name="chk_trust_report_score_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        doc="Unique identifier for the trust report."
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("website_scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
        doc="Foreign Key referencing the parent website scan."
    )
    trust_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        doc="The computed trust score ranging from 0 to 100."
    )
    risk_level: Mapped[RiskLevel] = mapped_column(
        Enum(RiskLevel),
        nullable=False,
        doc="The computed risk classification."
    )
    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Detailed text describing the reasons behind the computed rating."
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc="Timestamp when the report was generated."
    )
    explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        doc="Human-readable explanation of the trust evaluation."
    )
    key_risks: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        doc="JSON-serialized list of key security risks identified."
    )
    positive_signals: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        doc="JSON-serialized list of positive security indicators identified."
    )
    recommendation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None,
        doc="Concise user recommendation based on the trust evaluation."
    )

    # Relationships
    website_scan: Mapped["WebsiteScan"] = relationship(
        back_populates="trust_report",
        doc="The website scan metadata linked to this report."
    )
