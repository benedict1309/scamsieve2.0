from datetime import datetime
from typing import Optional

from sqlalchemy import Text, DateTime, ForeignKey, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ContentType, ReportStatus


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Cho phep gui an danh: reporter_id co the None
    reporter_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    reporter_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # ho tro rate-limit an danh

    content_type: Mapped[ContentType] = mapped_column(SAEnum(ContentType), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)  # noi dung nghi van
    reporter_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[ReportStatus] = mapped_column(
        SAEnum(ReportStatus), default=ReportStatus.PENDING, nullable=False
    )
    reviewed_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    admin_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Quan he
    reporter: Mapped[Optional["User"]] = relationship(
        back_populates="reports", foreign_keys=[reporter_id]
    )
    reviewer: Mapped[Optional["User"]] = relationship(
        back_populates="reviewed_reports", foreign_keys=[reviewed_by_id]
    )
    blacklist_entry: Mapped[Optional["Blacklist"]] = relationship(back_populates="source_report")
