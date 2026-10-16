from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, Text, DateTime, ForeignKey, JSON
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import InputType, RiskLevel


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    input_type: Mapped[InputType] = mapped_column(SAEnum(InputType), nullable=False)
    # None neu nguoi dung chon khong luu noi dung goc (bao ve rieng tu)
    original_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    risk_level: Mapped[RiskLevel] = mapped_column(SAEnum(RiskLevel), nullable=False)

    # Danh sach cac rule da khop, vi du:
    # [{"rule": "otp_request", "snippet": "cho toi ma OTP", "score": 30,
    #   "explanation": "Yeu cau ma OTP/mat khau la dau hieu lua dao pho bien"}]
    matched_rules: Mapped[list] = mapped_column(JSON, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="scans")
