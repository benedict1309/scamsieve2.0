from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ContentType


class Blacklist(Base):
    __tablename__ = "blacklist"

    id: Mapped[int] = mapped_column(primary_key=True)
    content_type: Mapped[ContentType] = mapped_column(SAEnum(ContentType), nullable=False)
    value: Mapped[str] = mapped_column(String(255), index=True, nullable=False)  # sdt/so TK/URL da chuan hoa
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # ghi chu / mo ta

    # Nguon cua entry: vd "hatinh.gov.vn", "vnreview.vn", "report#123", "csv_import"...
    # De phan biet 2 duong vao Blacklist: (1) qua Report duoc admin duyet, (2) import
    # hang loat tu nguon ngoai da xac minh (vd danh sach so lua dao tu bao/chinh quyen).
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Duoc dien khi entry sinh ra tu mot Report duoc duyet (xem report_service o Buoc 6)
    source_report_id: Mapped[Optional[int]] = mapped_column(ForeignKey("reports.id"), nullable=True)

    # Nullable: entry import hang loat (vd tu file CSV) truoc khi co tai khoan admin
    # thuc hien, hoac khong gan cho admin cu the nao. Khi duyet Report, service se
    # dien gia tri nay bang admin dang thao tac.
    created_by_admin_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    source_report: Mapped[Optional["Report"]] = relationship(back_populates="blacklist_entry")
