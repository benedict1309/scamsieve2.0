"""
Unit test cho app/services/blacklist_service.py.
Dung SQLite in-memory rieng cho test (khong dung chung scamsieve.db that),
tu tao bang va them vai dong Blacklist mau truoc moi test.
Chay: pytest tests/test_blacklist_service.py -v
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.enums import ContentType
from app.models.blacklist import Blacklist
# Dam bao Base.metadata biet het cac bang (co khoa ngoai toi users/reports)
from app.models import user, report, scan  # noqa: F401

from app.services.blacklist_service import check_blacklist_phone


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    session.add_all(
        [
            Blacklist(
                content_type=ContentType.PHONE,
                value="19003439",
                note="Đầu số dịch vụ giá trị gia tăng bị cảnh báo lừa đảo",
                source="hatinh.gov.vn",
            ),
            Blacklist(
                content_type=ContentType.PHONE,
                value="0987654321",
                note="Số di động từng được báo cáo lừa đảo",
                source="report#123",
            ),
        ]
    )
    session.commit()

    yield session
    session.close()


class TestCheckBlacklistPhone:
    def test_khop_so_premium(self, db_session):
        text = "Goi ngay so 1900 3439 de duoc ho tro."
        matches = check_blacklist_phone(text, db_session)
        rule_ids = [m.rule_id for m in matches]
        assert "blacklist_phone" in rule_ids

    def test_khop_so_di_dong_dang_quoc_te(self, db_session):
        text = "Anh chuyen khoan gap giup em qua Momo so +84987654321 nhe."
        matches = check_blacklist_phone(text, db_session)
        rule_ids = [m.rule_id for m in matches]
        assert "blacklist_phone" in rule_ids

    def test_khong_khop_so_khong_co_trong_blacklist(self, db_session):
        text = "Goi ngay so 0912345678 de duoc ho tro."
        assert check_blacklist_phone(text, db_session) == []

    def test_khong_co_so_dien_thoai_nao(self, db_session):
        text = "Chao ban, mai di ca phe khong?"
        assert check_blacklist_phone(text, db_session) == []

    def test_chuoi_rong(self, db_session):
        assert check_blacklist_phone("", db_session) == []
