"""
Unit tests cho app.services.report_service:
- Chuẩn hóa nội dung báo cáo (_normalize_content_for_lookup)
- Thẩm định đe dọa tức thì (verify_report_threat_instantly)
- Tiếp nhận báo cáo cộng đồng và tự động khóa Blacklist (submit_community_report)
- Kiểm tra danh tiếng cộng đồng (check_community_reputation_matches)
"""
import pytest
from app.database import SessionLocal, Base, engine
from app.models.enums import ContentType, ReportStatus
from app.models.report import Report
from app.models.blacklist import Blacklist
from app.services.report_service import (
    _normalize_content_for_lookup,
    verify_report_threat_instantly,
    submit_community_report,
    check_community_reputation_matches,
)


@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


class TestReportService:
    def test_normalize_content_phone(self):
        assert _normalize_content_for_lookup("0981 234 567", ContentType.PHONE) == "0981234567"
        assert _normalize_content_for_lookup("0981-234-567", ContentType.PHONE) == "0981234567"

    def test_normalize_content_url(self):
        assert _normalize_content_for_lookup("HTTPS://EXAMPLE.COM/PATH/", ContentType.URL) == "https://example.com/path"

    def test_normalize_content_text(self):
        assert _normalize_content_for_lookup("   Tin nhan lua dao   ", ContentType.TEXT) == "Tin nhan lua dao"

    def test_verify_report_threat_instantly_blacklist_hit(self, db_session):
        # Tạo sẵn bản ghi blacklist
        bl_val = "0999888777"
        existing = db_session.query(Blacklist).filter(Blacklist.value == bl_val).first()
        if not existing:
            db_session.add(Blacklist(content_type=ContentType.PHONE, value=bl_val, note="Test Blacklist"))
            db_session.commit()

        res = verify_report_threat_instantly(bl_val, ContentType.PHONE, db=db_session)
        assert res["verdict"] == "VERIFIED_SCAM"
        assert res["is_verified"] is True
        assert res["action"] == "blacklist_hit"

    def test_verify_report_threat_phishing_url(self, db_session):
        phishing_url = "http://vietcombank-login.xyz/portal"
        res = verify_report_threat_instantly(phishing_url, ContentType.URL, db=db_session)
        assert res["verdict"] == "VERIFIED_SCAM"
        assert res["is_verified"] is True

    def test_submit_community_report_and_auto_blacklist(self, db_session):
        test_url = "http://scam-threat-test-domain.xyz/auth"
        report = submit_community_report(
            db=db_session,
            content=test_url,
            content_type=ContentType.URL,
            scam_type="Mạo danh ngân hàng",
            reporter_note="Trang web yêu cầu mã OTP",
            is_scam=True,
        )
        assert report.id is not None
        assert report.content == test_url
        assert report.status in (ReportStatus.APPROVED, ReportStatus.PENDING)

        # Kiểm tra tự động thêm vào blacklist nếu được xác thực
        if report.status == ReportStatus.APPROVED:
            bl = db_session.query(Blacklist).filter(Blacklist.value == test_url).first()
            assert bl is not None

    def test_check_community_reputation_matches(self, db_session):
        known_bad_phone = "02499999888"
        # Báo cáo đầu số VoIP này
        submit_community_report(
            db=db_session,
            content=known_bad_phone,
            content_type=ContentType.PHONE,
            scam_type="Giả danh cơ quan",
            reporter_note="Gọi điện dọa bắt giam",
            is_scam=True,
        )

        matches = check_community_reputation_matches(known_bad_phone, db=db_session)
        assert len(matches) > 0
        assert any("cộng đồng" in m.category.lower() or "phản ánh" in m.category.lower() for m in matches)
