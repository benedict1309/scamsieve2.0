# File: tests/test_api_v1.py
"""
Kiểm thử bộ API V1 dành cho Chrome Extension và hệ thống Client.
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestApiV1Scan:
    def test_scan_empty_returns_400(self):
        resp = client.post("/api/v1/scan", json={"content": "   ", "input_type": "auto"})
        assert resp.status_code == 400
        assert "không được để trống" in resp.json()["detail"]

    def test_scan_safe_text_low_risk(self):
        resp = client.post(
            "/api/v1/scan",
            json={"content": "Hom nay ban co di hoc khong? Nho mang sach vo nhe.", "input_type": "auto"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["risk_level"] == "LOW"
        assert data["is_scam"] is False
        assert data["score"] <= 15

    def test_scan_critical_scam_high_risk(self):
        scam_text = (
            "Chuc mung ban da trung thuong xe SH! Vui long nop phi 500k de nhan qua. "
            "Nhap ngay ma OTP gui ve may cua ban va chuyen tien gap vao tai khoan."
        )
        resp = client.post("/api/v1/scan", json={"content": scam_text, "input_type": "auto"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["risk_level"] == "HIGH"
        assert data["is_scam"] is True
        assert data["score"] >= 70

    def test_scan_official_telco_promo_harmonized_safe(self):
        promo_text = (
            "[TB] NHAN NGAY 50K DIEM VIETTEL++\n"
            "Trai nghiem cac tien ich tren ung dung tai https://viettel.vn/50kdiem. "
            "Chi tiet lien he 198 (0d)."
        )
        resp = client.post("/api/v1/scan", json={"content": promo_text, "input_type": "auto"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["risk_level"] == "LOW"
        assert data["is_scam"] is False
        assert data["score"] == 0


class TestApiV1CheckUrl:
    def test_check_url_official_domain_safe(self):
        resp = client.get("/api/v1/check-url?url=https://viettel.vn/khuyen-mai")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_safe"] is True
        assert data["is_scam"] is False

    def test_check_url_phishing_scam(self):
        resp = client.get("/api/v1/check-url?url=http://vietcornbank-ebank.xyz/login")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["score"] >= 60

    def test_check_url_localhost_psieve_safe(self):
        resp = client.get("/api/v1/check-url?url=http://127.0.0.1:8000/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_safe"] is True
        assert data["is_scam"] is False
        assert data["score"] == 0

    def test_check_url_facebook_safe(self):
        resp = client.get("/api/v1/check-url?url=https://www.facebook.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_safe"] is True
        assert data["is_scam"] is False
        assert data["score"] == 0

    def test_check_url_claude_safe(self):
        resp = client.get("/api/v1/check-url?url=https://claude.ai")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_safe"] is True
        assert data["is_scam"] is False
        assert data["score"] == 0


class TestApiV1ScanImage:
    def test_scan_image_success(self, monkeypatch):
        from app.services.gemini_service import gemini_service
        monkeypatch.setattr(
            gemini_service,
            "analyze_image",
            lambda img_bytes, mime: {
                "active": True,
                "is_scam": False,
                "confidence": 95.0,
                "risk_level": "LOW",
                "category": "Tin nhắn quảng cáo / Thông báo chính thống",
                "extracted_text": "[TB] Trai nghiem My Viettel tai https://viettel.vn. Chi tiet 198.",
                "extracted_phone": "198",
                "visual_evidence": ["Tên miền chính thống viettel.vn"],
                "recommendation": "Nội dung an toàn.",
            }
        )
        dummy_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
        resp = client.post(
            "/api/v1/scan-image",
            files={"image": ("sample.png", dummy_png, "image/png")}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_scam"] is False
        assert data["risk_level"] == "LOW"


class TestApiV1InspectPage:
    def test_inspect_trusted_whitelist_safe(self):
        resp = client.post(
            "/api/v1/inspect-page",
            json={
                "url": "https://vnexpress.net/thoi-su",
                "title": "VnExpress - Báo tiếng Việt nhiều người xem nhất",
                "has_password_input": False,
                "has_otp_input": False,
                "has_credit_card_input": False,
                "text_snippet": "Tin tức thời sự nóng trong ngày",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["score"] == 0
        assert data["is_safe"] is True
        assert data["is_scam"] is False
        assert data["signals"]["is_trusted_whitelist"] is True

    def test_inspect_brand_spoofing_phishing(self):
        resp = client.post(
            "/api/v1/inspect-page",
            json={
                "url": "http://vcb-digibank-login.xyz/auth",
                "title": "Vietcombank - Đăng nhập VCB Digibank",
                "has_password_input": True,
                "has_otp_input": True,
                "has_credit_card_input": False,
                "form_action_domains": ["hack-server.ru"],
                "text_snippet": "Vui lòng nhập mật khẩu và mã OTP để xác thực tài khoản Vietcombank của bạn.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["score"] >= 90
        assert data["is_scam"] is True
        assert data["signals"]["brand_spoofed"] is True
        assert data["signals"]["credential_harvesting"] is True
        assert data["signals"]["cross_domain_form"] is True

    def test_inspect_otp_harvesting_untrusted_domain(self):
        resp = client.post(
            "/api/v1/inspect-page",
            json={
                "url": "http://quatang-triandacbiet.xyz/claim",
                "title": "Nhận quà tri ân",
                "has_password_input": False,
                "has_otp_input": True,
                "has_credit_card_input": False,
                "text_snippet": "Nhập mã OTP ngân hàng gửi về máy để nhận quà trị giá 5 triệu đồng.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["score"] >= 85
        assert data["is_scam"] is True
        assert data["signals"]["credential_harvesting"] is True

    def test_inspect_clean_blog_low_risk(self):
        resp = client.post(
            "/api/v1/inspect-page",
            json={
                "url": "https://my-coding-blog.org/python-tutorial",
                "title": "Hướng dẫn học Python căn bản cho người mới bắt đầu",
                "has_password_input": False,
                "has_otp_input": False,
                "has_credit_card_input": False,
                "text_snippet": "Chào mừng bạn đến với bài viết hướng dẫn học lập trình Python hôm nay.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["score"] <= 20
        assert data["is_safe"] is True
        assert data["is_scam"] is False

    def test_inspect_high_risk_tld_flagged(self):
        resp = client.post(
            "/api/v1/inspect-page",
            json={
                "url": "https://unknown-random-portal.top/index",
                "title": "Welcome to my portal",
                "has_password_input": False,
                "has_otp_input": False,
                "has_credit_card_input": False,
                "text_snippet": "Random text here",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["signals"]["is_high_risk_tld"] is True
        assert data["score"] >= 45


class TestApiV1InspectDeepAi:
    def test_inspect_deep_ai_job_scam(self):
        resp = client.post(
            "/api/v1/inspect-deep-ai",
            json={
                "url": "https://vieclam-tainha.site",
                "title": "Tuyển dụng CTV giật đơn Shopee",
                "page_text": "Tuyển ctv làm tại nhà, công việc giật đơn chốt đơn hưởng hoa hồng 20-30% ngày, nhận tiền ngay.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_scam"] is True
        assert data["risk_level"] == "HIGH"
        category_lower = data["scam_category"].lower()
        assert ("tuyển dụng" in category_lower) or ("việc làm" in category_lower) or ("nhiệm vụ" in category_lower)

    def test_inspect_deep_ai_clean_content(self):
        resp = client.post(
            "/api/v1/inspect-deep-ai",
            json={
                "url": "https://hocpython.edu/lesson-1",
                "title": "Khóa học Python căn bản",
                "page_text": "Hôm nay chúng ta sẽ tìm hiểu về cú pháp biến và vòng lặp trong ngôn ngữ lập trình Python.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_scam"] is False
        assert data["risk_level"] == "LOW"


class TestApiV1Health:
    def test_health_check_returns_ok(self):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"



