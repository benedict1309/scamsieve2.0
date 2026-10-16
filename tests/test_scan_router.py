"""
Test tich hop cho router /scan (Buoc 5), dung FastAPI TestClient.
Chay: pytest tests/test_scan_router.py -v

Luu y: dung chung DB dev (sqlite:///./scamsieve.db, xem app/config.py) vi
day la cach don gian nhat cho giai doan hoc tap - bang Blacklist rong nen
khong anh huong ket qua cac test o day (chi test phan detect_all()).
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestScanForm:
    def test_get_scan_tra_ve_form(self):
        response = client.get("/scan")
        assert response.status_code == 200
        assert "Kiểm tra nội dung" in response.text
        assert "<textarea" in response.text
        assert "Kiểm tra bằng nội dung" in response.text
        assert "Kiểm tra bằng hình ảnh" in response.text

    def test_get_scan_che_do_hinh_anh(self):
        response = client.get("/scan?mode=image")
        assert response.status_code == 200
        assert "Kiểm tra bằng hình ảnh" in response.text
        assert "Tải hoặc chụp ảnh màn hình" in response.text


class TestScanSubmit:
    def test_noi_dung_rong_bao_loi(self):
        response = client.post("/scan", data={"content": "   ", "input_type": "text"})
        assert response.status_code == 200
        assert "Vui lòng dán nội dung" in response.text

    def test_noi_dung_lua_dao_ro_rang_hien_thi_canh_bao(self):
        text = (
            "Chúc mừng bạn đã trúng thưởng 50 triệu đồng! Để nhận, đóng phí hồ sơ 500 nghìn "
            "và chuyển gấp giúp chúng tôi vào số tài khoản, xem chi tiết tại "
            "http://nhanthuong-vn.top"
        )
        response = client.post("/scan", data={"content": text, "input_type": "text"})
        assert response.status_code == 200
        # Nhieu rule cung khop (trung thuong + chuyen gap + URL dang ngo)
        # nen phai len it nhat muc MEDIUM.
        assert ("risk-medium" in response.text) or ("risk-high" in response.text)
        assert "score-circle-bar" in response.text

    def test_noi_dung_binh_thuong_khong_canh_bao(self):
        response = client.post(
            "/scan", data={"content": "Chào bạn, cuối tuần này rảnh không, đi xem phim nhé.", "input_type": "text"}
        )
        assert response.status_code == 200
        assert "risk-low" in response.text
        assert "score-circle-bar" in response.text

    def test_giu_lai_noi_dung_da_nhap_khi_bao_loi(self):
        response = client.post("/scan", data={"content": "   ", "input_type": "email"})
        assert response.status_code == 200
        # input_type da chon truoc do (email) van duoc giu lai tren form
        assert 'value="email" selected' in response.text


class TestScanImage:
    def test_upload_anh_thanh_cong(self):
        # 1x1 transparent PNG
        dummy_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
        response = client.post(
            "/scan-image",
            files={"image": ("screenshot.png", dummy_png, "image/png")},
        )
        assert response.status_code == 200
        assert "Kết quả kiểm tra" in response.text
        assert "Ảnh chụp đã phân tích" in response.text or "data:image/png;base64" in response.text

    def test_upload_anh_rong_bao_loi(self):
        response = client.post(
            "/scan-image",
            files={"image": ("empty.png", b"", "image/png")},
        )
        assert response.status_code == 200
        assert "Vui lòng chọn" in response.text

    def test_api_ocr_extract(self):
        dummy_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
        response = client.post(
            "/api/ocr-extract",
            files={"image": ("screenshot.png", dummy_png, "image/png")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "success" in data

    def test_api_gemini_consult_empty_content(self):
        response = client.post("/api/gemini-consult", data={"content": "   "})
        assert response.status_code == 200
        data = response.json()
        assert data.get("active") is False
        assert "Nội dung trống" in data.get("error", "")

    def test_api_gemini_consult_cross_verification_overrides_hallucination(self, monkeypatch):
        from app.services.gemini_service import gemini_service
        # Mô phỏng trường hợp Gemini AI Cloud bị ảo giác trả về is_scam = True cho tin nhắn Viettel chính thống
        monkeypatch.setattr(
            gemini_service,
            "analyze_message",
            lambda text: {
                "active": True,
                "is_scam": True,
                "confidence": 85.0,
                "risk_level": "HIGH",
                "category": "Tin nhắn giả mạo thương hiệu / Phishing",
                "analysis": "- Dấu hiệu lừa đảo giả mạo.",
                "recommendation": "Không bấm link.",
            }
        )

        telco_msg = (
            "[TB] NHẬN NGAY 50K ĐIỂM VIETTEL++\n"
            "Nhận quà và trải nghiệm các tiện ích hấp dẫn ngay trên ứng dụng Viettel Tammi tại https://viettel.vn/50kdiem\n"
            "Chi tiết liên hệ 198 (0đ)."
        )

        response = client.post("/api/gemini-consult", data={"content": telco_msg})
        assert response.status_code == 200
        data = response.json()
        # Cross-Verification Guardrail bắt buộc phải phủ quyết kết quả sai của Gemini
        assert data["is_scam"] is False
        assert data["risk_level"] == "LOW"
        assert "chính thống" in data["category"]

