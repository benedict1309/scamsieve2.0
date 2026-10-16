import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestChatbot:
    def test_chat_page_get_200(self):
        resp = client.get("/chat", follow_redirects=True)
        assert resp.status_code == 200
        assert "Trợ lý AI P-Sieve" in resp.text
        assert "Chatbot của P-Sieve" in resp.text
        assert "ms-chat-window" in resp.text

    def test_api_chat_empty_message_returns_400(self):
        resp = client.post("/api/chat", json={"message": "   "})
        assert resp.status_code == 400

    def test_api_chat_police_scam_inquiry(self):
        resp = client.post(
            "/api/chat",
            json={
                "message": "Có người tự xưng là công an C02 gọi điện bảo tôi buôn ma túy và dọa bắt, bắt tôi chuyển tiền vào tài khoản tạm giữ, có phải lừa đảo không?",
                "history": []
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "response" in data
        assert len(data["response"]) > 20
        # Kiem tra noi dung canh bao dut khoat
        resp_lower = data["response"].lower()
        assert ("lừa đảo" in resp_lower) or ("không" in resp_lower)

    def test_api_chat_job_scam_inquiry(self):
        resp = client.post(
            "/api/chat",
            json={
                "message": "Bên Shopee tuyển CTV giật đơn online hoa hồng 30% một ngày có uy tín không?",
                "history": []
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert len(data["response"]) > 20

    def test_api_chat_critical_triage_transferred_money(self):
        resp = client.post(
            "/api/chat",
            json={
                "message": "Cứu tôi với, tôi lỡ chuyển tiền 50 triệu và gửi mã OTP cho bên sàn tài chính rồi, làm sao lấy lại được tiền?",
                "history": []
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["triage_level"] == "CRITICAL"
        assert "15 PHÚT VÀNG" in data["triage_title"]
        assert "quick_actions" in data
        assert len(data["quick_actions"]) >= 2
        # Dam bao khuyen cao hanh dong khan cap
        resp_text = data["response"].lower()
        assert ("khóa" in resp_text) or ("hotline" in resp_text) or ("công an" in resp_text)

    def test_api_chat_scan_in_chat_url(self):
        resp = client.post(
            "/api/chat",
            json={
                "message": "Kiểm tra giúp tôi link này có an toàn không: http://vietcombank-login-ebank.xyz/auth",
                "history": []
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["scan_telemetry"] is not None
        assert data["scan_telemetry"]["has_url"] is True
        assert data["scan_telemetry"]["risk_score"] > 50

    def test_api_chat_bank_hotlines_endpoint(self):
        resp = client.get("/api/chat/bank-hotlines")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert len(data["banks"]) >= 8
        assert any(b["short"] == "VCB" for b in data["banks"])
        assert any(b["short"] == "TCB" for b in data["banks"])
