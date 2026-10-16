"""
Unit test cho app/detector/phone_utils.py (thuan tuy, khong dung DB).
Chay: pytest tests/test_phone_utils.py -v
"""
from app.detector.phone_utils import extract_phone_candidates


class TestExtractPhoneCandidates:
    def test_so_thuan_khong_dinh_dang(self):
        text = "Goi ngay so 19003439 de duoc ho tro."
        assert "19003439" in extract_phone_candidates(text)

    def test_so_co_khoang_trang(self):
        text = "Goi ngay so 1900 3439 de duoc ho tro."
        assert "19003439" in extract_phone_candidates(text)

    def test_so_landline_co_dau_gach_ngang(self):
        text = "Lien he tong dai 024-3944-6395 de xac minh."
        assert "02439446395" in extract_phone_candidates(text)

    def test_so_di_dong_dang_quoc_te_84(self):
        text = "Anh chuyen khoan gap giup em qua Momo so +84987654321 nhe."
        candidates = extract_phone_candidates(text)
        assert "84987654321" in candidates
        assert "0987654321" in candidates  # dang da doi ve 0 dau de khop Blacklist

    def test_khong_co_so_dien_thoai(self):
        assert extract_phone_candidates("Chao ban, mai di ca phe khong?") == []

    def test_chuoi_rong(self):
        assert extract_phone_candidates("") == []
        assert extract_phone_candidates("   ") == []

    def test_bo_qua_chuoi_so_qua_ngan(self):
        # "2024" (nam) chi co 4 chu so - khong du dai de coi la so dien thoai
        text = "Nam 2024 la mot nam nhieu bien dong."
        assert extract_phone_candidates(text) == []


class TestAnalyzeSenderRisk:
    def test_hotline_chinh_thong_vietcombank(self):
        from app.detector.phone_utils import analyze_sender_risk
        res = analyze_sender_risk("1900545413")
        assert res["risk_score"] == 0.0
        assert res.get("is_verified_official") is True
        assert "Vietcombank" in res["service"]

    def test_hotline_chinh_thong_police_113(self):
        from app.detector.phone_utils import analyze_sender_risk
        res = analyze_sender_risk("113")
        assert res["risk_score"] == 0.0
        assert res.get("is_verified_official") is True

    def test_dau_so_voip_lua_dao_gmobile_024999(self):
        from app.detector.phone_utils import analyze_sender_risk
        res = analyze_sender_risk("02499950012")
        assert res["risk_score"] >= 80.0
        assert "VoIP Gmobile" in res["service"]

    def test_so_di_dong_sim_rac_lap_so_0(self):
        from app.detector.phone_utils import analyze_sender_risk
        res = analyze_sender_risk("0901800000")
        assert res["risk_score"] >= 70.0
