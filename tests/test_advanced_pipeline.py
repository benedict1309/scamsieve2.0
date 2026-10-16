"""
Unit test kiểm thử các tầng nâng cấp của Pipeline chống gian lận đa lớp:
1. De-obfuscation (Homoglyphs & Teencode).
2. Guardrail chống False Positive trên tin nhắn cảnh báo bảo mật từ ngân hàng.
3. Chặn đứng kịch bản lợi dụng danh nghĩa Shipper/tiện ích để trộm mã OTP (False Negative prevention).
4. Chuẩn hóa SĐT giả mạo chữ 'O' thành số '0' và phân tích rủi ro đầu số người gửi.
"""
from app.detector.text_utils import normalize_text, preprocessor
from app.detector.phone_utils import extract_phone_candidates, analyze_sender_risk
from app.detector.guardrails import guardrail
from app.detector.scorer import scorer
from app.models.enums import RiskLevel


class TestDeObfuscationAndTeencode:
    def test_homoglyph_cyrillic_and_spaced_letters(self):
        # Kẻ gian dùng ký tự Cyrillic 'а', 'о' và chèn dấu chấm giữa các chữ cái
        obfuscated_text = "C.o.n.g A.n T.P t.r.i.e.u t.a.p"
        normalized = normalize_text(obfuscated_text)
        assert "cong an" in normalized
        assert "trieu tap" in normalized

    def test_teencode_expansion(self):
        # Teencode giao dịch tài chính
        text = "ck gap vao stk ngan hang giup minh"
        normalized = normalize_text(text)
        assert "chuyen khoan" in normalized
        assert "so tai khoan" in normalized


class TestContextualGuardrails:
    def test_bank_warning_negation_not_scam(self):
        # Tin nhắn bảo vệ từ Sacombank / Vietcombank
        bank_msg = (
            "Quy khach dang thuc hien Lien ket the. Ma OTP: 587437 hieu luc 3 phut. "
            "Quy khach se MAT TIEN va THONG TIN neu cung cap Ma OTP cho bat ky ai"
        )
        assert guardrail.has_bank_security_warning(bank_msg) is True
        
        # Scorer phân tích tin nhắn cảnh báo này
        result = scorer.analyze_message(bank_msg)
        assert result["risk_level"] == "LOW"
        assert result["is_scam"] is False

    def test_shipper_otp_theft_cannot_bypass(self):
        # Kẻ gian giả danh shipper đòi OTP - KHÔNG được phép bypass
        scam_text = "Em la shipper giao hang day a, anh doc giup em ma OTP de em hoan tat don"
        result = scorer.analyze_message(scam_text)
        
        # Guardrail phải từ chối bypass
        assert "Safe educational/billing/shipping context bypass" not in result["reason"]

    def test_legitimate_utility_can_bypass_when_clean(self):
        # Tin nhắn tiện ích thuần túy không có URL, không đòi OTP/tiền
        clean_utility = "Thong bao: Quy khach da thanh toan tien dien thang 5 thanh cong. Cam on quy khach."
        result = scorer.analyze_message(clean_utility)
        assert result["risk_level"] == "LOW"
        assert result["is_scam"] is False


class TestPhoneNormalizationAndSenderRisk:
    def test_phone_letter_O_replacement(self):
        # Kẻ gian gõ chữ 'O' thay cho số '0'
        text = "Lien he Zalo O987654321 de nhan thuong"
        candidates = extract_phone_candidates(text)
        assert "0987654321" in candidates

    def test_high_risk_international_sender(self):
        sender_info = analyze_sender_risk("+88216543210")
        assert sender_info["type"] == "HIGH_RISK_INTERNATIONAL"
        assert sender_info["risk_score"] > 0

    def test_brandname_sender(self):
        sender_info = analyze_sender_risk("VIETCOMBANK")
        assert sender_info["type"] == "BRANDNAME"
        assert sender_info["risk_score"] == 0.0


class TestVacationPrizeScam:
    def test_trung_thuong_ky_nghi_duong_nhanqua_dot_com(self):
        from app.detector.rules import detect_all
        from app.detector.patterns.url_patterns import url_extractor

        text = "Bạn đã trúng thưởng kỳ nghĩ dưỡng 2 ngày 1 đêm miễn phí hãy truy cập đường link nhanqua.com để nhận thưởng"
        
        # 1. Bắt được URL trần
        urls = url_extractor.extract_urls(text)
        assert "nhanqua.com" in urls

        # 2. Rule engine phát hiện trúng thưởng giả và tên miền mồi chài
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "fake_prize" in rule_ids
        assert "phishing_domain_keyword" in rule_ids


class TestAIModelUnaccentedAndObfuscation:
    def test_ai_detects_unaccented_scam(self):
        from app.detector.text_utils import prepare_model_input
        from app.detector.scorer import scorer

        # Tin nhắn hoàn toàn không dấu
        unaccented_scam = (
            "chao ban, tai khoan ngan hang cua quy khach da bi tam khoa, "
            "vui long xac minh tai khoan gap de tranh bi phong toa so du"
        )
        model_input = prepare_model_input(unaccented_scam)
        prob = scorer.ml_model.predict_proba([model_input])[0][1] * 100
        # AI phải bắt được xác suất lừa đảo cao dù không có dấu
        assert prob >= 70.0

    def test_ai_detects_obfuscated_with_interspersed_noise(self):
        from app.detector.text_utils import prepare_model_input
        from app.detector.scorer import scorer

        # Kẻ gian chèn dấu chấm giữa các chữ cái
        obfuscated_scam = (
            "c.h.u.y.e.n k.h.o.a.n g.a.p v.a.o s.t.k d.e x.a.c m.i.n.h v.u a.n"
        )
        model_input = prepare_model_input(obfuscated_scam)
        prob = scorer.ml_model.predict_proba([model_input])[0][1] * 100
        assert prob >= 70.0


class TestTyposquattingAndBrandProtection:
    def test_bank_typosquatting_vietcornbank(self):
        from app.detector.rules import detect_all

        text = "Vui lòng truy cập https://vietcornbank.com để cập nhật thông tin bảo mật."
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "brand_impersonation_url" in rule_ids
        match = next(m for m in matches if m.rule_id == "brand_impersonation_url")
        assert match.score >= 50
        assert "vietcombank" in match.explanation.lower()

    def test_ecommerce_homoglyph_sh0pee(self):
        from app.detector.rules import detect_all

        text = "Bạn có đơn hàng trúng thưởng tại http://sh0pee.vn/voucher"
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "brand_impersonation_url" in rule_ids

    def test_brand_substring_hijack(self):
        from app.detector.rules import detect_all

        text = "Bộ Công an yêu cầu cài đặt VNeID tại link http://vneid-xacthuc.vip/app"
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "brand_impersonation_url" in rule_ids

    def test_authorized_domains_not_flagged(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation

        # Tên miền chính thức của Vietcombank và Shopee không được báo lừa đảo
        vcb = check_brand_impersonation("vietcombank.com.vn")
        assert vcb.get("is_impersonation") is False
        assert vcb.get("is_authorized") is True

        shopee = check_brand_impersonation("shopee.vn")
        assert shopee.get("is_impersonation") is False
        assert shopee.get("is_authorized") is True

    def test_benign_domains_not_false_positive(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation

        # Không báo nhầm từ ngắn acb/vib trong macbook hay vibrant
        macbook = check_brand_impersonation("macbook.com")
        assert macbook.get("is_impersonation") is False

        vibrant = check_brand_impersonation("vibrant.com")
        assert vibrant.get("is_impersonation") is False


class TestEmailSpoofingAndDisposable:
    def test_disposable_email_flagged(self):
        from app.detector.rules import detect_all

        text = "Nhận hoá đơn và tiền bồi hoàn qua hòm thư invoice123@tempmail.com ngay"
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "disposable_email_domain" in rule_ids

    def test_police_impersonation_via_free_gmail(self):
        from app.detector.rules import detect_all

        text = "Lệnh triệu tập khẩn cấp của Công an TP Hà Nội, phản hồi qua email congan.hanoi@gmail.com"
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "free_email_impersonation" in rule_ids
        match = next(m for m in matches if m.rule_id == "free_email_impersonation")
        assert match.score >= 40

    def test_bank_impersonation_email_standalone(self):
        from app.detector.rules import detect_all

        # Người dùng quét trực tiếp địa chỉ email mạo danh
        text = "vietcombank.cskh.online@gmail.com"
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "free_email_impersonation" in rule_ids

    def test_legitimate_personal_gmail_not_flagged(self):
        from app.detector.rules import detect_all

        # Email trao đổi cá nhân bình thường không bị báo mạo danh
        text = "Mai gửi tài liệu học tập vào email nguyenvanan.k50@gmail.com giúp mình nhé."
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "free_email_impersonation" not in rule_ids
        assert "disposable_email_domain" not in rule_ids


class TestIllegalGamblingAndBetting:
    def test_song_tai_xiu_qbet888(self):
        from app.detector.rules import detect_all
        from app.detector.scorer import score_and_classify
        from app.models.enums import RiskLevel

        text = "Truy cập đường link để dẫn đến sòng tài xỉu qbet888.com"
        matches = detect_all(text)
        rule_ids = [m.rule_id for m in matches]
        assert "illegal_gambling" in rule_ids
        assert "phishing_domain_keyword" in rule_ids

        # Tổng điểm phải >= 70 để đạt mức HIGH (Màu Đỏ)
        score, risk_level = score_and_classify(matches)
        assert score >= 70
        assert risk_level == RiskLevel.HIGH


class TestUnifiedScoringArchitecture:
    def test_harmonized_telco_promotion_safe(self):
        from app.detector.scorer import scorer
        from app.detector.rules import detect_all
        from app.models.enums import RiskLevel

        msg = (
            "[TB] NẠP THẺ LIỀN TAY, DATA XÀI NGAY!\n"
            "Tặng 20% giá trị tất cả thẻ nạp trong ngày 25/09/2026.\n"
            "Tiền KM sử dụng truy cập Internet trong 15 ngày.\n"
            "Nạp thẻ online tại các ví điện tử, ứng dụng thanh toán hoặc trên app Viettel Tammi tại https://vietteltammi.go.link/naptienkm20\n"
            "Để nạp thẻ cào, Quý khách soạn NT [Mã thẻ] gửi 100.\n"
            "Chi tiết gọi 197 (phím 19, 0đ). Trân trọng."
        )
        raw_matches = detect_all(msg)
        unified = scorer.evaluate_unified_risk(msg, raw_matches)
        assert unified["risk_level"] == RiskLevel.LOW
        assert unified["score"] <= 15
        assert unified["ai_result"]["is_scam"] is False
        assert unified["ai_result"]["scam_prob"] < 5.0

    def test_harmonized_critical_scam_high_risk(self):
        from app.detector.scorer import scorer
        from app.detector.rules import detect_all
        from app.models.enums import RiskLevel

        msg = "Em la shipper giao hang day a, anh doc giup em ma OTP de em hoan tat don hang cho anh"
        raw_matches = detect_all(msg)
        unified = scorer.evaluate_unified_risk(msg, raw_matches)
        assert unified["risk_level"] == RiskLevel.HIGH
        assert unified["score"] >= 70
        assert unified["ai_result"]["is_scam"] is True

    def test_harmonized_bank_security_warning_safe(self):
        from app.detector.scorer import scorer
        from app.detector.rules import detect_all
        from app.models.enums import RiskLevel

        msg = (
            "Vietcombank: Quy khach dang thuc hien giao dich 5.000.000d. Ma OTP: 198273. "
            "Khong cung cap ma OTP cho bat ky ai de tranh bi mat tien."
        )
        raw_matches = detect_all(msg)
        unified = scorer.evaluate_unified_risk(msg, raw_matches)
        assert unified["risk_level"] == RiskLevel.LOW
        assert unified["score"] == 0
        assert unified["ai_result"]["is_scam"] is False


class TestDomainIntelligence:
    def test_tldextract_public_suffix_parsing(self):
        from app.services.domain_intel import domain_intel
        parts = domain_intel.extract_domain_parts("https://sub.portal.vietcombank.com.vn/ebank")
        assert parts["domain"] == "vietcombank"
        assert parts["suffix"] == "com.vn"
        assert parts["registered_domain"] == "vietcombank.com.vn"

    def test_campaign_deeplink_parsing(self):
        from app.services.domain_intel import domain_intel
        parts = domain_intel.extract_domain_parts("https://vietteltammi.go.link/naptienkm20")
        assert parts["subdomain"] == "vietteltammi"
        assert parts["domain"] == "go"
        assert parts["suffix"] == "link"
        assert parts["registered_domain"] == "go.link"


class TestVietnameseNLPIntent:
    def test_protective_warning_intent(self):
        from app.detector.vi_nlp_engine import vi_nlp_engine
        text = "Vietcombank khuyen cao: Tuyet doi KHONG chia se ma OTP cho bat ky ai duoi moi hinh thuc."
        res = vi_nlp_engine.analyze_intent(text)
        assert res["intent_category"] == "PROTECTIVE_WARNING"
        assert res["is_protective"] is True
        assert res["is_credential_theft"] is False

    def test_credential_theft_intent(self):
        from app.detector.vi_nlp_engine import vi_nlp_engine
        text = "Em la shipper giao hang, anh doc giup em ma OTP 6 so gui ve may de em hoan tat don nhe."
        res = vi_nlp_engine.analyze_intent(text)
        assert res["is_credential_theft"] is True
        assert res["confidence_modifier"] > 0


class TestImageCrossVerificationGuardrail:
    def test_official_telco_image_ocr_cross_verification_safe(self):
        from app.detector.scorer import scorer
        from app.detector.rules import detect_all
        from app.detector.base import RuleMatch
        from app.models.enums import RiskLevel

        ocr_text = (
            "[TB] NHẬN NGAY 50K ĐIỂM VIETTEL++\n"
            "Nhận quà và trải nghiệm các tiện ích hấp dẫn ngay trên ứng dụng Viettel Tammi tại https://viettel.vn/50kdiem\n"
            "- Đổi điểm Viettel++ sang data, phút gọi và SMS.\n"
            "- Miễn phí data, gọi điện thả ga trên ứng dụng. Chương trình áp dụng cho thuê bao nhận tin nhắn. Chi tiết liên hệ 198 (0đ)."
        )

        matches = detect_all(ocr_text)
        # Mô phỏng Vision AI bị ảo giác gắn cờ lừa đảo
        matches.append(
            RuleMatch(
                rule_id="vision_scam_evidence",
                category="Thông báo / văn bản mạo danh doanh nghiệp (Viettel)",
                snippet="Bằng chứng từ ảnh chụp màn hình",
                score=90,
                explanation="Tên ứng dụng Viettel được ghi là 'Viettel Tammi' thay vì 'My Viettel'.",
            )
        )

        unified = scorer.evaluate_unified_risk(ocr_text, matches)
        assert unified["risk_level"] == RiskLevel.LOW
        assert unified["score"] <= 5  # score nhỏ (trusted domain bypass giảm xuống gần 0) vẫn là LOW
        assert unified["ai_result"]["is_scam"] is False

    def test_genuine_scam_image_remains_high_risk(self):
        from app.detector.scorer import scorer
        from app.detector.rules import detect_all
        from app.detector.base import RuleMatch
        from app.models.enums import RiskLevel

        ocr_text = (
            "Bo Cong An thong bao: Ong co lenh bat tam giam vi lien quan duong day rua tien quoc te. "
            "Truy cap ngay https://congan-toaan-dieutra.xyz de xac minh neu khong se bi phong toa tai san."
        )

        matches = detect_all(ocr_text)
        matches.append(
            RuleMatch(
                rule_id="vision_scam_evidence",
                category="Lệnh bắt giữ giả mạo",
                snippet="Bằng chứng từ ảnh chụp màn hình",
                score=95,
                explanation="Phát hiện lệnh triệu tập giả mạo cơ quan điều tra.",
            )
        )

        unified = scorer.evaluate_unified_risk(ocr_text, matches)
        assert unified["risk_level"] == RiskLevel.HIGH
        assert unified["score"] >= 75
        assert unified["ai_result"]["is_scam"] is True








