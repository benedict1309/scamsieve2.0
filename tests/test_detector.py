"""
Unit test cho module detector - nhom rule "gia danh co quan/to chuc".
Chay: pytest tests/test_detector.py -v
"""
from app.detector.rules import (
    check_impersonation,
    check_otp,
    check_urgent_transfer,
    check_suspicious_url,
    check_prize,
    check_app_install,
    detect_all,
)
from app.detector.scorer import total_score, classify_risk
from app.models.enums import RiskLevel


class TestImpersonationPoliceCourt:
    def test_co_dau(self):
        text = (
            "Chào anh/chị, tôi là cán bộ Công an quận Hoàn Kiếm. Anh chị đang liên "
            "quan đến một vụ án điều tra rửa tiền, yêu cầu hợp tác, nếu không chúng "
            "tôi sẽ ra lệnh bắt giữ."
        )
        matches = check_impersonation(text)
        rule_ids = [m.rule_id for m in matches]
        assert "imp_police_court" in rule_ids

    def test_khong_dau(self):
        text = (
            "toi la can bo cong an dang dieu tra vu an lien quan den ban, "
            "yeu cau hop tac neu khong se bi trieu tap"
        )
        matches = check_impersonation(text)
        rule_ids = [m.rule_id for m in matches]
        assert "imp_police_court" in rule_ids


class TestImpersonationBank:
    def test_co_dau(self):
        text = (
            "Ngân hàng Vietcombank thông báo tài khoản của quý khách đã bị tạm khóa, "
            "vui lòng xác minh tài khoản ngay để tránh bị phong tỏa."
        )
        matches = check_impersonation(text)
        rule_ids = [m.rule_id for m in matches]
        assert "imp_bank" in rule_ids


class TestImpersonationEcommerce:
    def test_co_dau(self):
        text = (
            "Đơn hàng của bạn đang được giao từ Shopee, vui lòng xác nhận thông tin "
            "để nhận hàng, nếu không đơn hàng sẽ bị hoàn về."
        )
        matches = check_impersonation(text)
        rule_ids = [m.rule_id for m in matches]
        assert "imp_ecommerce" in rule_ids


class TestImpersonationUtility:
    def test_co_dau(self):
        text = (
            "Tập đoàn Điện lực EVN thông báo hóa đơn của bạn còn nợ tiền điện tháng trước, "
            "vui lòng thanh toán ngay để tránh bị cắt điện."
        )
        matches = check_impersonation(text)
        rule_ids = [m.rule_id for m in matches]
        assert "imp_utility" in rule_ids


class TestOtpShareRequest:
    def test_co_dau(self):
        text = (
            "Đơn hàng cần xác minh người nhận. Shipper sẽ gọi, bạn đọc giúp mã OTP "
            "vừa nhận để bên kho hoàn tất giao hàng."
        )
        matches = check_otp(text)
        rule_ids = [m.rule_id for m in matches]
        assert "otp_share_request" in rule_ids

    def test_khong_dau(self):
        text = "ben ngan hang goi dien bao doc giup ma otp de xac minh giao dich"
        matches = check_otp(text)
        rule_ids = [m.rule_id for m in matches]
        assert "otp_share_request" in rule_ids

    def test_bien_the_cho_toi_ma(self):
        text = "Anh cho em xin mã OTP vừa gửi về máy để em xử lý đơn hàng giúp anh nhé."
        matches = check_otp(text)
        rule_ids = [m.rule_id for m in matches]
        assert "otp_share_request" in rule_ids

    def test_khong_bao_nham_tin_ngan_hang_that(self):
        # Tin OTP that tu ngan hang: co nhac "OTP" nhung KHONG yeu cau doc/cung cap
        text = (
            "Quy khach dang thuc hien Chuyen tien nhanh 247 den TK Nguoi nhan: "
            "NGUYEN VAN A So tien: 500,000 Ma OTP: 136452 hieu luc 5 phut"
        )
        assert check_otp(text) == []

    def test_khong_bao_nham_tin_canh_bao_khong_cung_cap(self):
        # Tin nhac nho AN TOAN, khong phai yeu cau - khong nen bao
        text = (
            "Quy khach dang thuc hien Lien ket the/TK Sacombank Ma OTP: 587437 hieu luc "
            "5 phut Quy khach se MAT TIEN va THONG TIN neu cung cap Ma OTP cho bat ky ai"
        )
        assert check_otp(text) == []

    def test_chuoi_rong(self):
        assert check_otp("") == []
        assert check_otp("   ") == []


class TestUrgentTransfer:
    def test_gia_danh_nguoi_than_co_dau(self):
        text = (
            "Anh ơi em đang kẹt viện phí cho mẹ 5 triệu, mai em gửi lại liền. "
            "Anh chuyển gấp giúp em số 1234567890 Vietcombank với, em cảm ơn anh nhiều."
        )
        matches = check_urgent_transfer(text)
        rule_ids = [m.rule_id for m in matches]
        assert "urgent_transfer" in rule_ids

    def test_khong_dau(self):
        text = "chi oi em dang ket tien vien phi, chi chuyen ngay giup em duoc khong"
        matches = check_urgent_transfer(text)
        rule_ids = [m.rule_id for m in matches]
        assert "urgent_transfer" in rule_ids

    def test_doa_phong_toa(self):
        text = "Tài khoản của bạn bị nghi ngờ gian lận, vui lòng xác minh ngay để tránh bị phong tỏa."
        matches = check_urgent_transfer(text)
        rule_ids = [m.rule_id for m in matches]
        assert "urgent_transfer" in rule_ids

    def test_khong_bao_nham_tin_binh_thuong(self):
        text = "Chào bạn, cuối tuần này rảnh không, đi xem phim nhé."
        assert check_urgent_transfer(text) == []

    def test_chuoi_rong(self):
        assert check_urgent_transfer("") == []
        assert check_urgent_transfer("   ") == []


class TestSuspiciousUrl:
    def test_domain_gia_mao_ngan_hang(self):
        text = (
            "Vietcombank thông báo tài khoản của bạn tạm khóa, vui lòng xác minh tại "
            "https://vietcombank.vn-gll.top/xacthuc để mở khóa."
        )
        matches = check_suspicious_url(text)
        rule_ids = [m.rule_id for m in matches]
        assert "suspicious_url" in rule_ids

    def test_domain_gia_mao_co_quan_nha_nuoc(self):
        text = "Viện kiểm sát thông báo quyết định phong tỏa tài khoản, xem chi tiết: http://toaan.ho-so-online.vip"
        matches = check_suspicious_url(text)
        rule_ids = [m.rule_id for m in matches]
        assert "suspicious_url" in rule_ids

    def test_www_prefix(self):
        text = "Xem chi tiết khuyến mãi tại www.shopee.tuyendung-ctv.top nhé."
        matches = check_suspicious_url(text)
        rule_ids = [m.rule_id for m in matches]
        assert "suspicious_url" in rule_ids

    def test_khong_bao_nham_domain_that(self):
        text = "Viettel thông báo: quý khách vừa đăng ký gói cước tại viettel.vn, chi tiết truy cập mydata.viettel.vn."
        assert check_suspicious_url(text) == []

    def test_khong_bao_nham_khong_co_link(self):
        text = "Chào bạn, mai đi cà phê không?"
        assert check_suspicious_url(text) == []

    def test_chuoi_rong(self):
        assert check_suspicious_url("") == []
        assert check_suspicious_url("   ") == []


class TestFakePrize:
    def test_trung_thuong_dong_phi(self):
        text = "Bạn trúng thưởng 50 triệu đồng! Để nhận, đóng phí hồ sơ 500 nghìn vào số tài khoản 123456."
        matches = check_prize(text)
        rule_ids = [m.rule_id for m in matches]
        assert "fake_prize" in rule_ids

    def test_trung_giai_quay_so(self):
        text = "Chúc mừng bạn đã may mắn quay trúng thưởng 1 xe máy Honda. Nhập thông tin nhận thưởng tại link bên dưới."
        matches = check_prize(text)
        rule_ids = [m.rule_id for m in matches]
        assert "fake_prize" in rule_ids

    def test_khong_dau(self):
        text = "so dien thoai cua ban da trung giai dac biet, hoan tat thu tuc nhan qua ngay hom nay"
        matches = check_prize(text)
        rule_ids = [m.rule_id for m in matches]
        assert "fake_prize" in rule_ids

    def test_khong_bao_nham_tiep_thi_that(self):
        # Tin tiep thi that tu telco: chi la "CO HOI" trung thuong, khong doi phi
        text = (
            "MobiFone dành tặng Quý khách cơ hội trúng thưởng IPHONE 14 PRO khi tham gia khảo "
            "sát và chia sẻ ý kiến về MobiFone tại https://chiase.mobifone.vn/"
        )
        assert check_prize(text) == []

    def test_khong_bao_nham_khong_lien_quan(self):
        assert check_prize("Chào bạn, mai đi cà phê không?") == []

    def test_chuoi_rong(self):
        assert check_prize("") == []
        assert check_prize("   ") == []


class TestAppInstall:
    def test_link_apk_truc_tiep(self):
        text = "Yêu cầu công dân vào phần mềm xác minh dữ liệu, tải app tại: http://bocongan.apk-chinhphu.cc"
        matches = check_app_install(text)
        rule_ids = [m.rule_id for m in matches]
        assert "app_install_apk" in rule_ids

    def test_cai_dat_ngoai_ch_play(self):
        text = "Anh cài đặt ứng dụng hỗ trợ này giúp em, không qua CH Play mà tải trực tiếp từ link em gửi nhé."
        matches = check_app_install(text)
        rule_ids = [m.rule_id for m in matches]
        assert "app_install_unofficial" in rule_ids

    def test_khong_bao_nham_cai_app_that(self):
        text = "Tải & cài đặt ví MoMo để nhận ngay ưu đãi. Chi tiết: https://momo.vn"
        assert check_app_install(text) == []

    def test_khong_bao_nham_co_quan_nha_nuoc_that(self):
        text = (
            "Bộ thông tin và truyền thông: Hãy cài đặt sử dụng ứng dụng i-Speed để kiểm tra "
            "tốc độ truy cập Internet của bạn."
        )
        assert check_app_install(text) == []

    def test_chuoi_rong(self):
        assert check_app_install("") == []
        assert check_app_install("   ") == []


class TestNoFalsePositive:
    def test_tin_nhan_binh_thuong(self):
        text = "Chào bạn, tối nay đi ăn lẩu không? Mình đặt bàn lúc 7h nhé."
        matches = check_impersonation(text)
        assert matches == []

    def test_chuoi_rong(self):
        assert check_impersonation("") == []
        assert check_impersonation("   ") == []


class TestSnippetExtraction:
    def test_snippet_khong_rong(self):
        text = "Chúng tôi là Công an, yêu cầu quý khách hợp tác để tránh bị lừa đảo."
        matches = check_impersonation(text)
        assert len(matches) == 1
        assert matches[0].snippet != ""
        assert "an" in matches[0].snippet.lower()  # mot phan cua "Cong an"


class TestScorer:
    def test_diem_va_muc_do_tang_dan(self):
        # Khong co dau hieu gi -> LOW
        assert classify_risk(0) == RiskLevel.LOW
        # Diem trung binh -> MEDIUM
        assert classify_risk(40) == RiskLevel.MEDIUM
        assert classify_risk(69) == RiskLevel.MEDIUM
        # Diem cao -> HIGH
        assert classify_risk(70) == RiskLevel.HIGH
        assert classify_risk(100) == RiskLevel.HIGH

    def test_tong_diem_khong_vuot_qua_100(self):
        text = (
            "toi la can bo cong an dieu tra vu an, ngan hang thong bao tai khoan cua ban "
            "bi khoa, shopee bao don hang cua ban bi loi, dien luc evn thong bao hoa don cua ban"
        )
        matches = detect_all(text)
        # Ca 4 nhom deu khop -> 25+20+18+20 = 83, van duoi 100 nhung test gioi han chung
        score = total_score(matches)
        assert score <= 100
        assert len(matches) == 4  # ca 4 nhom gia danh deu duoc phat hien

    def test_tin_nhan_gia_danh_co_diem_nhung_chua_du_cao(self):
        # Cau nay CO dau hieu de doa/hoi thuc ("yeu cau hop tac neu khong..."),
        # nhung nhom rule "hoi thuc/de doa" chua duoc xay (se lam o lan sau) -
        # nen hien tai chi rule "imp_police_court" khop (25 diem -> LOW).
        # Test nay se can cap nhat len MEDIUM/HIGH sau khi them nhom rule do.
        text = (
            "Tôi là cán bộ công an đang điều tra vụ án liên quan đến anh/chị, "
            "yêu cầu hợp tác nếu không sẽ ra lệnh bắt giữ."
        )
        matches = detect_all(text)
        score = total_score(matches)
        assert score == 25
        assert classify_risk(score) == RiskLevel.LOW

    def test_tin_nhan_binh_thuong_diem_thap(self):
        text = "Chào bạn, mai đi cà phê không?"
        matches = detect_all(text)
        score = total_score(matches)
        assert score == 0
        assert classify_risk(score) == RiskLevel.LOW


class TestAdvancedScamScenarios:
    def test_reverse_otp_scam(self):
        from app.detector.rules import check_reverse_otp_scam
        text = (
            "Vietcombank: Ma OTP 582910 xac nhan thanh toan 15.000.000d tai Dien May Xanh. "
            "Neu khong phai ban thuc hien, vui long truy cap https://vcb-huygiaodich.xyz de huy."
        )
        matches = check_reverse_otp_scam(text)
        assert len(matches) >= 1
        assert matches[0].rule_id == "reverse_otp_scam"
        assert matches[0].score == 50

    def test_bts_station_spoofing(self):
        from app.detector.rules import check_bts_station_spoofing
        text = (
            "Vietcombank tran trong thong bao: Tai khoan quy khach vua duoc cap han muc moi, "
            "vui long dang nhap tai https://vietcombank-nhanqua.vip de xac nhan."
        )
        matches = check_bts_station_spoofing(text)
        assert len(matches) >= 1
        assert matches[0].rule_id == "bts_fake_brand_sms"

    def test_email_display_name_spoofing(self):
        from app.detector.rules import check_email_spoofing
        text = 'Từ: "Ngân hàng Vietcombank CSKH" <hotro.khachhang192@gmail.com>'
        matches = check_email_spoofing(text)
        rule_ids = [m.rule_id for m in matches]
        assert "display_name_email_spoofing" in rule_ids

    def test_official_telco_promotion_not_flagged_as_bts_scam(self):
        from app.detector.rules import detect_all, check_bts_station_spoofing
        text = (
            "[TB] NẠP THẺ LIỀN TAY, DATA XÀI NGAY!\n"
            "Tặng 20% giá trị tất cả thẻ nạp trong ngày 25/09/2026.\n"
            "Tiền KM sử dụng truy cập Internet trong 15 ngày.\n"
            "Nạp thẻ online tại các ví điện tử, ứng dụng thanh toán hoặc trên app Viettel Tammi tại https://vietteltammi.go.link/naptienkm20\n"
            "Để nạp thẻ cào, Quý khách soạn NT [Mã thẻ] gửi 100.\n"
            "Chi tiết gọi 197 (phím 19, 0đ). Trân trọng."
        )
        assert check_bts_station_spoofing(text) == []
        matches = detect_all(text)
        assert matches == []

    def test_official_telco_campaign_url_not_impersonation(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation
        res = check_brand_impersonation("vietteltammi.go.link")
        assert res.get("is_impersonation") is False
        assert res.get("is_authorized") is True

    def test_dga_domain_detection(self):
        from app.detector.patterns.url_patterns import check_dga_domain
        from app.detector.rules import check_suspicious_url
        dga_info = check_dga_domain("gwx6sd.cc")
        assert dga_info["is_dga"] is True
        assert dga_info["vowel_ratio"] == 0.0

        matches = check_suspicious_url("Truy cập vào trang https://gwx6sd.cc để nhận quà")
        rule_ids = [m.rule_id for m in matches]
        assert "dga_random_domain" in rule_ids
        assert "suspicious_url" in rule_ids

    def test_combosquatting_detection(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation
        from app.detector.rules import check_suspicious_url
        res = check_brand_impersonation("vietcombank-ebank.xyz")
        assert res.get("is_impersonation") is True
        assert res.get("type") == "COMBOSQUATTING"
        assert "ebank" in res.get("matched_keywords", [])

        matches = check_suspicious_url("Đăng nhập https://vietcombank-ebank.xyz để cập nhật mã Smart OTP")
        rule_ids = [m.rule_id for m in matches]
        assert "brand_impersonation_url" in rule_ids

    def test_subdomain_deception_detection(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation
        res = check_brand_impersonation("vietcombank.com.vn.attacker-server.xyz")
        assert res.get("is_impersonation") is True
        assert res.get("type") == "SUBDOMAIN_DECEPTION"
        assert res.get("brand") == "vietcombank"

    def test_homoglyph_attack_detection(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation
        from app.detector.rules import check_suspicious_url
        # Tên miền chứa ký tự Cyrillic 'е' (U+0435) thay vì Latin 'e'
        cyrillic_domain = "vi\u0435tcombank.com"
        res = check_brand_impersonation(cyrillic_domain)
        assert res.get("is_impersonation") is True
        assert res.get("type") == "HOMOGLYPH_ATTACK"
        assert res.get("brand") == "vietcombank"

        matches = check_suspicious_url(f"Truy cập {cyrillic_domain} để cập nhật thông tin")
        rule_ids = [m.rule_id for m in matches]
        assert "brand_impersonation_url" in rule_ids

    def test_tunnel_hosting_abuse_detection(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation
        res = check_brand_impersonation("vietcombank-login.trycloudflare.com")
        assert res.get("is_impersonation") is True
        assert res.get("type") == "TUNNEL_HOSTING_ABUSE"
        assert res.get("brand") == "vietcombank"

    def test_credential_spoofing_detection(self):
        from app.detector.rules import check_suspicious_url
        spoofed_url = "https://vietcombank.com.vn@evil-attacker.xyz/login"
        matches = check_suspicious_url(f"Đăng nhập tài khoản tại {spoofed_url}")
        rule_ids = [m.rule_id for m in matches]
        assert "credential_spoofing_url" in rule_ids

    def test_open_redirect_abuse_detection(self):
        from app.detector.rules import check_suspicious_url
        open_redir_url = "https://www.google.com/url?q=https://gwx6sd.cc"
        matches = check_suspicious_url(f"Bấm vào đường link nhận thưởng: {open_redir_url}")
        rule_ids = [m.rule_id for m in matches]
        assert "open_redirect_abuse" in rule_ids

    def test_zalo_me_scam_not_bypassed(self):
        from app.detector.scorer import RiskScorer
        scorer = RiskScorer()
        scam_text = "Tuyển CTV làm việc tại nhà chốt đơn lương 500k/ngày nhận tiền ngay, bấm vào https://zalo.me/g/abcxyz để vào nhóm nhận nhiệm vụ"
        res = scorer.analyze_message(scam_text)
        assert res["is_scam"] is True
        assert res["risk_level"] in ("MEDIUM", "HIGH")
        assert res["risk_score"] >= 50.0

    def test_scam_with_legit_url_not_bypassed(self):
        from app.detector.scorer import RiskScorer
        scorer = RiskScorer()
        scam_text = "Yêu cầu cung cấp mã OTP xác thực ngay nếu không tài khoản sẽ bị khóa. Chi tiết xem tại https://vietcombank.com.vn"
        res = scorer.analyze_message(scam_text)
        assert res["is_scam"] is True
        assert res["risk_level"] in ("MEDIUM", "HIGH")
