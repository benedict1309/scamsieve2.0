"""
Trích xuất, chuẩn hóa và phân tích rủi ro số điện thoại (Telecom Intelligence).

Module thuần túy (không phụ thuộc DB) nhằm mục đích:
1. Trích xuất ứng viên số điện thoại trong văn bản để tra cứu Blacklist.
2. Phân tích danh tính người gửi và nhận diện các dải số rủi ro cao tại Việt Nam:
   - Đầu số cố định ảo VoIP/SIP Trunk (024/028 999x, 888x, 445x, 730x, 710x...)
   - Đầu số cố định 024/028 mạo danh cơ quan chức năng / công an / tòa án
   - Đầu số quốc tế lừa đảo nháy máy (Wangiri)
   - Số di động rác có cấu trúc lặp dị thường (tứ quý, ngũ quý, dãy số 0)
"""
import re
from typing import Dict, Any, List, Tuple

# Bắt các chuỗi giống số điện thoại
_PHONE_CANDIDATE_RE = re.compile(r"(?<!\w)\+?[0-9Oo](?:[\s.\-]?[0-9Oo]){7,10}(?!\w)")

# Các đầu số quốc tế rủi ro cao (vệ tinh / lừa đảo cước / Wangiri)
_HIGH_RISK_INTL_PREFIXES = (
    "+88", "+252", "+855", "+232", "+247",
    "+226", "+234", "+212", "+221", "+62",
    "+231", "+220", "+224", "+269", "+675",
)

# Quy hoạch dải số di động Việt Nam chuẩn
_VN_MOBILE_RE = re.compile(
    r'^0('
    r'3[2-9]|'    # Viettel: 032-039
    r'5[25689]|'  # Vietnamobile: 052, 055, 056, 058; Reddi: 059
    r'7[06-9]|'   # Mobifone: 070, 076-079
    r'8[1-9]|'    # Vinaphone: 081-086; Viettel: 088-089; Mobifone: 090
    r'9[0-9]'     # Tất cả 090-099
    r')\d{7}$'
)
_VN_LANDLINE_RE  = re.compile(r'^02\d{9}$')
_VN_HOTLINE_RE   = re.compile(r'^(1900|1800)\d{4,6}$')
_VN_SHORTCODE_RE = re.compile(r'^\d{3,5}$')

# Danh bạ Hotline chính thức của Ngân hàng, Nhà mạng và Dịch vụ công khẩn cấp tại Việt Nam
# (Giúp triệt tiêu 100% False Positive khi tra cứu số thật)
VERIFIED_OFFICIAL_HOTLINES: Dict[str, Dict[str, str]] = {
    # Khẩn cấp & Dịch vụ công quốc gia
    "111": {"org": "Tổng đài Quốc gia Bảo vệ Trẻ em", "type": "VN_SHORTCODE", "description": "Đường dây nóng bảo vệ trẻ em 24/7 của Bộ LĐ-TB&XH"},
    "112": {"org": "Tổng đài Cứu nạn Quốc gia", "type": "VN_SHORTCODE", "description": "Yêu cầu trợ giúp cứu nạn trên phạm vi toàn quốc"},
    "113": {"org": "Cảnh sát Phản ứng nhanh", "type": "VN_SHORTCODE", "description": "Tổng đài tiếp nhận tin báo an ninh trật tự khẩn cấp của Bộ Công an"},
    "114": {"org": "Cứu hỏa & Cứu nạn cứu hộ", "type": "VN_SHORTCODE", "description": "Tổng đài báo cháy và cứu nạn khẩn cấp của Cảnh sát PCCC"},
    "115": {"org": "Cấp cứu Y tế", "type": "VN_SHORTCODE", "description": "Tổng đài gọi xe cấp cứu y tế công cộng 24/7"},
    "1022": {"org": "Cổng Dịch vụ công 1022", "type": "VN_SHORTCODE", "description": "Tổng đài tiếp nhận thông tin phản ánh về đời sống dân sinh và dịch vụ công"},
    "156": {"org": "Tổng đài Tiếp nhận phản ánh Cuộc gọi/Tin nhắn rác", "type": "VN_SHORTCODE", "description": "Tổng đài chính thức của Bộ Thông tin & Truyền thông"},
    "5656": {"org": "Tổng đài Danh sách không quảng cáo (DNC)", "type": "VN_SHORTCODE", "description": "Đầu số đăng ký từ chối cuộc gọi rác của Cục An toàn thông tin"},

    # Ngân hàng thương mại lớn tại Việt Nam
    "1900545413": {"org": "Vietcombank", "type": "VN_HOTLINE", "description": "Trung tâm Hỗ trợ Khách hàng 24/7 chính thức của Ngân hàng Vietcombank"},
    "02438243524": {"org": "Vietcombank (Quốc tế)", "type": "VN_LANDLINE", "description": "Hotline hỗ trợ khách hàng quốc tế của Vietcombank"},
    "1900545415": {"org": "VietinBank", "type": "VN_HOTLINE", "description": "Trung tâm Chăm sóc Khách hàng chính thức của Ngân hàng VietinBank"},
    "19009247": {"org": "BIDV", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của Ngân hàng BIDV"},
    "02422200588": {"org": "BIDV (Hà Nội)", "type": "VN_LANDLINE", "description": "Đầu số hỗ trợ chính thức của Ngân hàng BIDV"},
    "1800585885": {"org": "Agribank", "type": "VN_HOTLINE", "description": "Tổng đài Dịch vụ Khách hàng chính thức của Ngân hàng Nông nghiệp Agribank"},
    "1900585832": {"org": "Techcombank", "type": "VN_HOTLINE", "description": "Dịch vụ Khách hàng chính thức 24/7 của Ngân hàng Techcombank"},
    "1800588822": {"org": "MBBank", "type": "VN_HOTLINE", "description": "Trung tâm Dịch vụ Khách hàng chính thức của Ngân hàng Quân Đội (MB)"},
    "1900588822": {"org": "MBBank", "type": "VN_HOTLINE", "description": "Trung tâm Dịch vụ Khách hàng chính thức của Ngân hàng Quân Đội (MB)"},
    "1900545436": {"org": "ACB", "type": "VN_HOTLINE", "description": "Trung tâm Dịch vụ Khách hàng 24/7 chính thức của Ngân hàng ACB"},
    "1900545426": {"org": "Sacombank", "type": "VN_HOTLINE", "description": "Trung tâm Dịch vụ Khách hàng chính thức của Ngân hàng Sacombank"},
    "19006060": {"org": "VPBank", "type": "VN_HOTLINE", "description": "Tổng đài Dịch vụ Khách hàng 24/7 chính thức của Ngân hàng VPBank"},
    "1900233448": {"org": "TPBank", "type": "VN_HOTLINE", "description": "Trung tâm Dịch vụ Khách hàng chính thức của Ngân hàng Tiên Phong (TPBank)"},
    "19006036": {"org": "TPBank", "type": "VN_HOTLINE", "description": "Đầu số hỗ trợ khách hàng của Ngân hàng TPBank"},
    "18008195": {"org": "VIB", "type": "VN_HOTLINE", "description": "Dịch vụ Khách hàng chính thức của Ngân hàng Quốc Tế VIB"},
    "19006083": {"org": "HDBank", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng 24/7 chính thức của Ngân hàng HDBank"},
    "1900555577": {"org": "SHB", "type": "VN_HOTLINE", "description": "Trung tâm Chăm sóc Khách hàng chính thức của Ngân hàng SHB"},
    "1900555590": {"org": "SeABank", "type": "VN_HOTLINE", "description": "Tổng đài Dịch vụ Khách hàng chính thức của Ngân hàng SeABank"},
    "18006260": {"org": "OCB", "type": "VN_HOTLINE", "description": "Tổng đài Dịch vụ Khách hàng chính thức của Ngân hàng Phương Đông (OCB)"},
    "1900545433": {"org": "MSB", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của Ngân hàng Hàng Hải (MSB)"},
    "1800577758": {"org": "LPBank", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của Ngân hàng Lộc Phát Việt Nam"},

    # Nhà mạng viễn thông & Internet
    "18008098": {"org": "Viettel Telecom", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng Di động chính thức của Viettel (Miễn phí)"},
    "19008198": {"org": "Viettel Telecom", "type": "VN_HOTLINE", "description": "Đầu số hỗ trợ dịch vụ chuyên sâu của Viettel"},
    "18008119": {"org": "Viettel Internet", "type": "VN_HOTLINE", "description": "Tổng đài báo hỏng và hỗ trợ kỹ thuật Cáp quang/Truyền hình Viettel"},
    "18001091": {"org": "VinaPhone", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của mạng di động VinaPhone"},
    "18001166": {"org": "VNPT Internet", "type": "VN_HOTLINE", "description": "Tổng đài hỗ trợ kỹ thuật và báo hỏng mạng Internet VNPT"},
    "18001090": {"org": "MobiFone", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của mạng di động MobiFone"},
    "9090": {"org": "MobiFone (Nội mạng)", "type": "VN_SHORTCODE", "description": "Tổng đài giải đáp thắc mắc nội mạng MobiFone"},
    "789": {"org": "Vietnamobile", "type": "VN_SHORTCODE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của mạng di động Vietnamobile"},

    # Ví điện tử, Sàn TMĐT & Dịch vụ phổ biến
    "1900545441": {"org": "Ví điện tử MoMo", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của Ví MoMo"},
    "1900561558": {"org": "Zalo / ZaloPay", "type": "VN_HOTLINE", "description": "Tổng đài Hỗ trợ Khách hàng chính thức của Zalo & ZaloPay"},
    "19001221": {"org": "Shopee Việt Nam", "type": "VN_HOTLINE", "description": "Trung tâm Hỗ trợ Khách hàng chính thức của Sàn TMĐT Shopee"},
    "19006035": {"org": "Tiki Việt Nam", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của Tiki"},
    "19006501": {"org": "Lazada Việt Nam", "type": "VN_HOTLINE", "description": "Trung tâm Hỗ trợ Khách hàng chính thức của Sàn TMĐT Lazada"},
    "1900545411": {"org": "Viettel Post", "type": "VN_HOTLINE", "description": "Tổng đài Hỗ trợ Khách hàng chuyển phát Viettel Post"},
    "19001201": {"org": "VNPost (Bưu điện VN)", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của Tổng công ty Bưu điện Việt Nam"},
    "19001203": {"org": "Giao Hàng Nhanh (GHN)", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng chính thức của GHN Express"},
    "19006092": {"org": "Giao Hàng Tiết Kiệm (GHTK)", "type": "VN_HOTLINE", "description": "Tổng đài Hỗ trợ Khách hàng chính thức của GHTK"},
    "18001060": {"org": "Thế Giới Di Động", "type": "VN_HOTLINE", "description": "Tổng đài Khiếu nại và Chăm sóc Khách hàng Thế Giới Di Động"},
    "19001060": {"org": "Thế Giới Di Động", "type": "VN_HOTLINE", "description": "Tổng đài Tư vấn bán hàng chính thức của Thế Giới Di Động"},
    "18001061": {"org": "Điện Máy Xanh", "type": "VN_HOTLINE", "description": "Tổng đài Hỗ trợ Kỹ thuật và Bảo hành Điện Máy Xanh"},
    "18002097": {"org": "FPT Shop", "type": "VN_HOTLINE", "description": "Tổng đài Tư vấn & Chăm sóc Khách hàng FPT Shop"},
    "19006600": {"org": "FPT Telecom", "type": "VN_HOTLINE", "description": "Tổng đài Chăm sóc Khách hàng và Hỗ trợ Kỹ thuật FPT Telecom"},
}

# Danh bạ dải số cố định ảo VoIP / SIP Trunk có rủi ro lừa đảo cao nhất tại Việt Nam
# (prefix, risk_score, service_name, warning_detail)
_VOIP_SCAM_PREFIXES: List[Tuple[str, float, str, str]] = [
    (
        "024999", 85.0, "VoIP Gmobile (Hà Nội)",
        "Đầu số cố định ảo 024 999x (Gmobile VoIP) — Đây là dải số bị phản ánh lừa đảo nhiều nhất Việt Nam. "
        "Chiêu trò phổ biến: Giả danh Công an dọa lệnh bắt/rửa tiền, Tòa án báo phạt nguội giao thông, nháy máy ép gọi lại trừ cước VAS."
    ),
    (
        "028999", 85.0, "VoIP Gmobile (TP.HCM)",
        "Đầu số cố định ảo 028 999x (Gmobile VoIP) — Dải số có tỷ lệ lừa đảo và cuộc gọi rác cực cao. "
        "Chiêu trò phổ biến: Nháy máy liên tục, giả danh công ty tài chính tín dụng đen, lừa đảo tuyển dụng việc làm online."
    ),
    (
        "024888", 85.0, "VoIP Digitel (Hà Nội)",
        "Đầu số cố định ảo 024 888x (Digitel VoIP) — Chuyên bị lợi dụng để mạo danh nhân viên điện lực/nhà mạng dọa khóa dịch vụ đòi nợ cước, hoặc giả mạo ngân hàng lừa OTP."
    ),
    (
        "028888", 85.0, "VoIP Digitel (TP.HCM)",
        "Đầu số cố định ảo 028 888x (Digitel VoIP) — Chuyên bị lợi dụng để giả danh cơ quan chức năng, giả shipper yêu cầu chuyển khoản đơn hàng COD giả mạo."
    ),
    (
        "024445", 80.0, "VoIP CMC Telecom (Hà Nội)",
        "Đầu số cố định ảo 024 445x (CMC VoIP) — Thường xuyên ghi nhận phản ánh mạo danh nhân viên ngân hàng/sàn thương mại điện tử thông báo nâng hạn mức tín dụng hoặc nhận quà để chiếm đoạt OTP."
    ),
    (
        "028445", 80.0, "VoIP CMC Telecom (TP.HCM)",
        "Đầu số cố định ảo 028 445x (CMC VoIP) — Thường bị phản ánh liên quan đến cuộc gọi mạo danh tài chính và lừa đảo thẻ tín dụng."
    ),
    (
        "028730", 80.0, "SIP Trunk FPT (TP.HCM)",
        "Đầu số 028 730x (FPT SIP Trunk) — Thường xuyên bị các hệ thống Robocall tự động phát ghi âm sẵn mồi chài đầu tư chứng khoán quốc tế, tiền ảo, sàn Forex cờ bạc hoặc cho vay nặng lãi."
    ),
    (
        "024730", 80.0, "SIP Trunk FPT (Hà Nội)",
        "Đầu số 024 730x (FPT SIP Trunk) — Ghi nhận nhiều cuộc gọi tự động Robocall quấy rối, quảng cáo khóa học hoặc dụ dỗ tham gia hội nhóm đầu tư tài chính."
    ),
    (
        "028710", 75.0, "SIP Trunk CMC (TP.HCM)",
        "Đầu số 028 710x (CMC SIP Trunk) — Thuộc dải đầu số ảo thường bị các công ty tài chính 'ma' hoặc telesale rác gọi làm phiền và dẫn dụ vay tiền."
    ),
    (
        "024710", 75.0, "SIP Trunk CMC (Hà Nội)",
        "Đầu số 024 710x (CMC SIP Trunk) — Thường bị phản ánh là cuộc gọi rác và mồi chài tài chính không rõ nguồn gốc."
    ),
    (
        "028220", 75.0, "VoIP Viettel (TP.HCM)",
        "Đầu số cố định ảo 028 220x — Có nhiều phản ánh mạo danh viễn thông và cơ quan chức năng."
    ),
    (
        "024220", 75.0, "VoIP Viettel (Hà Nội)",
        "Đầu số cố định ảo 024 220x — Có nhiều phản ánh mạo danh cơ quan chức năng đe dọa người dân."
    ),
    (
        "024567", 75.0, "VoIP Dịch vụ (Hà Nội)",
        "Đầu số 024 567x — Dải số thường bị kẻ gian thuê làm đầu số ảo phát tán cuộc gọi lừa đảo."
    ),
    (
        "028567", 75.0, "VoIP Dịch vụ (TP.HCM)",
        "Đầu số 028 567x — Dải số thường bị kẻ gian thuê làm đầu số ảo phát tán cuộc gọi lừa đảo."
    ),
]


def _strip_non_digits(raw: str) -> str:
    cleaned = re.sub(r'[Oo]', '0', raw)
    return re.sub(r"\D", "", cleaned)


def extract_phone_candidates(text: str) -> list[str]:
    """
    Tìm tất cả chuỗi giống số điện thoại trong text, trả về danh sách các dạng số thuần.
    """
    if not text or not text.strip():
        return []

    candidates: list[str] = []
    seen: set[str] = set()

    for match in _PHONE_CANDIDATE_RE.finditer(text):
        digits = _strip_non_digits(match.group())
        if not digits or len(digits) < 7:
            continue

        forms = {digits}
        # Số di động VN dạng quốc tế: 84 + 9 số -> 0 + 9 số
        if digits.startswith("84") and len(digits) == 11:
            forms.add("0" + digits[2:])
        # Gõ nhầm/dư 0 sau mã quốc gia: 0084 + 9 số
        if digits.startswith("0084") and len(digits) == 13:
            forms.add("0" + digits[4:])

        for form in forms:
            if form not in seen:
                seen.add(form)
                candidates.append(form)

    return candidates


def _analyze_telecom_heuristics(digits: str) -> Tuple[float, List[str], str]:
    """
    Phân tích Telecom Intelligence chuyên sâu:
    - Nhận diện các dải VoIP / SIP Trunk độc hại
    - Nhận diện cấu trúc số đẹp lặp dị thường (tứ quý, ngũ quý, autodialer)
    - Nhận diện số cố định 024 / 028
    Trả về (risk_score, notes[], detected_service).
    """
    notes: List[str] = []
    max_score = 0.0
    detected_service = "UNKNOWN"

    core = digits[1:] if digits.startswith("0") else digits

    # 1. KIỂM TRA DẢI CỐ ĐỊNH ẢO VOIP / SIP TRUNK RỦI RO CAO (024/028)
    matched_voip = False
    for prefix, score, s_name, warning in _VOIP_SCAM_PREFIXES:
        if digits.startswith(prefix):
            max_score = max(max_score, score)
            detected_service = s_name
            notes.append(warning)
            matched_voip = True
            break

    # 2. KIỂM TRA ĐẶC ĐIỂM SỐ CỐ ĐỊNH 024 / 028 NÓI CHUNG
    if (digits.startswith("024") or digits.startswith("028")) and len(digits) == 11:
        # Nếu chưa khớp dải VoIP cụ thể ở trên, kiểm tra xem có đuôi lặp số đẹp không
        has_repeating_suffix = bool(re.search(r'(\d)\1{3,}$', digits)) # đuôi tứ quý trở lên
        if has_repeating_suffix:
            max_score = max(max_score, 85.0)
            notes.append(
                f"Số cố định ({digits[:3]}) có đuôi chữ số lặp liên tiếp — "
                "Đây là dạng số 'đẹp' thường được các tổ chức lừa đảo mua qua dịch vụ tổng đài ảo "
                "nhằm tạo vỏ bọc uy tín để mạo danh cơ quan công quyền hoặc tổ chức tài chính."
            )
        elif not matched_voip:
            # Là số cố định 024 hoặc 028 thông thường: NÂNG LÊN MỨC CẢNH BÁO CAO (MEDIUM 55)
            max_score = max(max_score, 55.0)
            city = "Hà Nội (024)" if digits.startswith("024") else "TP.HCM (028)"
            notes.append(
                f"Đầu số cố định khu vực {city} — CẢNH GIÁC CAO: Cơ quan Công an, Tòa án, Viện kiểm sát "
                "và Ngân hàng KHÔNG BAO GIỜ làm việc, điều tra hoặc yêu cầu chuyển tiền/đọc mã OTP qua điện thoại. "
                "Nếu cuộc gọi thông báo nợ cước, dọa phạt nguội giao thông hoặc yêu cầu xác minh tài khoản, hãy CÚP MÁY NGAY."
            )

    # 3. KIỂM TRA SỐ DI ĐỘNG CÓ MẪU SỐ LẶP DỊ THƯỜNG (SIM RÁC / ROBOCALL)
    elif _VN_MOBILE_RE.match(digits):
        # Tứ quý / ngũ quý hoặc chuỗi số 0 tận cùng
        if re.search(r'0{4,}$', digits):
            max_score = max(max_score, 75.0)
            notes.append(
                f"Số di động kết thúc bằng chuỗi nhiều số 0 ({digits}) — "
                "Dấu hiệu số ảo tạo bởi phần mềm tổng đài tự động (Robocall) phát tán cuộc gọi rác, "
                "lừa đảo nâng cấp eSIM hoặc mạo danh tư vấn đầu tư."
            )
        elif re.search(r'(\d)\1{4,}', core): # ngũ quý
            max_score = max(max_score, 75.0)
            notes.append(
                f"Số di động có chuỗi chữ số lặp bất thường ({digits}) — "
                "Thường là SIM rác số đẹp được kẻ gian mua để thực hiện cuộc gọi lừa đảo theo kịch bản "
                "(giả shipper đơn COD ảo, lừa tuyển dụng CTV việc nhẹ lương cao)."
            )

    # 4. KIỂM TRA ĐẦU SỐ DỊCH VỤ 1900 (VAS CƯỚC CAO)
    elif _VN_HOTLINE_RE.match(digits):
        if digits.startswith("1900"):
            max_score = max(max_score, 65.0)
            notes.append(
                f"Đầu số 1900 là số dịch vụ viễn thông giá trị gia tăng (cước từ 1.000đ - 15.000đ/phút). "
                "Cảnh giác chiêu trò nháy máy 1-2 giây rồi dập máy để lừa nạn nhân gọi lại nhằm trừ cước viễn thông. "
                "Tuyệt đối KHÔNG gọi lại nếu không rõ danh tính."
            )

    return max_score, notes, detected_service


def analyze_sender_risk(sender: str) -> Dict[str, Any]:
    """
    Phân tích danh tính người gửi: Brandname, Đầu số nội địa (Mobile/Landline/Hotline),
    hoặc Đầu số quốc tế rủi ro cao. Kết hợp Telecom Intelligence chuyên sâu.
    """
    if not sender or not sender.strip():
        return {"sender": "", "type": "UNKNOWN", "risk_score": 0.0, "notes": []}

    sender_clean = sender.strip()
    notes: List[str] = []
    risk_score = 0.0
    sender_type = "UNKNOWN"

    # 1. Kiểm tra Brandname (chứa ký tự chữ cái và không bắt đầu bằng +)
    if re.search(r'[A-Za-z]', sender_clean) and not sender_clean.startswith('+'):
        sender_type = "BRANDNAME"
        return {
            "sender": sender_clean,
            "type": sender_type,
            "service": "BRANDNAME",
            "risk_score": 0.0,
            "notes": ["Tin nhắn từ Brandname chính thức (tên thương hiệu định danh)"],
        }

    # 2. Đầu số quốc tế nguy hiểm (Wangiri / vệ tinh / VoIP lừa đảo xuyên biên giới)
    for prefix in _HIGH_RISK_INTL_PREFIXES:
        if sender_clean.startswith(prefix):
            sender_type = "HIGH_RISK_INTERNATIONAL"
            risk_score = 90.0
            notes.append(
                f"ĐẦU SỐ QUỐC TẾ CẢNH BÁO NGUY HIỂM ({prefix}) — Các đầu số này liên quan trực tiếp đến "
                "chiêu trò nháy máy quốc tế (Wangiri scam), trừ cước vệ tinh cực đắt hoặc đe dọa tống tiền xuyên biên giới. "
                "TUYỆT ĐỐI KHÔNG bắt máy và KHÔNG gọi lại dưới mọi hình thức."
            )
            return {
                "sender": sender_clean,
                "type": sender_type,
                "service": "HIGH_RISK_INTERNATIONAL",
                "risk_score": risk_score,
                "notes": notes,
            }

    digits = _strip_non_digits(sender_clean)
    if digits.startswith("84") and len(digits) == 11:
        digits = "0" + digits[2:]
    if digits.startswith("0084") and len(digits) == 13:
        digits = "0" + digits[4:]

    # 2.5 Kiểm tra Danh bạ Hotline chính thức đã được xác minh (Whitelist 0% False Positive)
    if digits in VERIFIED_OFFICIAL_HOTLINES:
        info = VERIFIED_OFFICIAL_HOTLINES[digits]
        return {
            "sender": sender_clean,
            "normalized": digits,
            "type": info["type"],
            "service": info["org"],
            "risk_score": 0.0,
            "is_verified_official": True,
            "notes": [f"SỐ TỔNG ĐÀI CHÍNH THỨC ĐÃ XÁC MINH: {info['org']} — {info['description']}."],
        }

    # 3. Phân loại loại số viễn thông
    if _VN_MOBILE_RE.match(digits):
        sender_type = "VN_MOBILE"
    elif _VN_LANDLINE_RE.match(digits):
        sender_type = "VN_LANDLINE"
    elif _VN_HOTLINE_RE.match(digits):
        sender_type = "VN_HOTLINE"
    elif _VN_SHORTCODE_RE.match(digits):
        sender_type = "VN_SHORTCODE"

    # 4. Phân tích Telecom Intelligence chuyên sâu
    telecom_score, telecom_notes, detected_service = _analyze_telecom_heuristics(digits)
    risk_score = max(risk_score, telecom_score)
    notes.extend(telecom_notes)

    return {
        "sender": sender_clean,
        "normalized": digits,
        "type": sender_type,
        "service": detected_service,
        "risk_score": risk_score,
        "notes": notes,
    }
