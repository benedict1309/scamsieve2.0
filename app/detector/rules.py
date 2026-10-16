"""
Dinh nghia cac rule phat hien dau hieu lua dao.
Moi ham check_* nhan vao noi dung goc, tra ve list[RuleMatch] (co the rong).

Hien tai da co: nhom "gia danh co quan/to chuc" (4 kich ban con).
Cac nhom khac (OTP, hoi thuc chuyen tien, URL dang ngo, trung thuong,
cai app la...) se duoc bo sung o cac lan cap nhat sau, moi nhom 1 ham
check_* rieng, roi gop lai trong detect_all().
"""
from app.detector.base import RuleMatch
from app.detector.text_utils import normalize_text
from app.detector.patterns.vi_keywords import (
    POLICE_COURT_KEYWORDS,
    BANK_KEYWORDS,
    ECOMMERCE_KEYWORDS,
    UTILITY_KEYWORDS,
    IDENTITY_CLAIM_MARKERS,
    CUSTOMER_TARGETING_MARKERS,
    OTP_KEYWORDS,
    OTP_SHARE_REQUEST_MARKERS,
    URGENT_TRANSFER_KEYWORDS,
    PRIZE_MENTION_KEYWORDS,
    PRIZE_CLAIM_ACTION_MARKERS,
    APK_FILE_KEYWORDS,
    APP_INSTALL_KEYWORDS,
    UNOFFICIAL_SOURCE_MARKERS,
    GAMBLING_KEYWORDS,
    JOB_SCAM_INTENT_MARKERS,
    JOB_SCAM_BAIT_MARKERS,
    JOB_SCAM_CONTACT_MARKERS,
)
from app.detector.patterns.url_patterns import SUSPICIOUS_TLDS
import re

_ALL_MARKERS = IDENTITY_CLAIM_MARKERS + CUSTOMER_TARGETING_MARKERS

# (rule_id, ten hien thi, danh sach tu khoa, diem, giai thich)
_IMPERSONATION_GROUPS = [
    (
        "imp_police_court",
        "Giả danh công an / tòa án / viện kiểm sát",
        POLICE_COURT_KEYWORDS,
        25,
        "Nội dung nhắc đến công an, tòa án, viện kiểm sát hoặc lệnh bắt/triệu tập — "
        "đây là chiêu phổ biến để tạo áp lực tâm lý, khiến nạn nhân hoảng sợ và làm theo yêu cầu.",
    ),
    (
        "imp_bank",
        "Giả danh ngân hàng / tổng đài CSKH",
        BANK_KEYWORDS,
        20,
        "Nội dung nhắc đến ngân hàng hoặc tổng đài chăm sóc khách hàng — cần cảnh giác vì "
        "kẻ gian thường giả danh ngân hàng để yêu cầu xác minh tài khoản hoặc cung cấp OTP.",
    ),
    (
        "imp_ecommerce",
        "Giả danh sàn thương mại điện tử / đơn vị giao hàng",
        ECOMMERCE_KEYWORDS,
        18,
        "Nội dung nhắc đến sàn thương mại điện tử hoặc đơn vị giao hàng — kẻ gian hay giả "
        "danh để báo đơn hàng lỗi/hoàn tiền nhằm dụ bấm vào link giả hoặc cung cấp thông tin cá nhân.",
    ),
    (
        "imp_utility",
        "Giả danh cơ quan thuế / BHXH / điện lực",
        UTILITY_KEYWORDS,
        20,
        "Nội dung nhắc đến cơ quan thuế, bảo hiểm xã hội hoặc điện lực — kẻ gian thường giả "
        "danh các đơn vị này để dọa cắt dịch vụ hoặc phạt tiền nhằm ép nạn nhân chuyển khoản gấp.",
    ),
]


def _extract_snippet(original: str, normalized: str, keyword: str, context: int = 25) -> str:
    """Lay doan van ban goc xung quanh vi tri khop, de nguoi dung de doi chieu."""
    idx = normalized.find(keyword)
    if idx == -1:
        return ""
    start = max(0, idx - context)
    end = min(len(original), idx + len(keyword) + context)
    snippet = original[start:end].strip().replace("\n", " ")
    if start > 0:
        snippet = "..." + snippet
    if end < len(original):
        snippet = snippet + "..."
    return snippet


def check_impersonation(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu gia danh co quan/to chuc (4 kich ban).

    Chi tinh la khop khi tu khoa to chuc DI KEM voi dau hieu "tu xung dai
    dien" hoac "huong thang toi ban/tai khoan cua ban" (xem CUSTOMER_TARGETING_MARKERS/
    IDENTITY_CLAIM_MARKERS) - tranh bao nham cac tin PSA canh bao lua dao hoac
    thong bao hanh chinh chi nhac ten to chuc mot cach thong thuong.
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)

    if not any(marker in normalized for marker in _ALL_MARKERS):
        return []

    matches: list[RuleMatch] = []

    for rule_id, category, keywords, score, explanation in _IMPERSONATION_GROUPS:
        for kw in keywords:
            if kw in normalized:
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        category=category,
                        snippet=_extract_snippet(text, normalized, kw),
                        score=score,
                        explanation=explanation,
                    )
                )
                break  # chi lay 1 lan khop dau tien moi rule, tranh cong diem lap nhieu lan
    return matches


_OTP_EXPLANATION = (
    "Nội dung nhắc đến mã OTP/mã xác thực VÀ có yêu cầu đọc/cung cấp mã đó cho người khác — "
    "đây là dấu hiệu rất nguy hiểm, vì các tổ chức thật (ngân hàng, ví điện tử...) không bao "
    "giờ yêu cầu khách hàng đọc hoặc gửi mã OTP qua điện thoại/tin nhắn. Tuyệt đối không cung "
    "cấp mã OTP cho bất kỳ ai."
)


def check_otp(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu yeu cau doc/cung cap ma OTP.

    Chi tinh la khop khi VUA co tu khoa OTP/ma xac thuc, VUA co cum tu the
    hien ai do dang yeu cau doc/cung cap ma (xem OTP_SHARE_REQUEST_MARKERS).
    Chi rieng viec nhac den "OTP" khong du de bao (tin nhan that tu ngan
    hang cung chua "Ma OTP: 123456" nhung khong yeu cau ai doc/gui no).
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)

    if not any(kw in normalized for kw in OTP_KEYWORDS):
        return []
    if not any(marker in normalized for marker in OTP_SHARE_REQUEST_MARKERS):
        return []

    for kw in OTP_KEYWORDS:
        if kw in normalized:
            return [
                RuleMatch(
                    rule_id="otp_share_request",
                    category="Yêu cầu đọc/cung cấp mã OTP",
                    snippet=_extract_snippet(text, normalized, kw),
                    score=30,
                    explanation=_OTP_EXPLANATION,
                )
            ]
    return []  # khong the xay ra (da check any() o tren) nhung giu cho chac chan


_URGENT_TRANSFER_EXPLANATION = (
    "Nội dung có cụm từ hối thúc chuyển tiền gấp (giả danh người thân/bạn bè cần tiền gấp, "
    "hoặc dọa phong tỏa tài khoản...) — kẻ gian thường tạo áp lực thời gian để nạn nhân "
    "không kịp suy nghĩ, kiểm tra lại trước khi chuyển khoản."
)


def check_urgent_transfer(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu hoi thuc chuyen tien gap (vd gia danh nguoi than muon
    tien gap, doa phong toa tai khoan de ep chuyen tien...).
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)

    for kw in URGENT_TRANSFER_KEYWORDS:
        if kw in normalized:
            return [
                RuleMatch(
                    rule_id="urgent_transfer",
                    category="Hối thúc chuyển tiền gấp",
                    snippet=_extract_snippet(text, normalized, kw),
                    score=22,
                    explanation=_URGENT_TRANSFER_EXPLANATION,
                )
            ]
    return []


from app.detector.patterns.url_patterns import (
    SUSPICIOUS_TLDS,
    PHISHING_DOMAIN_KEYWORDS,
    PROTECTED_BRANDS,
    url_extractor,
    extract_emails,
    DISPOSABLE_EMAIL_DOMAINS,
    FREE_EMAIL_DOMAINS,
)

_SUSPICIOUS_URL_EXPLANATION = (
    "Nội dung chứa đường link dùng đuôi tên miền lạ ({tld}) — đây là loại đuôi rẻ, "
    "dễ đăng ký nặc danh mà kẻ gian hay dùng để tạo website giả mạo ngân hàng/cơ "
    "quan nhà nước/sàn thương mại điện tử thật. Tuyệt đối không bấm vào link lạ "
    "hoặc nhập thông tin cá nhân, mật khẩu, mã OTP trên các trang này."
)

_PHISHING_DOMAIN_EXPLANATION = (
    "Đường link hoặc tên miền '{netloc}' chứa từ khóa mồi chài lừa đảo ('{keyword}') — "
    "đây là dấu hiệu website giả mạo được lập ra nhằm chiếm đoạt tài sản hoặc thông tin cá nhân."
)


def check_suspicious_url(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu link dang ngo:
    1. Giả mạo thương hiệu / Typosquatting (vietcornbank, sh0pee, vietcombank-login...).
    2. Ten mien co TLD la/gia re (top, vip, cc...).
    3. Ten mien chua tu khoa lua dao moi chai (nhanqua, nhanthuong, smartotp, ebank...).
    """
    if not text or not text.strip():
        return []

    urls = url_extractor.extract_urls(text)
    if not urls:
        return []

    matches: list[RuleMatch] = []
    for url in urls:
        features = url_extractor.extract_features(url)
        netloc = features.get("netloc", "")
        tld = features.get("tld", "")

        # 1. Phát hiện giả mạo thương hiệu (Subdomain Deception, Combosquatting, Typosquatting)
        # 1. Phát hiện Giả mạo Thương hiệu, Homoglyph, Combosquatting, Subdomain Deception
        if features.get("is_brand_impersonation"):
            imp_info = features.get("impersonation_info", {})
            imp_type = imp_info.get("type", "BRAND_HIJACK")
            detail = imp_info.get("detail", "")
            brand = imp_info.get("brand", "")
            if imp_type == "HOMOGLYPH_ATTACK":
                category = "Tấn công ký tự thị giác (IDN Homoglyph Attack)"
                score_val = 80
            elif imp_type == "HOMOGLYPH_ANOMALY":
                category = "Ký tự quốc tế ngụy trang bất thường"
                score_val = 60
            elif imp_type == "TUNNEL_HOSTING_ABUSE":
                category = "Lạm dụng hạ tầng Cloud/Tunnel lưu trữ web giả mạo"
                score_val = 75
            elif imp_type == "SUBDOMAIN_DECEPTION":
                category = "Giả mạo thương hiệu tinh vi (Subdomain Deception)"
                score_val = 75
            elif imp_type == "COMBOSQUATTING":
                category = "Mạo danh thương hiệu kết hợp từ khóa (Combosquatting)"
                score_val = 70
            elif imp_type == "TYPOSQUATTING":
                category = "Giả mạo thương hiệu (Typosquatting)"
                score_val = 65
            else:
                category = "Mạo danh thương hiệu trong tên miền"
                score_val = 60

            matches.append(
                RuleMatch(
                    rule_id="brand_impersonation_url",
                    category=category,
                    snippet=url,
                    score=score_val,
                    explanation=detail + " Đây là thủ đoạn lừa đảo nguy hiểm nhằm đánh cắp tài khoản ngân hàng hoặc dữ liệu cá nhân. Tuyệt đối không truy cập liên kết này.",
                )
            )

        # 1b. Phát hiện Credential Spoofing qua ký tự '@'
        if features.get("has_credential_spoofing"):
            spoofed_cred = features.get("spoofed_credential", "")
            actual_h = features.get("actual_host", "")
            matches.append(
                RuleMatch(
                    rule_id="credential_spoofing_url",
                    category="Ngụy trang tiền tố URL lừa đảo (Credential Spoofing)",
                    snippet=url,
                    score=75,
                    explanation=(
                        f"Đường dẫn sử dụng cú pháp '@' giả mạo: Hiển thị tiền tố '{spoofed_cred}' nhằm đánh lừa người dùng, "
                        f"nhưng thực chất trình duyệt sẽ kết nối tới máy chủ độc hại '{actual_h}'. Đây là kỹ thuật lừa đảo phishing tinh vi."
                    ),
                )
            )

        # 1c. Phát hiện Bẫy chuyển hướng mở (Open Redirect Abuse)
        if features.get("is_open_redirect_abuse"):
            redir_target = features.get("redirect_target_url", "")
            matches.append(
                RuleMatch(
                    rule_id="open_redirect_abuse",
                    category="Lợi dụng dịch vụ uy tín để chuyển hướng độc hại (Open Redirect)",
                    snippet=f"{url} -> {redir_target}",
                    score=70,
                    explanation=(
                        f"Liên kết lợi dụng cổng chuyển hướng của một dịch vụ trung gian để che giấu đích đến độc hại: '{redir_target}'. "
                        "Mặc dù tên miền hiển thị có vẻ quen thuộc, người dùng khi bấm vào sẽ bị chuyển hướng ngay sang trang web lừa đảo."
                    ),
                )
            )

        # 1d. Phát hiện Địa chỉ IP dạng che giấu (Hex / DWORD IP Obfuscation)
        if features.get("is_obfuscated_ip"):
            matches.append(
                RuleMatch(
                    rule_id="obfuscated_ip_address",
                    category="Địa chỉ IP ngụy trang (Hex/DWORD Obfuscation)",
                    snippet=url,
                    score=75,
                    explanation=(
                        f"Địa chỉ IP '{netloc}' được mã hóa dưới dạng số Hex hoặc số nguyên DWORD nhằm qua mặt các bộ lọc an ninh mạng. "
                        "Kỹ thuật này thường được tin tặc sử dụng để trốn tránh việc nhận diện tên miền máy chủ độc hại."
                    ),
                )
            )

        # 2. Phát hiện tên miền sinh ngẫu nhiên (DGA / Gibberish Domain)
        if features.get("is_dga"):
            dga_info = features.get("dga_info", {})
            ent = dga_info.get("entropy", 0.0)
            reasons_str = "; ".join(dga_info.get("reasons", []))
            matches.append(
                RuleMatch(
                    rule_id="dga_random_domain",
                    category="Tên miền sinh ngẫu nhiên (DGA / Botnet)",
                    snippet=url,
                    score=50,
                    explanation=(
                        f"Tên miền '{netloc}' có dấu hiệu sinh tự động bằng thuật toán DGA (Entropy: {ent}). "
                        f"{reasons_str}. Kỹ thuật này thường được các đối tượng lừa đảo, cờ bạc lậu dùng để tạo hàng loạt website rác né tránh danh sách đen."
                    ),
                )
            )

        # 3. Kiem tra TLD rui ro (khong canh bao neu da duoc xac thuc chinh thuc)
        if tld in SUSPICIOUS_TLDS and not features.get("is_authorized_brand"):
            matches.append(
                RuleMatch(
                    rule_id="suspicious_url",
                    category="Đường link đáng ngờ",
                    snippet=url,
                    score=25,
                    explanation=_SUSPICIOUS_URL_EXPLANATION.format(tld=tld),
                )
            )

        # 3. Kiem tra tu khoa lua dao / co bac trong ten mien
        matched_kw = None
        for kw in PHISHING_DOMAIN_KEYWORDS:
            if kw in netloc:
                matched_kw = kw
                break
        if not matched_kw:
            bet_match = re.search(r'(?:[a-z0-9]*bet\d{2,4}|[a-z0-9]*win\d{2,4}|w88|m88|fun88|fb88|go88)', netloc)
            if bet_match:
                matched_kw = bet_match.group(0)

        if matched_kw:
            matches.append(
                RuleMatch(
                    rule_id="phishing_domain_keyword",
                    category="Tên miền mồi chài lừa đảo / cờ bạc",
                    snippet=url,
                    score=35,
                    explanation=_PHISHING_DOMAIN_EXPLANATION.format(netloc=netloc, keyword=matched_kw),
                )
            )

        # 4. Kiem tra Link rut gon chuyen huong nguy trang
        if features.get("is_redirected"):
            resolved = features.get("resolved_url", "")
            matches.append(
                RuleMatch(
                    rule_id="shortened_url_redirect",
                    category="Liên kết rút gọn ngụy trang",
                    snippet=f"{url} -> {resolved}",
                    score=30,
                    explanation=(
                        f"Đường link rút gọn '{url}' tự động chuyển hướng người dùng tới địa chỉ: '{resolved}'. "
                        "Kẻ gian thường sử dụng các dịch vụ rút gọn link để che giấu tên miền độc hại và vượt qua bộ lọc an ninh. "
                        "Hãy kiểm tra thật kỹ tên miền đích trước khi truy cập."
                    ),
                )
            )

        # 5. Kiem tra Tuoi ten mien (Domain Age / RDAP Intelligence)
        if features.get("is_new_disposable_domain"):
            reg_dom = features.get("registered_domain", "")
            age = features.get("domain_age_days", 0)
            matches.append(
                RuleMatch(
                    rule_id="disposable_phishing_domain_age",
                    category="Tên miền mới đăng ký nguy cơ cao (< 30 ngày)",
                    snippet=f"{reg_dom} ({age} ngày tuổi)",
                    score=40,
                    explanation=(
                        f"Tên miền '{reg_dom}' chỉ mới được đăng ký cách đây khoảng {age} ngày. "
                        "Hơn 90% các trang web lừa đảo trực tuyến sử dụng tên miền mới đăng ký để qua mặt các bộ lọc an ninh. "
                        "Cần hết sức cẩn trọng và không cung cấp thông tin tài khoản trên trang web này."
                    ),
                )
            )

        # 6. Kiem tra Du doan Nguy co Mo hinh AI chuyen biet (URL Lexical Classifier & Context)
        url_ml_risk = features.get("url_ml_risk", 0.0)
        is_url_ml_phishing = features.get("is_url_ml_phishing", False)
        if (is_url_ml_phishing or url_ml_risk >= 65.0) and not features.get("is_authorized_brand"):
            matches.append(
                RuleMatch(
                    rule_id="url_lexical_ml_threat",
                    category="Mô hình AI phát hiện liên kết lừa đảo / độc hại",
                    snippet=url,
                    score=int(min(max(url_ml_risk, 75.0), 95.0)),
                    explanation=(
                        f"Mô hình phân loại cấu trúc liên kết phát hiện URL '{url}' có độ tương đồng cao với các chiến dịch lừa đảo mạng ({url_ml_risk:.1f}% xác suất). "
                        "Cấu trúc đường dẫn và tên miền chứa các chỉ số đặc trưng của trang phishing/malware."
                    ),
                )
            )

    return matches


def check_email_spoofing(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu gia mao va lua dao qua dia chi email:
    1. Dung hom thu rac/tam thoi (Disposable Email).
    2. Mao danh co quan nha nuoc, to chuc, ngan hang qua email mien phi (gmail, yahoo, outlook...).
    """
    if not text or not text.strip():
        return []

    emails = extract_emails(text)
    if not emails:
        return []

    normalized = normalize_text(text)
    matches: list[RuleMatch] = []

    org_indicators = [
        "cong an", "toaan", "toa an", "vien kiem sat", "bo cong an", "vneid",
        "chinh phu", "cuc an ninh", "cuc thue", "tong cuc thue", "bao hiem xa hoi", "bhxh",
        "ngan hang", "vietcombank", "techcombank", "bidv", "agribank", "mbbank",
        "vpbank", "acb", "sacombank", "tpbank", "vib", "cskh", "tong dai",
        "shopee", "lazada", "tiki", "momo", "viettel", "vinaphone", "mobifone"
    ]

    for email in emails:
        email_lower = email.lower()
        parts = email_lower.split("@")
        if len(parts) != 2:
            continue
        user_part, domain = parts

        # 1. Hòm thư rác tạm thời
        if domain in DISPOSABLE_EMAIL_DOMAINS:
            matches.append(
                RuleMatch(
                    rule_id="disposable_email_domain",
                    category="Địa chỉ email rác nặc danh (Disposable Email)",
                    snippet=email,
                    score=40,
                    explanation=(
                        f"Địa chỉ email '{email}' sử dụng dịch vụ hòm thư rác tạm thời ({domain}). "
                        "Kẻ gian thường dùng các dịch vụ nặc danh này để phát tán mã độc, thư đe dọa "
                        "hoặc lừa đảo mà không để lại danh tính thật."
                    ),
                )
            )
            continue

        # 2. Mạo danh cơ quan / tổ chức qua hòm thư miễn phí
        if domain in FREE_EMAIL_DOMAINS:
            user_part_clean = user_part.replace(".", "").replace("_", "").replace("-", "")
            has_org_in_user = any(org.replace(" ", "") in user_part_clean for org in org_indicators)
            has_org_in_text = any(org in normalized for org in org_indicators)

            if has_org_in_user or has_org_in_text:
                matches.append(
                    RuleMatch(
                        rule_id="free_email_impersonation",
                        category="Mạo danh cơ quan / tổ chức qua Email miễn phí",
                        snippet=email,
                        score=45,
                        explanation=(
                            f"Địa chỉ email '{email}' dùng dịch vụ email miễn phí ({domain}) nhưng lại liên hệ "
                            "dưới danh nghĩa cơ quan nhà nước, ngân hàng hoặc tổ chức. Cơ quan nhà nước "
                            "và các doanh nghiệp uy tín luôn sử dụng hòm thư với tên miền định danh riêng "
                            "(.gov.vn hoặc tên miền chính thức của đơn vị), tuyệt đối không dùng hòm thư "
                            "miễn phí như Gmail, Yahoo hay Outlook để làm việc."
                        ),
                    )
                )

        # 3. Mạo danh tổ chức qua Tên hiển thị Email (Display Name Spoofing)
        display_match = re.search(r'([^\r\n<(\[]{2,50})\s*[<(\[]\s*' + re.escape(email) + r'\s*[>)\]]', text, re.I)
        if display_match and domain in FREE_EMAIL_DOMAINS:
            display_name = display_match.group(1).strip()
            display_name_norm = normalize_text(display_name)
            if any(org in display_name_norm for org in org_indicators):
                matches.append(
                    RuleMatch(
                        rule_id="display_name_email_spoofing",
                        category="Mạo danh tổ chức qua Tên hiển thị Email (Display Name Spoofing)",
                        snippet=f'"{display_name}" <{email}>',
                        score=50,
                        explanation=(
                            f"Email đặt tên người gửi hiển thị là '{display_name}' nhưng hòm thư thực tế lại là email cá nhân ({email}). "
                            "Đây là thủ đoạn lừa đảo tinh vi lợi dụng thói quen chỉ nhìn tên hiển thị trên điện thoại để đánh lừa nạn nhân."
                        ),
                    )
                )

    return matches


_PRIZE_EXPLANATION = (
    "Nội dung khẳng định bạn ĐÃ trúng thưởng/trúng giải (thường là ngẫu nhiên, không cần tham "
    "gia) KÈM yêu cầu hành động để nhận (đóng phí, điền thông tin, ký hợp đồng điện tử...). "
    "Đây là chiêu lừa phổ biến: chương trình trúng thưởng thật không bao giờ yêu cầu người "
    "trúng phải trả tiền trước để nhận giải."
)


def check_prize(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu trung thuong/trung giai gia. Chi bao khi VUA co cum
    tu ve trung thuong VUA co cum tu ve hanh dong nhan thuong/dong phi -
    tranh bao nham voi tin nhan tiep thi that (vd "CO HOI trung thuong..."
    tu telco/ngan hang, khong khang dinh chac chan va khong doi phi).
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)

    # Bỏ qua nếu là tin tiếp thị "cơ hội trúng thưởng" chính thống
    if "co hoi" in normalized:
        return []

    if not any(kw in normalized for kw in PRIZE_MENTION_KEYWORDS):
        return []
    if not any(marker in normalized for marker in PRIZE_CLAIM_ACTION_MARKERS):
        return []

    for kw in PRIZE_MENTION_KEYWORDS:
        if kw in normalized:
            return [
                RuleMatch(
                    rule_id="fake_prize",
                    category="Trúng thưởng giả",
                    snippet=_extract_snippet(text, normalized, kw),
                    score=25,
                    explanation=_PRIZE_EXPLANATION,
                )
            ]
    return []


_APK_EXPLANATION = (
    "Nội dung nhắc đến việc tải/cài file .apk trực tiếp — các ứng dụng chính thống (ngân "
    "hàng, cơ quan nhà nước...) luôn hướng dẫn cài qua CH Play/App Store, KHÔNG bao giờ gửi "
    "link tải file .apk rời cho người dùng tự cài. Đây là cách phổ biến để cài phần mềm gián "
    "điệp/chiếm quyền điều khiển điện thoại."
)
_APP_INSTALL_EXPLANATION = (
    "Nội dung yêu cầu cài đặt ứng dụng từ nguồn KHÔNG chính thống (không qua CH Play/App "
    "Store). Đây là dấu hiệu cần cảnh giác cao vì có thể là phần mềm gián điệp/chiếm quyền "
    "điều khiển điện thoại, tuy nhiên nhóm này CHƯA được kiểm chứng bằng dữ liệu thực tế "
    "(data/labeled_messages.csv không có đủ ví dụ) - chỉ dựa trên kiến thức chung về các "
    "chiêu lừa đảo phổ biến."
)


def check_app_install(text: str) -> list[RuleMatch]:
    """
    Kiem tra dau hieu cai dat ung dung la/gia mao.

    2 tang tin cay:
    1. Nhac den file ".apk" - tin hieu doc lap, da kiem chung sach (2/2
       trong data/labeled_messages.csv), diem cao hon.
    2. Co dong tu cai/tai ung dung VA cum tu the hien nguon KHONG chinh
       thong - CHUA duoc kiem chung bang data (xem ghi chu o
       patterns/vi_keywords.py), diem thap hon, danh dau ro trong
       explanation la chua kiem chung.
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)

    for kw in APK_FILE_KEYWORDS:
        if kw in normalized:
            return [
                RuleMatch(
                    rule_id="app_install_apk",
                    category="Yêu cầu cài file .apk trực tiếp",
                    snippet=_extract_snippet(text, normalized, kw),
                    score=25,
                    explanation=_APK_EXPLANATION,
                )
            ]

    has_install_verb = any(kw in normalized for kw in APP_INSTALL_KEYWORDS)
    has_unofficial_marker = any(marker in normalized for marker in UNOFFICIAL_SOURCE_MARKERS)
    if has_install_verb and has_unofficial_marker:
        for kw in APP_INSTALL_KEYWORDS:
            if kw in normalized:
                return [
                    RuleMatch(
                        rule_id="app_install_unofficial",
                        category="Cài đặt ứng dụng từ nguồn không chính thống",
                        snippet=_extract_snippet(text, normalized, kw),
                        score=18,
                        explanation=_APP_INSTALL_EXPLANATION,
                    )
                ]
    return []


_GAMBLING_EXPLANATION = (
    "Nội dung mồi chài tham gia sòng bài, tài xỉu, nổ hũ, cá cược hoặc cờ bạc trực tuyến trái phép. "
    "Hầu hết các cổng game này đều là bẫy lừa đảo nạp tiền (khi nạp số tiền lớn sẽ bị khóa tài "
    "khoản không cho rút tiền, chiếm đoạt tài sản hoặc dẫn dụ cài đặt mã độc). Tại Việt Nam, mọi hình "
    "thức cá cược/sòng bạc qua mạng chưa được cấp phép đều là hành vi vi phạm pháp luật nghiêm trọng."
)


def check_gambling(text: str) -> list[RuleMatch]:
    """
    Kiểm tra dấu hiệu dụ dỗ cờ bạc, sòng bài, tài xỉu, cá độ online.
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)
    for kw in GAMBLING_KEYWORDS:
        if kw in normalized:
            return [
                RuleMatch(
                    rule_id="illegal_gambling",
                    category="Mồi chài cờ bạc / Sòng bài trực tuyến",
                    snippet=_extract_snippet(text, normalized, kw),
                    score=45,
                    explanation=_GAMBLING_EXPLANATION,
                )
            ]
    return []


_JOB_SCAM_EXPLANATION = (
    "Nội dung có dấu hiệu mạo danh tuyển dụng nhân sự/cộng tác viên làm việc online tại nhà "
    "với mức thu nhập cao bất thường, việc nhẹ lương ngày hoặc dẫn dụ liên hệ qua Zalo/Telegram. "
    "Đây là chiêu trò lừa đảo nhiệm vụ phổ biến (dẫn dụ nạp tiền chốt đơn Shopee/TikTok/Lazada "
    "hoặc đánh giá sản phẩm rồi chiếm đoạt toàn bộ số tiền của nạn nhân)."
)


def check_job_scam(text: str) -> list[RuleMatch]:
    """
    Kiểm tra dấu hiệu lừa đảo tuyển dụng / việc nhẹ lương cao / làm nhiệm vụ.
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)
    has_intent = any(marker in normalized for marker in JOB_SCAM_INTENT_MARKERS)
    has_bait = any(marker in normalized for marker in JOB_SCAM_BAIT_MARKERS)

    if has_intent and has_bait:
        matched_kw = next((m for m in JOB_SCAM_BAIT_MARKERS if m in normalized), None) or next((m for m in JOB_SCAM_INTENT_MARKERS if m in normalized), "tuyen dung")
        return [
            RuleMatch(
                rule_id="job_recruitment_scam",
                category="Lừa đảo tuyển dụng / Việc nhẹ lương cao / CTV làm nhiệm vụ",
                snippet=_extract_snippet(text, normalized, matched_kw),
                score=40,
                explanation=_JOB_SCAM_EXPLANATION,
            )
        ]
    return []


_REVERSE_OTP_EXPLANATION = (
    "Nội dung thông báo phát sinh giao dịch trừ tiền/thanh toán lớn kèm hướng dẫn 'Nếu không phải bạn thực hiện hãy bấm link/gọi để hủy'. "
    "Đây là thủ đoạn lừa đảo tâm lý đảo ngược (Reverse Phishing): kẻ gian tạo sự hoảng loạn giả để nạn nhân vội vàng bấm vào liên kết lạ hoặc gọi điện xác minh, "
    "từ đó dẫn dụ nạn nhân nhập thông tin đăng nhập ngân hàng và mã OTP để chiếm đoạt tiền."
)


def check_reverse_otp_scam(text: str) -> list[RuleMatch]:
    """
    Kiểm tra dấu hiệu lừa đảo tâm lý đảo ngược (Reverse OTP / Reverse Phishing):
    Thông báo trừ tiền/thanh toán/gói cước giả -> dọa nạn nhân bấm link hủy giao dịch.
    """
    if not text or not text.strip():
        return []

    normalized = normalize_text(text)

    # Dấu hiệu 1: Thông báo giao dịch/trừ tiền/đăng ký dịch vụ
    has_charge_context = bool(re.search(
        r'(?:thanh\s+toan|giao\s+dich|tru\s+tien|da\s+thanh\s+toan|thanh\s+cong|dang\s+ky\s+goi|phi\s+duy\s+tri|ma\s+otp|otp|don\s+hang)',
        normalized
    ))

    # Dấu hiệu 2: Mồi chài hủy giao dịch / nếu không phải bạn
    has_cancel_bait = bool(re.search(
        r'(?:neu\s+(?:khong\s+phai|k\s+phai)\s+(?:ban|quy\s+khach)|khong\s+phai\s+ban|de\s+huy|de\s+hoan\s+tien|xac\s+minh\s+de\s+huy|lien\s+he\s+de\s+huy|goi\s+.*de\s+huy|bam\s+vao\s+link\s+de\s+huy|truy\s+cap\s+.*de\s+huy)',
        normalized
    ))

    urls = url_extractor.extract_urls(text)
    if has_charge_context and has_cancel_bait and urls:
        matched_snippet = urls[0]
        return [
            RuleMatch(
                rule_id="reverse_otp_scam",
                category="Lừa đảo tâm lý đảo ngược (Reverse OTP Phishing)",
                snippet=_extract_snippet(text, normalized, "de huy") or matched_snippet,
                score=50,
                explanation=_REVERSE_OTP_EXPLANATION,
            )
        ]
    return []


_BTS_SPOOF_EXPLANATION = (
    "Tin nhắn có nội dung xưng danh ngân hàng/nhà mạng nhưng lại đính kèm đường link dẫn đến website lạ (không phải tên miền chính thức). "
    "Kẻ gian hiện nay thường dùng trạm phát sóng di động giả mạo (Fake BTS) để chèn tin nhắn mạo danh Brandname vào cùng luồng tin nhắn thật của ngân hàng nhằm lừa người dân bấm vào link độc hại."
)


def check_bts_station_spoofing(text: str) -> list[RuleMatch]:
    """
    Kiểm tra dấu hiệu mạo danh tin nhắn thương hiệu qua trạm phát sóng BTS giả mạo.
    """
    if not text or not text.strip():
        return []

    urls = url_extractor.extract_urls(text)
    if not urls:
        return []

    normalized = normalize_text(text)

    # DAMPENER: Kiểm tra nếu là thông báo khuyến mãi / CSKH chính thống của nhà mạng viễn thông
    # Dấu hiệu tin nhắn nhà mạng thật: có tiền tố [TB] hoặc cú pháp tổng đài chính thống (gửi 100, gọi 197, gửi 191...)
    # VÀ không chứa các từ khóa đe dọa / đánh cắp thông tin (khóa tài khoản, xác thực, hủy...)
    has_threat_action = bool(re.search(
        r'(?:khoa\s+tai\s+khoan|tam\s+khoa|huy\s+dich\s+vu|bi\s+khoa|canh\s+bao|xac\s+thuc|nhap\s+otp|cung\s+cap\s+otp|dang\s+nhap\s+de|truy\s+cap\s+de\s+huy)',
        normalized
    ))

    has_official_telco_syntax = bool(re.search(
        r'(?:\[tb\]|\(tb\)|^tb:|\bsoan\s+[a-z0-9\s\[\]]+\s+gui\s+(?:100|191|109|888|900|999|9084)\b|\bgui\s+(?:100|191|109|888|900|999)\b|\bgoi\s+(?:197|198|9191|9090|18008098|18001091|18001090)\b)',
        normalized
    ))

    # Nếu có cú pháp nhà mạng chính thống và không có bất kỳ hành vi đe dọa nào -> không phải trạm BTS giả
    if has_official_telco_syntax and not has_threat_action:
        return []

    brand_names = [
        "vietcombank", "techcombank", "mbbank", "bidv", "agribank",
        "vpbank", "acb", "tpbank", "sacombank", "vib",
        "viettel", "vinaphone", "mobifone"
    ]

    for brand_kw in brand_names:
        if brand_kw in normalized:
            official_domains = PROTECTED_BRANDS.get(brand_kw, [])
            for url in urls:
                features = url_extractor.extract_features(url)
                netloc = features.get("netloc", "").lower()
                # Kiểm tra xem có thuộc danh bạ tên miền chính thức của thương hiệu không
                is_authorized = any(netloc == auth or netloc.endswith("." + auth) for auth in official_domains)
                # Kiểm tra thêm nền tảng deep link chiến dịch hợp lệ của thương hiệu (go.link, onelink.me)
                if not is_authorized and any(netloc.endswith("." + plat) for plat in ("go.link", "onelink.me")):
                    if brand_kw in netloc and not any(kw in netloc for kw in PHISHING_DOMAIN_KEYWORDS):
                        is_authorized = True

                if not is_authorized:
                    return [
                        RuleMatch(
                            rule_id="bts_fake_brand_sms",
                            category="Mạo danh Brandname qua trạm BTS giả",
                            snippet=f"{brand_kw.upper()} -> {url}",
                            score=55,
                            explanation=_BTS_SPOOF_EXPLANATION,
                        )
                    ]
    return []


def detect_all(text: str) -> list[RuleMatch]:
    """
    Diem vao chinh: chay tat ca cac rule THUAN TUY (khong DB) da co, gop
    ket qua lai. Nhom "tra cuu blacklist so dien thoai" (co DB) duoc goi
    rieng o app/services/blacklist_service.py.
    """
    matches: list[RuleMatch] = []
    matches.extend(check_impersonation(text))
    matches.extend(check_otp(text))
    matches.extend(check_urgent_transfer(text))
    matches.extend(check_suspicious_url(text))
    matches.extend(check_email_spoofing(text))
    matches.extend(check_gambling(text))
    matches.extend(check_job_scam(text))
    matches.extend(check_reverse_otp_scam(text))
    matches.extend(check_bts_station_spoofing(text))
    matches.extend(check_prize(text))
    matches.extend(check_app_install(text))
    return matches
