import re
import math
import urllib.parse
import logging
from collections import Counter
import httpx
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

# Danh bạ TLD quốc tế nguy cơ cao được phân tích theo thống kê an ninh mạng mới nhất
SUSPICIOUS_TLDS = {
    "top", "vip", "cc", "club", "ru", "online", "bond", "xyz", "site", "tech", "band", "me", "info",
    "cam", "fit", "sbs", "cfd", "icu", "buzz", "space", "rest", "lat", "bid", "work", "live", "life", "monster",
    "de", "shop", "link", "run", "biz", "to", "app", "pro", "io", "us", "cyou"
}

# Từ khóa nghiệp vụ bẫy lừa đảo thường bị ghép với thương hiệu (Combosquatting)
COMBOSQUATTING_KEYWORDS = {
    "login", "dangnhap", "ebank", "ibanking", "smartotp", "otp", "xacthuc",
    "portal", "auth", "secure", "security", "token", "banking", "online",
    "cskh", "hotro", "tongdai", "khieunai", "chamsoc",
    "trian", "quatang", "khuyenmai", "tangqua", "nhanqua", "sukien",
    "vaytien", "vaynhanh", "taiapp", "caiapp", "kiemtien",
    "taikhoan", "kichhoat", "nangcap", "baomat", "thongbao"
}

PHISHING_DOMAIN_KEYWORDS = {
    "nhanqua", "nhanthuong", "quatang", "trungthuong", "quaythuong", "vongquay",
    "trian", "tangqua", "khuyenmai", "sukien", "traothuong", "gamebai", "kiemtien",
    "vaynhanh", "vaytien", "taiapp", "caiapp", "xacthuc", "smartotp", "ebank",
    "taixiu", "songbac", "cacuoc", "nohu", "xocdia", "casino", "baccarat",
    "qbet", "sunwin", "go88", "kubet", "thabet", "shbet", "jun88", "new88", "hi88", "f8bet"
}

# Danh bạ các thương hiệu, ngân hàng và cơ quan chính thống tại Việt Nam cần bảo vệ
PROTECTED_BRANDS = {
    # 1. Khối Ngân hàng Thương mại (Toàn diện hệ thống NHTM Việt Nam)
    "vietcombank": ["vietcombank.com.vn"],
    "techcombank": ["techcombank.com.vn", "techcombank.com"],
    "mbbank": ["mbbank.com.vn"],
    "bidv": ["bidv.com.vn"],
    "agribank": ["agribank.com.vn"],
    "vpbank": ["vpbank.com.vn"],
    "acb": ["acb.com.vn"],
    "tpbank": ["tpbank.com.vn"],
    "sacombank": ["sacombank.com.vn"],
    "vib": ["vib.com.vn"],
    "vietinbank": ["vietinbank.vn"],
    "hdbank": ["hdbank.com.vn"],
    "shb": ["shb.com.vn"],
    "msb": ["msb.com.vn"],
    "ocb": ["ocb.com.vn"],
    "seabank": ["seabank.com.vn"],
    "lpbank": ["lpbank.com.vn"],
    "eximbank": ["eximbank.com.vn"],
    "pvcombank": ["pvcombank.com.vn"],
    "bacabank": ["bacabank.vn"],
    "namabank": ["namabank.com.vn"],
    "kienlongbank": ["kienlongbank.com"],
    "baovietbank": ["baovietbank.com.vn"],
    "vietabank": ["vietabank.com.vn"],
    "saigonbank": ["saigonbank.com.vn"],
    "shinhan": ["shinhan.com.vn"],
    "woori": ["woori.com.vn"],
    "uob": ["uob.com.vn"],
    "hsbc": ["hsbc.com.vn"],
    "standardchartered": ["sc.com"],

    # 2. Khối Ví điện tử & Trung gian thanh toán Fintech
    "momo": ["momo.vn"],
    "zalopay": ["zalopay.vn", "zalo.me"],
    "vnpay": ["vnpay.vn"],
    "shopeepay": ["shopeepay.vn"],
    "payoo": ["payoo.vn"],

    # 3. Khối Viễn thông
    "viettel": [
        "viettel.vn", "viettelpost.vn", "vietteltelecom.vn", "viettelmoney.vn",
        "viettelpay.vn", "vtp.vn", "myviettel.vn", "vt.vn", "yk.vtp.vn",
        "viettelstore.vn", "tv360.vn", "vtscloud.vn",
        "viettel.go.link", "vietteltammi.go.link", "viettelmoney.go.link", "myvt.page.link"
    ],
    "vinaphone": ["vinaphone.com.vn", "vnpt.com.vn", "vinaphone.vn", "vnpt.vn", "vnptmoney.vn", "vnptpay.vn", "vinaphone.vietlottsms.vn"],
    "vnptpay": ["vnptpay.vn", "vnptmoney.vn"],
    "mobifone": ["mobifone.vn", "mobifone.com.vn", "mymobifone.page.link"],

    # 4. Khối Cơ quan Nhà nước & Dịch vụ công thiết yếu
    "vneid": ["vneid.gov.vn"],
    "bocongan": ["bocongan.gov.vn"],
    "dichvucong": ["dichvucong.gov.vn"],
    "chinhphu": ["chinhphu.vn", "baochinhphu.vn"],
    "baohiemxahoi": ["baohiemxahoi.gov.vn"],
    "tongcucthue": ["gdt.gov.vn", "thuedientu.gdt.gov.vn"],
    "tinnhiemmang": ["tinnhiemmang.vn"],
    "ncsc": ["ncsc.gov.vn"],
    "evn": ["evn.com.vn"],
    "vnpost": ["vnpost.vn"],

    # 5. Thương mại điện tử & Dịch vụ số phổ biến
    "shopee": ["shopee.vn"],
    "lazada": ["lazada.vn"],
    "tiki": ["tiki.vn"],
    "sendo": ["sendo.vn"],
    "thegioididong": ["thegioididong.com"],
    "fpt": ["fpt.com.vn", "fptshop.com.vn", "fpt.vn", "fpt.edu.vn"],
    "zalo": ["zalo.me", "chat.zalo.me"],
    "facebook": ["facebook.com", "fb.com", "messenger.com", "instagram.com"],
    "google": ["google.com", "google.com.vn", "youtube.com", "gmail.com", "goo.gl"],
    "microsoft": ["microsoft.com", "office.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "telegram": ["telegram.org", "t.me"],
    "openai": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    "claude": ["claude.ai", "claude.com", "anthropic.com"],
    "anthropic": ["anthropic.com", "claude.ai", "claude.com"],
    "garena": ["garena.vn"],
    "p-sieve": ["127.0.0.1", "localhost"],
    # Tài chính tiêu dùng & Đối tác định danh
    "homecredit": ["homecredit.vn", "hcvn.app"],
    "fecredit": ["fecredit.com.vn"],
    "vietcom": ["vietcombank.com.vn"],
    "chiaki": ["chiaki.vn"],
}

# Dịch vụ Tunneling / Lưu trữ ứng dụng tạm thời miễn phí thường bị lạm dụng
TUNNEL_HOSTING_DOMAINS = {
    "ngrok-free.app", "ngrok.io", "loca.lt", "trycloudflare.com", "duckdns.org",
    "serveo.net", "firebaseapp.com", "web.app", "workers.dev", "pages.dev",
    "vercel.app", "netlify.app", "glitch.me", "repl.co", "herokuapp.com", "render.com",
    "surge.sh", "fly.dev", "b-cdn.net"
}

# Bảng mã ánh xạ Homoglyph / Confusable ký tự Cyrillic và Greek sang chữ Latin
HOMOGLYPH_MAP = {
    # Cyrillic lowercase sang Latin
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0455': 's', '\u0456': 'i', '\u0458': 'j', '\u0445': 'x', '\u0443': 'y',
    '\u0475': 'v', '\u0501': 'd', '\u051b': 'q', '\u051d': 'w',
    # Greek lowercase sang Latin
    '\u03b1': 'a', '\u03b2': 'b', '\u03b5': 'e', '\u03b9': 'i', '\u03ba': 'k',
    '\u03bd': 'v', '\u03bf': 'o', '\u03c1': 'p', '\u03c4': 't', '\u03c5': 'u',
    '\u03c7': 'x',
}

# Các dịch vụ chuyển hướng công cộng dễ bị khai thác Open Redirect
OPEN_REDIRECT_HOSTS = {
    "google.com", "www.google.com", "google.com.vn", "www.google.com.vn",
    "l.facebook.com", "lm.facebook.com", "facebook.com",
    "t.co", "youtube.com", "www.youtube.com", "linkedin.com", "www.linkedin.com",
    "bing.com", "www.bing.com", "duckduckgo.com"
}
REDIRECT_PARAMS = {"q", "u", "url", "redirect", "dest", "target", "next", "link", "r", "to", "out"}

DISPOSABLE_EMAIL_DOMAINS = {
    "tempmail.com", "10minutemail.com", "mailinator.com", "guerrillamail.com",
    "sharklasers.com", "yopmail.com", "trashmail.com", "dispostable.com",
    "temp-mail.org", "mohmal.com", "getnada.com", "throwawaymail.com",
    "emailondeck.com", "generator.email"
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"
}

EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')


def calculate_shannon_entropy(text: str) -> float:
    """Tính độ hỗn loạn Shannon Entropy (đo lường độ ngẫu nhiên của chuỗi ký tự)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def check_dga_domain(netloc: str) -> Dict[str, Any]:
    """
    Phát hiện tên miền sinh tự động (DGA / Gibberish Domain) với độ chính xác cao:
    1. Tỷ lệ nguyên âm (Vowel Ratio): Ngôn ngữ tự nhiên luôn có 25-50% nguyên âm.
       Tên miền lừa đảo DGA (vd: gwx6sd, q8z9x1, z8k9qp2) có tỷ lệ nguyên âm <= 12% (hoặc 0 nguyên âm).
    2. Độ hỗn loạn Shannon Entropy: Các tên miền ngẫu nhiên có entropy cao bất thường.
    3. Tỷ lệ số xen kẽ và cụm phụ âm liên tiếp.
    """
    if not netloc:
        return {"is_dga": False}
    clean = netloc.lower().split(':')[0].strip()
    parts = clean.split('.')
    label = parts[0]
    if len(parts) >= 2:
        if parts[-1] == 'vn' and len(parts) >= 3 and parts[-2] in {"com", "gov", "edu", "net", "org"}:
            label = parts[-3]
        else:
            label = parts[-2]

    core = label.replace('-', '').replace('_', '')
    length = len(core)
    if length < 5:
        return {"is_dga": False, "label": label, "entropy": 0.0, "vowel_ratio": 0.0}

    counts = Counter(core)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    vowels = sum(1 for c in core if c in 'aeiou')
    vowel_ratio = vowels / max(length, 1)
    digits = sum(1 for c in core if c.isdigit())
    digit_ratio = digits / max(length, 1)
    has_long_consonant = bool(re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', core))

    is_dga = False
    reasons = []

    # Tiêu chí 1: Không có hoặc quá ít nguyên âm (vd: gwx6sd -> 0 nguyên âm)
    if vowel_ratio <= 0.12 and length >= 5:
        is_dga = True
        reasons.append(f"Tỷ lệ nguyên âm cực thấp ({vowel_ratio*100:.1f}%), nghi vấn sinh ngẫu nhiên")

    # Tiêu chí 2: Cụm phụ âm liên tiếp >= 5 ký tự và entropy cao
    if has_long_consonant and entropy >= 2.3:
        is_dga = True
        reasons.append("Chứa cụm phụ âm liên tiếp bất thường")

    # Tiêu chí 3: Tỷ lệ số xen kẽ cao bất thường kèm entropy cao
    if digit_ratio >= 0.4 and entropy >= 2.5:
        is_dga = True
        reasons.append(f"Tỷ lệ số xen kẽ cao bất thường ({digit_ratio*100:.1f}%)")

    return {
        "is_dga": is_dga,
        "label": label,
        "entropy": round(entropy, 3),
        "vowel_ratio": round(vowel_ratio, 3),
        "digit_ratio": round(digit_ratio, 3),
        "reasons": reasons
    }


def levenshtein_distance(s1: str, s2: str) -> int:
    """Tính khoảng cách Levenshtein giữa 2 chuỗi (số bước sửa đổi tối thiểu)."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def jaro_similarity(s1: str, s2: str) -> float:
    """Tính độ tương đồng Jaro giữa 2 chuỗi (từ 0.0 đến 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    transpositions = 0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    return (
        (matches / len1)
        + (matches / len2)
        + ((matches - transpositions / 2) / matches)
    ) / 3.0


def jaro_winkler_similarity(s1: str, s2: str, prefix_scaling: float = 0.1) -> float:
    """
    Tính độ tương đồng Jaro-Winkler giữa 2 chuỗi (0.0 -> 1.0).
    Ưu tiên tiền tố giống nhau (thường gặp trong Typosquatting thương hiệu).
    """
    jaro = jaro_similarity(s1, s2)
    prefix_len = 0
    max_prefix = min(4, min(len(s1), len(s2)))
    for i in range(max_prefix):
        if s1[i] == s2[i]:
            prefix_len += 1
        else:
            break
    return jaro + (prefix_len * prefix_scaling * (1.0 - jaro))


def calculate_brand_similarity(candidate: str, brand: str) -> float:
    """
    Thuật toán Kết hợp Khoảng cách Thương hiệu Chuẩn Công nghiệp (Ensemble Brand Distance):
    Kết hợp Jaro-Winkler (70%) + Normalized Levenshtein (30%).
    """
    if not candidate or not brand:
        return 0.0
    cand_clean = candidate.lower().strip()
    brand_clean = brand.lower().strip()
    if cand_clean == brand_clean:
        return 1.0

    jw = jaro_winkler_similarity(cand_clean, brand_clean)
    lev_dist = levenshtein_distance(cand_clean, brand_clean)
    max_len = max(len(cand_clean), len(brand_clean))
    lev_sim = max(0.0, 1.0 - (lev_dist / max_len))

    return round(jw * 0.7 + lev_sim * 0.3, 4)


def decode_punycode_and_homoglyphs(domain: str) -> Tuple[str, bool, bool]:
    """
    Giải mã Punycode (xn--) và chuẩn hóa Homoglyph (chữ Cyrillic, Greek thị giác sang Latin).
    Trả về (normalized_domain, has_punycode, has_homoglyphs).
    """
    parts = domain.split('.')
    decoded_parts = []
    has_punycode = False
    for part in parts:
        if part.startswith('xn--'):
            has_punycode = True
            try:
                decoded = part.encode('ascii').decode('idna')
                decoded_parts.append(decoded)
            except Exception:
                decoded_parts.append(part)
        else:
            decoded_parts.append(part)

    decoded_domain = '.'.join(decoded_parts)
    has_homoglyphs = False
    mapped_chars = []
    for char in decoded_domain:
        if char in HOMOGLYPH_MAP:
            mapped_chars.append(HOMOGLYPH_MAP[char])
            has_homoglyphs = True
        else:
            mapped_chars.append(char)

    return ''.join(mapped_chars), has_punycode, has_homoglyphs


def check_brand_impersonation(netloc: str) -> Dict[str, Any]:
    """
    Phát hiện giả mạo thương hiệu và Typosquatting đa tầng:
    1. IDN Homoglyph / Punycode Attack: Dùng ký tự Cyrillic/Greek nhìn giống hệt chữ Latin (vd: viеtcombank.com).
    2. Cloud Tunnel / Ephemeral Hosting Abuse: Dùng hạ tầng tạm thời (trycloudflare, ngrok, workers.dev).
    3. Subdomain Deception: Giả mạo nhãn thương hiệu vào subdomain (vd: vietcombank.com.vn.attacker.xyz).
    4. Combosquatting: Ghép tên thương hiệu với từ khóa nghiệp vụ/bảo mật (vd: vietcombank-ebank.xyz).
    5. Substring Hijacking: Tên miền chứa tên thương hiệu nhưng không thuộc hệ thống chính thức.
    6. Typosquatting: Tên miền cố tình viết chệch 1-2 ký tự (vd: vietcornbank, sh0pee).
    """
    if not netloc:
        return {"is_impersonation": False}

    domain_clean = netloc.lower().strip()
    if ':' in domain_clean:
        domain_clean = domain_clean.split(':')[0]

    # Kiểm tra xem có phải tên miền chính thức không
    for brand, auth_domains in PROTECTED_BRANDS.items():
        for auth in auth_domains:
            if domain_clean == auth or domain_clean.endswith('.' + auth):
                return {"is_impersonation": False, "is_authorized": True, "brand": brand}

    # Kiểm tra subdomain chiến dịch trên các nền tảng deep link / smart link đối tác hợp lệ (AppsFlyer go.link, OneLink...)
    if any(domain_clean.endswith('.' + plat) for plat in ("go.link", "onelink.me")):
        if not any(kw in domain_clean for kw in PHISHING_DOMAIN_KEYWORDS):
            for brand in PROTECTED_BRANDS:
                if brand in domain_clean:
                    return {"is_impersonation": False, "is_authorized": True, "brand": brand}

    # 1. Phát hiện Tấn công IDN Homoglyph & Punycode (Visual Confusable Spoofing)
    norm_homo, has_puny, has_homo = decode_punycode_and_homoglyphs(domain_clean)
    if has_puny or has_homo:
        for brand, auth_domains in PROTECTED_BRANDS.items():
            if brand in norm_homo:
                return {
                    "is_impersonation": True,
                    "type": "HOMOGLYPH_ATTACK",
                    "brand": brand,
                    "decoded_domain": norm_homo,
                    "detail": f"Tên miền '{netloc}' sử dụng kỹ thuật tấn công ký tự tương đồng thị giác (IDN Homoglyph Attack / Punycode). Tên miền cố tình ngụy trang thành thương hiệu '{brand}' bằng các ký tự quốc tế nhìn giống chữ cái Latin."
                }
        if has_homo:
            return {
                "is_impersonation": True,
                "type": "HOMOGLYPH_ANOMALY",
                "decoded_domain": norm_homo,
                "detail": f"Tên miền '{netloc}' chứa ký tự đa ngữ tương đồng thị giác (Cyrillic/Greek confusables) bất thường, có dấu hiệu ngụy trang đánh lừa người dùng."
            }

    # 2. Phát hiện Lạm dụng Dịch vụ Tunneling / Lưu trữ Đám mây Tạm thời (ngrok, trycloudflare, workers.dev, v.v...)
    for tunnel in TUNNEL_HOSTING_DOMAINS:
        if domain_clean.endswith('.' + tunnel):
            sub = domain_clean[:-len(tunnel)-1]
            sub_tokens = set(re.split(r'[^a-z0-9]', sub))
            for brand in PROTECTED_BRANDS:
                if brand in sub_tokens or brand in sub:
                    return {
                        "is_impersonation": True,
                        "type": "TUNNEL_HOSTING_ABUSE",
                        "brand": brand,
                        "tunnel_service": tunnel,
                        "detail": f"Tên miền '{netloc}' lạm dụng dịch vụ lưu trữ đám mây tạm thời ({tunnel}) để dựng trang mạo danh thương hiệu '{brand}'."
                    }
            if any(kw in sub_tokens for kw in COMBOSQUATTING_KEYWORDS) or any(kw in sub for kw in PHISHING_DOMAIN_KEYWORDS):
                return {
                    "is_impersonation": True,
                    "type": "TUNNEL_HOSTING_ABUSE",
                    "tunnel_service": tunnel,
                    "detail": f"Tên miền '{netloc}' lạm dụng hạ tầng đám mây tạm thời ({tunnel}) kết hợp từ khóa nghiệp vụ/lừa đảo để lập trang web bẫy thông tin."
                }

    # Bóc tách Subdomain và Apex Domain
    domain_parts = domain_clean.split('.')
    if len(domain_parts) >= 3:
        if domain_parts[-1] == "vn" and len(domain_parts) >= 4 and domain_parts[-2] in {"com", "gov", "edu", "net", "org"}:
            subdomain_part = '.'.join(domain_parts[:-3])
            apex_domain = '.'.join(domain_parts[-3:])
        else:
            subdomain_part = '.'.join(domain_parts[:-2])
            apex_domain = '.'.join(domain_parts[-2:])

        # 3. Phát hiện Subdomain Deception (Lừa mắt trên thiết bị di động / SMS)
        sub_tokens = set(re.split(r'[^a-z0-9]', subdomain_part))
        for brand, auth_domains in PROTECTED_BRANDS.items():
            matched_sub = (brand in sub_tokens) if len(brand) <= 4 else (brand in subdomain_part)
            if matched_sub:
                if not any(apex_domain == a or apex_domain.endswith('.' + a) for a in auth_domains):
                    return {
                        "is_impersonation": True,
                        "type": "SUBDOMAIN_DECEPTION",
                        "brand": brand,
                        "apex_domain": apex_domain,
                        "detail": f"Tên miền '{netloc}' sử dụng kỹ thuật Subdomain Deception: Giả mạo nhãn thương hiệu '{brand}' vào tiền tố tên miền để đánh lừa người dùng, trong khi máy chủ thực sự thuộc về '{apex_domain}'."
                    }

    # Chuẩn hóa leetspeak cơ bản
    normalized_domain = domain_clean.replace('0', 'o').replace('1', 'i').replace('3', 'e')
    domain_tokens = set(re.split(r'[^a-z0-9]', normalized_domain))

    # 4. Phát hiện Combosquatting (Ghép thương hiệu với từ khóa tài chính / bảo mật)
    for brand, auth_domains in PROTECTED_BRANDS.items():
        if brand in domain_tokens or (len(brand) > 4 and brand in normalized_domain):
            matched_combos = [kw for kw in COMBOSQUATTING_KEYWORDS if kw in domain_tokens]
            if matched_combos:
                return {
                    "is_impersonation": True,
                    "type": "COMBOSQUATTING",
                    "brand": brand,
                    "matched_keywords": matched_combos,
                    "detail": f"Tên miền '{netloc}' sử dụng kỹ thuật Combosquatting: Ghép tên thương hiệu '{brand}' với từ khóa nghiệp vụ ({', '.join(matched_combos)}) trên hạ tầng chưa xác thực."
                }

    # 5. Kiểm tra lạm dụng tên thương hiệu (Substring Hijacking)
    for brand, auth_domains in PROTECTED_BRANDS.items():
        matched = False
        if len(brand) <= 4:
            if brand in domain_tokens:
                matched = True
        else:
            if brand in normalized_domain:
                matched = True

        if matched:
            return {
                "is_impersonation": True,
                "type": "BRAND_HIJACK",
                "brand": brand,
                "detail": f"Tên miền '{netloc}' mạo danh thương hiệu/tổ chức '{brand}' nhưng không thuộc hệ thống chính thức ({', '.join(auth_domains)})."
            }

    # 6. Kiểm tra Typosquatting Nâng cao & Khoảng cách Thương hiệu (Ensemble Brand Distance)
    if len(domain_parts) >= 2:
        if domain_parts[-1] == "vn" and domain_parts[-2] in {"com", "gov", "edu", "net", "org"}:
            check_labels = domain_parts[:-2]
        else:
            check_labels = domain_parts[:-1]
    else:
        check_labels = domain_parts

    for label in check_labels:
        if len(label) < 3:
            continue

        # 6.1 Phát hiện Hyphenation Squatting (chèn dấu gạch nối giữa tên thương hiệu: viet-com-bank, tech-com-bank)
        if '-' in label:
            dehyphen = label.replace('-', '')
            for brand, auth_domains in PROTECTED_BRANDS.items():
                if len(brand) >= 4 and dehyphen == brand:
                    return {
                        "is_impersonation": True,
                        "type": "TYPOSQUATTING",
                        "brand": brand,
                        "similarity_score": 100.0,
                        "distance": 0,
                        "matched_word": label,
                        "detail": f"Tên miền '{netloc}' sử dụng kỹ thuật Hyphenation Squatting (chèn gạch nối '{label}' để mạo danh thương hiệu '{brand.upper()}')."
                    }

        # 6.2 Phân tích đa từ với Thuật toán Khoảng cách Thương hiệu (Jaro-Winkler + Levenshtein)
        candidate_words = [label] + [w for w in label.split('-') if len(w) >= 3]
        for word in candidate_words:
            normalized_word = word.replace('0', 'o').replace('1', 'i').replace('3', 'e')

            for brand, auth_domains in PROTECTED_BRANDS.items():
                if word in {"ebank", "ibanking"} and brand == "mbbank":
                    continue
                if normalized_word == brand:
                    continue

                dist = levenshtein_distance(normalized_word, brand)
                sim_score = calculate_brand_similarity(normalized_word, brand)

                is_match = False
                # Đối với thương hiệu dài (>= 5 ký tự: vietcombank, techcombank, shopee, viettel...)
                if len(brand) >= 5:
                    if sim_score >= 0.85:
                        is_match = True
                    elif dist <= 2 and normalized_word[0] == brand[0] and abs(len(normalized_word) - len(brand)) <= 2:
                        is_match = True
                # Đối với thương hiệu ngắn (<= 4 ký tự: vcb, acb, bidv, tiki...)
                else:
                    if sim_score >= 0.90 and len(normalized_word) >= 3:
                        is_match = True
                    elif dist <= 1 and normalized_word[0] == brand[0] and len(normalized_word) == len(brand):
                        is_match = True

                if is_match:
                    pct = round(sim_score * 100, 1)
                    return {
                        "is_impersonation": True,
                        "type": "TYPOSQUATTING",
                        "brand": brand,
                        "similarity_score": pct,
                        "distance": dist,
                        "matched_word": word,
                        "detail": f"Tên miền '{netloc}' sử dụng kỹ thuật Typosquatting (độ tương đồng {pct}%, khoảng cách {dist} với thương hiệu '{brand.upper()}' từ từ khóa '{word}')."
                    }

    return {"is_impersonation": False}


class URLExtractor:
    def __init__(self):
        homo_chars = ''.join(re.escape(k) for k in HOMOGLYPH_MAP.keys())
        tlds_all = sorted(list(SUSPICIOUS_TLDS | {"com.vn", "edu.vn", "gov.vn", "vn", "com", "net", "org"}), key=lambda x: -len(x))
        tlds_pattern = r"(?:" + "|".join(re.escape(t) for t in tlds_all) + r")"
        char_cls = f'[a-zA-Z0-9_{homo_chars}-]'
        self.url_pattern = re.compile(
            r'(?i)\b(?:https?://|www\d{0,3}\.)[^\s()<>{}\[\]]+|(?<![\w@/])(?:' + char_cls + r'+\.)+' + tlds_pattern + r'(?:/[^\s()<>{}\[\]]*)?'
        )
        self.ip_pattern = re.compile(
            r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        self.shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "page.link",
            "s.net.vn", "shorturl.at", "cutt.ly", "rebrand.ly", "gg.gg", "soo.gd",
            "v.gd", "rutgon.me", "link1s.com", "bom.so", "bom.to", "tiny.cc",
            "shortcm.li", "tny.im", "chilp.it", "clck.ru", "cutt.us"
        }

    def trace_shortened_url(self, url: str, timeout: float = 2.0) -> Tuple[str, bool]:
        """
        Dò theo luồng chuyển hướng của link rút gọn để tìm ra tên miền đích thực sự.
        Dùng HTTP HEAD/GET với timeout ngắn để không làm chậm ứng dụng.
        Trả về (final_url, is_redirected).
        """
        if not url:
            return url, False
        try:
            target = url if url.startswith(('http://', 'https://')) else 'http://' + url
            with httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as client:
                resp = client.head(target)
                final_url = str(resp.url)
                if final_url != target and final_url != target + "/":
                    return final_url, True
        except Exception:
            try:
                with httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as client:
                    resp = client.get(target, headers={"Range": "bytes=0-100"})
                    final_url = str(resp.url)
                    if final_url != target and final_url != target + "/":
                        return final_url, True
            except Exception:
                pass
        return url, False

    def extract_urls(self, text: str) -> List[str]:
        if not text:
            return []
        try:
            import unicodedata
            norm_text = unicodedata.normalize('NFKC', text)
            matches = self.url_pattern.findall(norm_text)
            urls = []
            for match in matches:
                cleaned_url = match.rstrip(".,;:!?)\"']")
                if cleaned_url and cleaned_url not in urls:
                    urls.append(cleaned_url)
            return urls
        except Exception as e:
            logger.error(f"Error extracting URLs: {str(e)}", exc_info=True)
            return []

    def extract_features(self, url: str) -> Dict[str, Any]:
        features = {
            "is_ip_domain": False, "is_shortened": False, "is_redirected": False,
            "resolved_url": url, "resolved_netloc": "", "subdomain_count": 0,
            "has_suspicious_keywords": False, "has_phishing_keyword": False,
            "is_brand_impersonation": False, "impersonation_info": {},
            "path_length": 0, "netloc": "", "tld": ""
        }
        try:
            target_url = url
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url

            sanitized_url = re.sub(r'\[.*?\]', 'dummy', target_url)
            parsed = urllib.parse.urlparse(sanitized_url)

            # 1. Phát hiện Credential Spoofing qua ký tự '@' trong authority (vd: https://vietcombank.com.vn@evil.xyz)
            raw_authority = target_url.split('://', 1)[-1].split('/', 1)[0].split('?', 1)[0].split('#', 1)[0]
            if '@' in raw_authority:
                user_info, actual_host = raw_authority.split('@', 1)
                features["has_credential_spoofing"] = True
                features["spoofed_credential"] = user_info
                features["actual_host"] = actual_host
                netloc = actual_host.lower().split(':')[0]
            else:
                netloc = parsed.netloc.lower()
                if ':' in netloc:
                    netloc = netloc.split(':')[0]

            features["netloc"] = netloc
            features["path_length"] = len(parsed.path)

            parts = netloc.split('.')
            if len(parts) >= 2:
                features["tld"] = parts[-1]
                if len(parts) > 2:
                    features["subdomain_count"] = len(parts) - 2

            is_local = netloc in ("localhost", "127.0.0.1", "0.0.0.0") or netloc.startswith("127.") or netloc.startswith("192.168.") or netloc.startswith("10.")
            if self.ip_pattern.match(netloc) and not is_local:
                features["is_ip_domain"] = True

            # Phát hiện IP dạng số nguyên (DWORD) hoặc Hex (vd: 0x7f000001, 2130706433)
            is_hex_ip = netloc.startswith("0x")
            is_dword_ip = netloc.isdigit() and int(netloc) > 65535 and not netloc.startswith("0")
            if is_hex_ip or is_dword_ip:
                features["is_ip_domain"] = True
                features["is_obfuscated_ip"] = True

            # 2. Phát hiện và giám định bẫy chuyển hướng mở (Open Redirect Abuse)
            is_open_redir_host = (
                netloc in OPEN_REDIRECT_HOSTS 
                or any(netloc.endswith('.' + h) for h in OPEN_REDIRECT_HOSTS)
            )
            qs = urllib.parse.parse_qs(parsed.query)
            target_redirect_url = None
            for p in REDIRECT_PARAMS:
                if p in qs and qs[p]:
                    cand = qs[p][0]
                    if cand.startswith(('http://', 'https://')) or ('.' in cand and not cand.startswith('/')):
                        target_redirect_url = cand
                        break

            if target_redirect_url and (is_open_redir_host or 'redirect' in parsed.path.lower() or 'url' in parsed.path.lower()):
                features["is_open_redirect"] = True
                features["redirect_target_url"] = target_redirect_url
                # Bóc tách và kiểm tra đệ quy mục tiêu đích được chuyển hướng
                target_features = self.extract_features(target_redirect_url)
                if (
                    target_features.get("is_dga") 
                    or target_features.get("is_brand_impersonation") 
                    or target_features.get("has_phishing_keyword")
                    or target_features.get("is_suspicious_tld")
                    or target_features.get("is_ip_domain")
                ):
                    features["is_open_redirect_abuse"] = True
                    features["nested_threat"] = target_features

            # Kiểm tra và giải mã link rút gọn ngụy trang
            if netloc in self.shorteners:
                features["is_shortened"] = True
                final_url, redirected = self.trace_shortened_url(target_url, timeout=2.0)
                if redirected:
                    features["is_redirected"] = True
                    features["resolved_url"] = final_url
                    parsed_final = urllib.parse.urlparse(final_url)
                    final_netloc = parsed_final.netloc.lower().split(':')[0]
                    features["resolved_netloc"] = final_netloc

                    # Quét tên miền đích sau khi giải mã rút gọn
                    final_imp = check_brand_impersonation(final_netloc)
                    if final_imp.get("is_impersonation"):
                        features["is_brand_impersonation"] = True
                        features["impersonation_info"] = final_imp

                    betting_final = bool(re.search(r'(?:[a-z0-9]*bet\d{2,4}|[a-z0-9]*win\d{2,4}|w88|m88|fun88|fb88|go88)', final_netloc))
                    if any(kw in final_netloc for kw in PHISHING_DOMAIN_KEYWORDS) or betting_final:
                        features["has_phishing_keyword"] = True

            suspicious_path_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'xacthuc', 'nhanthuong']
            if any(kw in parsed.path.lower() for kw in suspicious_path_keywords):
                features["has_suspicious_keywords"] = True

            betting_domain = bool(re.search(
                r'(?:[a-z0-9]*bet\d{0,4}|[a-z0-9]*win\d{0,4}|w88|m88|fun88|fb88|go88|kubet|thabet|shbet|jun88|new88|hi88|f8bet|nohu|xocdia|taixiu|v\d+m\d+|f\d{4,}|[a-z]{1,4}\d{3,6}\.(?:com|net|vip|cc|online))',
                netloc
            ))
            if any(kw in netloc for kw in PHISHING_DOMAIN_KEYWORDS) or betting_domain:
                features["has_phishing_keyword"] = True

            # Kiểm tra giả mạo thương hiệu, Homoglyphs & Typosquatting
            imp_check = check_brand_impersonation(netloc)
            if imp_check.get("is_impersonation"):
                features["is_brand_impersonation"] = True
                features["impersonation_info"] = imp_check
            features["is_authorized_brand"] = imp_check.get("is_authorized", False)

            # 6. Kiểm tra Tên miền DGA & TLD rủi ro cao (Zero-Day Domain Analysis)
            dga_check = check_dga_domain(netloc)
            features["is_dga"] = False if features["is_authorized_brand"] else dga_check.get("is_dga", False)
            features["dga_info"] = dga_check
            features["is_suspicious_tld"] = False if features["is_authorized_brand"] else (features.get("tld", "") in SUSPICIOUS_TLDS)

            # 7. Dự đoán nguy cơ Phishing bằng mô hình ML LightGBM chuyên biệt (20 Pure Lexical Features)
            try:
                from app.detector.url_ml_classifier import url_classifier
                ml_eval = url_classifier.predict(target_url)
                features["url_ml_risk"] = ml_eval.get("risk_score", 0.0)
                features["is_url_ml_phishing"] = ml_eval.get("is_phishing", False)
            except Exception:
                features["url_ml_risk"] = 0.0
                features["is_url_ml_phishing"] = False

            return features
        except Exception as e:
            logger.error(f"Feature extraction failed for URL {url}: {str(e)}")
            return features


def extract_emails(text: str) -> List[str]:
    """Trích xuất tất cả các địa chỉ email có trong văn bản."""
    if not text:
        return []
    return EMAIL_REGEX.findall(text)


url_extractor = URLExtractor()