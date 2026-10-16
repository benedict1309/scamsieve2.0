# File: scripts/build_balanced_url_dataset.py
"""
Xây dựng tập dữ liệu URL chuẩn công nghiệp (2.500+ mẫu):
- Cân bằng Benign vs Phishing
- Bổ sung URL cấp domain/homepage (Google, VCB, MB, Viettel, Microsoft,...)
- Bổ sung URL có đường dẫn hợp pháp và các biến thể thực tế
- Bổ sung các mẫu Phishing đối kháng (Typosquatting, Combosquatting, DGA, IP domain)
"""
import csv
import os
import sys

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ORIGINAL_DATA_PATH = 'data/url_phishing_dataset.csv'
TARGET_DATA_PATH = 'data/url_dataset_industrial.csv'

# 1. Danh sách Top Global Domains & Services (Tranco/Alexa)
GLOBAL_BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com", "instagram.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "amazon.com", "reddit.com", "netflix.com",
    "linkedin.com", "microsoft.com", "bing.com", "live.com", "office.com", "github.com",
    "gitlab.com", "apple.com", "pinterest.com", "wordpress.org", "tumblr.com", "imgur.com",
    "stackoverflow.com", "cloudflare.com", "zoom.us", "spotify.com", "adobe.com", "dropbox.com",
    "twitch.tv", "medium.com", "quora.com", "imdb.com", "cnn.com", "bbc.com", "nytimes.com",
    "theguardian.com", "reuters.com", "bloomberg.com", "forbes.com", "nih.gov", "cdc.gov",
    "who.int", "un.org", "harvard.edu", "stanford.edu", "mit.edu", "berkeley.edu", "ox.ac.uk",
    "cam.ac.uk", "python.org", "pypi.org", "npmjs.com", "mozilla.org", "w3.org", "ietf.org",
    "apache.org", "kernel.org", "debian.org", "ubuntu.com", "centos.org", "docker.com",
    "kubernetes.io", "openai.com", "anthropic.com", "claude.ai", "chatgpt.com", "huggingface.co",
    "salesforce.com", "oracle.com", "ibm.com", "intel.com", "cisco.com", "dell.com", "hp.com"
]

# 2. Danh sách Top Vietnamese Domains & Services
VN_BENIGN_DOMAINS = [
    # Ngân hàng & Tài chính
    "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn", "agribank.com.vn",
    "vpbank.com.vn", "acb.com.vn", "tpbank.com.vn", "sacombank.com.vn", "vib.com.vn",
    "vietinbank.vn", "hdbank.com.vn", "shb.com.vn", "msb.com.vn", "ocb.com.vn", "seabank.com.vn",
    "lpbank.com.vn", "eximbank.com.vn", "pvcombank.com.vn", "bacabank.vn", "namabank.com.vn",
    "momo.vn", "zalopay.vn", "zalo.me", "vnpay.vn", "shopeepay.vn", "payoo.vn",
    # Viễn thông
    "viettel.vn", "vietteltelecom.vn", "viettelmoney.vn", "viettelpost.vn", "myviettel.vn",
    "mobifone.vn", "mobifone.com.vn", "vinaphone.vn", "vinaphone.com.vn", "vnpt.vn", "vietnamobile.com.vn", "fpt.vn",
    # Chính phủ & Dịch vụ công
    "chinhphu.vn", "baochinhphu.vn", "dichvucong.gov.vn", "vneid.gov.vn", "bocongan.gov.vn",
    "baohiemxahoi.gov.vn", "gdt.gov.vn", "thuedientu.gdt.gov.vn", "tinnhiemmang.vn", "ncsc.gov.vn", "chongluadao.vn",
    # Thương mại điện tử & Bán lẻ
    "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "thegioididong.com", "dienmayxanh.com",
    "bachhoaxanh.com", "fptshop.com.vn", "cellphones.com.vn", "hoanghamobile.com", "mediamart.vn",
    # Báo chí & Truyền hình
    "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn", "vtv.vn",
    "laodong.vn", "tienphong.vn", "soha.vn", "kenh14.vn", "znews.vn", "plo.vn", "cafef.vn", "cafebiz.vn",
    # Trường đại học & Nghiên cứu
    "vnu.edu.vn", "hust.edu.vn", "neu.edu.vn", "ftu.edu.vn", "uit.edu.vn", "hcmut.edu.vn", "ueh.edu.vn"
]

BENIGN_PATHS = [
    "", "/", "/about", "/contact", "/login", "/register", "/security", "/privacy",
    "/terms", "/help", "/support", "/faq", "/docs", "/blog", "/news", "/pricing",
    "/services", "/products", "/features", "/api/v1", "/download", "/search"
]

# 3. Mẫu Phishing tổng hợp đa dạng đối kháng
PHISHING_PATTERNS_TEMPLATE = [
    # Typosquatting / Combosquatting ngân hàng
    "http://vietcombank-login-online.xyz", "https://vietcombank-smart-otp.top",
    "http://techcombank-xacthuc.site", "https://techcombank-ebanking.buzz",
    "http://mbbank-nhanthuong.club", "https://mb-smartotp-update.online",
    "http://bidv-baomat-taikhoan.icu", "https://agribank-vaytien-online.cc",
    "http://acb-khuyenmai-trian.vip", "https://vpbank-neo-secure.cfd",
    "http://tpbank-ebank-login.rest", "https://sacombank-pay-verify.lat",
    "http://vib-chamsockhachhang.band", "https://vietinbank-smart-portal.sbs",
    # Subdomain Deception
    "http://vietcombank.com.vn.ebank-auth-update.info/login.php",
    "https://mbbank.com.vn.nhan-qua-2026.xyz/portal/claim",
    "http://techcombank.com.vn.kichhoat-smartotp.top/auth",
    "http://vneid.gov.vn.dichvucong-capnhat.site/vneid-install.apk",
    "https://bocongan.gov.vn.lenh-bat-giam-truy-to.xyz/ho-so-vu-an",
    "http://shopee.vn.voucher-trian-100k.top/nhan-thuong",
    "http://viettel.vn.napthe-khuyenmai50.xyz/nap-tien",
    # IP Address trực tiếp
    "http://172.67.145.22/vcb/login.php", "http://103.45.23.11:8080/portal/auth",
    "http://192.241.155.3/smartotp/index.html", "http://45.76.12.98/bidv/verify",
    # Cờ bạc, cá cược, lừa đảo việc làm
    "https://tai-xiu-go88-doi-thuong.club", "http://sunwin-songbac-online.vip",
    "http://kubet-casino-dangky.top", "https://viec-nhe-luong-cao-ctv.xyz/dang-ky",
    "http://chot-don-shopee-kiem-tien.top/task", "https://nhan-code-no-hu-100k.site"
]

def generate_industrial_dataset():
    urls = []
    seen = set()
    
    # 1. Nạp từ tập gốc
    if os.path.exists(ORIGINAL_DATA_PATH):
        with open(ORIGINAL_DATA_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                u = row.get('URL', '').strip()
                t = row.get('type', '').strip().lower()
                if u and u not in seen:
                    seen.add(u)
                    urls.append((u, t))
                    
    initial_benign = sum(1 for _, t in urls if t == 'benign')
    initial_phishing = sum(1 for _, t in urls if t == 'phishing')
    print(f"Mẫu từ tập gốc: {len(urls)} (Benign: {initial_benign}, Phishing: {initial_phishing})")
    
    # 2. Sinh Benign URLs (Domain-level + Subpaths)
    all_benign_domains = GLOBAL_BENIGN_DOMAINS + VN_BENIGN_DOMAINS
    added_benign = 0
    for d in all_benign_domains:
        for proto in ["https://", "http://"]:
            for p in BENIGN_PATHS:
                full_url = f"{proto}{d}{p}"
                if full_url not in seen:
                    seen.add(full_url)
                    urls.append((full_url, 'benign'))
                    added_benign += 1
                # Thêm biến thể www.
                www_url = f"{proto}www.{d}{p}"
                if www_url not in seen:
                    seen.add(www_url)
                    urls.append((www_url, 'benign'))
                    added_benign += 1
                    
    print(f"Đã bổ sung mẫu Benign chuẩn công nghiệp: {added_benign} mẫu")
    
    # 3. Sinh thêm Phishing URLs đối kháng
    added_phishing = 0
    for template in PHISHING_PATTERNS_TEMPLATE:
        for extra in ["", "/login", "/verify", "/update", "/step1", "/confirm.php", "?user=client", "?ref=sms"]:
            phish_url = f"{template}{extra}"
            if phish_url not in seen:
                seen.add(phish_url)
                urls.append((phish_url, 'phishing'))
                added_phishing += 1
                
    # Thêm biến thể phishing cho các ngân hàng với các TLD lạ
    shady_tlds = ["xyz", "top", "club", "site", "online", "cc", "vip", "cfd", "sbs", "buzz"]
    for bank in ["vietcombank", "techcombank", "mbbank", "bidv", "acb", "tpbank", "vpbank"]:
        for action in ["dangnhap", "smartotp", "ebanking", "xacthuc", "baomat", "capnhat"]:
            for tld in shady_tlds:
                p_url = f"http://{bank}-{action}.{tld}/login"
                if p_url not in seen:
                    seen.add(p_url)
                    urls.append((p_url, 'phishing'))
                    added_phishing += 1
                    
    print(f"Đã bổ sung mẫu Phishing đối kháng: {added_phishing} mẫu")
    total = len(urls)
    total_benign = sum(1 for _, t in urls if t == 'benign')
    total_phishing = sum(1 for _, t in urls if t == 'phishing')
    print(f"Tổng số mẫu tập dữ liệu mới: {total} (Benign: {total_benign}, Phishing: {total_phishing})")
    
    with open(TARGET_DATA_PATH, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["url", "type"])
        for u, t in urls:
            writer.writerow([u, t])
            
    print(f"Đã lưu tập dữ liệu URL chuẩn công nghiệp tại: {TARGET_DATA_PATH}")

if __name__ == '__main__':
    generate_industrial_dataset()

