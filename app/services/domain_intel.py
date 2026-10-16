# File: app/services/domain_intel.py
"""
Dịch vụ Tình báo Tên miền Chuyên sâu (In-depth Domain Intelligence Engine):
1. Bóc tách tên miền theo Public Suffix List chuẩn quốc tế (tldextract: subdomain, domain, suffix).
2. Dò theo chuỗi chuyển hướng URL rút gọn đa tầng (Recursive Multi-hop Unshortener, tối đa 5 bước).
3. Truy vấn Tuổi tên miền & Ngày đăng ký qua giao thức RDAP (IETF RFC 7482) với bộ nhớ đệm Cache LRU.
   - Phát hiện tên miền lừa đảo "dùng một lần" mới đăng ký dưới 30 ngày (Disposable Phishing Domains).
"""
import ipaddress
import socket
import re
import urllib.parse
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
import httpx
import tldextract

logger = logging.getLogger(__name__)


class DomainIntelligenceEngine:
    def __init__(self):
        # Bộ nhớ đệm tra cứu RDAP (in-memory cache) tránh gửi request trùng lặp
        self._rdap_cache: Dict[str, Dict[str, Any]] = {}
        # Bộ nhớ đệm URL rút gọn
        self._unshorten_cache: Dict[str, str] = {}
        
        # Danh sách các dịch vụ rút gọn link phổ biến
        self.known_shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "page.link",
            "s.net.vn", "shorturl.at", "cutt.ly", "rebrand.ly", "gg.gg", "soo.gd",
            "v.gd", "rutgon.me", "link1s.com", "bom.so", "bom.to", "tiny.cc",
            "shortcm.li", "tny.im", "chilp.it", "clck.ru", "cutt.us"
        }
        
        # Các TLD rủi ro cao thường xuyên bị kẻ gian đăng ký nặc danh giá rẻ
        self.high_risk_tlds = {
            "top", "vip", "cc", "club", "ru", "online", "bond", "xyz", "site", "tech", "band", "me", "info", "buzz"
        }

    @staticmethod
    def is_safe_public_url(target_url: str) -> Tuple[bool, str]:
        """
        Kiểm tra và ngăn chặn lỗ hổng SSRF (Server-Side Request Forgery):
        1. Chỉ cho phép các giao thức chuẩn web: http, https.
        2. Chặn tuyệt đối loopback (127.0.0.1, ::1), IP nội bộ (10.x, 172.16.x, 192.168.x),
           Link-local (169.254.x / cloud metadata), Multicast và tên miền cục bộ (.local, .internal, .lan, localhost).
        3. Phân giải DNS và kiểm tra toàn bộ địa chỉ IP trả về.
        """
        try:
            parsed = urllib.parse.urlparse(target_url)
            scheme = (parsed.scheme or "").lower()
            if scheme not in ("http", "https"):
                return False, f"Giao thức không được hỗ trợ hoặc bị chặn: {scheme}"
            
            hostname = parsed.hostname
            if not hostname:
                return False, "URL không chứa hostname hợp lệ"
                
            hostname_lower = hostname.lower().strip()
            
            # Chặn tên miền nội bộ phổ biến
            if hostname_lower in ("localhost", "0.0.0.0") or hostname_lower.endswith((".local", ".internal", ".lan", ".corp", ".home")):
                return False, f"Hostname nội bộ bị chặn: {hostname}"

            # Phân giải DNS
            try:
                addr_info = socket.getaddrinfo(hostname_lower, None)
            except socket.gaierror:
                return False, f"Không thể phân giải tên miền: {hostname}"
            except Exception as e:
                return False, f"Lỗi DNS lookup: {e}"

            # Kiểm tra tất cả IP tương ứng
            for item in addr_info:
                ip_str = item[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_multicast
                        or ip.is_reserved
                        or ip.is_unspecified
                        or str(ip).startswith("169.254.")
                    ):
                        return False, f"Địa chỉ IP nội bộ bị chặn (SSRF Protection): {ip_str}"
                except ValueError:
                    return False, f"Địa chỉ IP không hợp lệ: {ip_str}"

            return True, "URL công khai an toàn"
        except Exception as e:
            return False, f"Lỗi xác thực URL: {e}"

    def extract_domain_parts(self, url_or_domain: str) -> Dict[str, str]:
        """
        Bóc tách chính xác tên miền theo chuẩn Public Suffix List.
        Ví dụ: 'vietteltammi.go.link' -> subdomain: 'vietteltammi', domain: 'go', suffix: 'link', registered_domain: 'go.link'
        Ví dụ: 'vietcombank-login.com.vn' -> subdomain: '', domain: 'vietcombank-login', suffix: 'com.vn', registered_domain: 'vietcombank-login.com.vn'
        """
        if not url_or_domain:
            return {"subdomain": "", "domain": "", "suffix": "", "registered_domain": ""}
        
        target = url_or_domain.strip().lower()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        try:
            ext = tldextract.extract(target)
            registered = ext.top_domain_under_public_suffix if hasattr(ext, 'top_domain_under_public_suffix') else (f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain)
            return {
                "subdomain": ext.subdomain,
                "domain": ext.domain,
                "suffix": ext.suffix,
                "registered_domain": registered or ext.domain,
            }
        except Exception as e:
            logger.error(f"Lỗi khi bóc tách tên miền với tldextract: {e}")
            parsed = urllib.parse.urlparse(target)
            netloc = parsed.netloc.split(':')[0]
            return {"subdomain": "", "domain": netloc, "suffix": "", "registered_domain": netloc}

    def resolve_multi_hop_redirects(self, url: str, max_hops: int = 5, timeout: float = 2.0) -> Tuple[str, List[str]]:
        """
        Giải mã đệ quy đa tầng các liên kết rút gọn ngụy trang (Multi-hop Unshortener) với cơ chế phòng thủ SSRF:
        1. Kiểm tra an toàn SSRF ở từng bước hop (chặn IP private/loopback, chỉ chấp nhận http/https).
        2. Dò theo chuỗi chuyển hướng HTTP (tối đa max_hops bước) để tìm ra website đích thực sự.
        """
        if not url:
            return url, []

        clean_url = url.strip()
        if clean_url in self._unshorten_cache:
            return self._unshorten_cache[clean_url], [clean_url, self._unshorten_cache[clean_url]]

        current_url = clean_url if clean_url.startswith(("http://", "https://")) else "http://" + clean_url
        
        # Kiểm tra SSRF hop đầu tiên
        is_safe, reason = self.is_safe_public_url(current_url)
        if not is_safe:
            logger.warning(f"Chặn chuyển hướng URL do nguy cơ SSRF: {current_url} ({reason})")
            return current_url, [current_url]

        redirect_chain = [current_url]
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        for hop in range(max_hops):
            try:
                with httpx.Client(follow_redirects=False, timeout=timeout, headers=headers) as client:
                    try:
                        resp = client.head(current_url)
                    except Exception:
                        resp = client.get(current_url, headers={"Range": "bytes=0-200"})

                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location")
                        if not location:
                            break
                        next_url = urllib.parse.urljoin(current_url, location)
                        # Kiểm tra an toàn SSRF trước khi theo chuyển hướng
                        is_safe_hop, hop_reason = self.is_safe_public_url(next_url)
                        if not is_safe_hop:
                            logger.warning(f"Chặn hop chuyển tiếp do nguy cơ SSRF: {next_url} ({hop_reason})")
                            break
                        if next_url in redirect_chain:
                            break
                        current_url = next_url
                        redirect_chain.append(current_url)
                    else:
                        break
            except Exception as e:
                logger.debug(f"Dừng dò chuyển hướng tại hop {hop} cho URL {current_url}: {e}")
                break

        if len(redirect_chain) > 1:
            self._unshorten_cache[clean_url] = current_url
        return current_url, redirect_chain

    def query_domain_age(self, registered_domain: str, timeout: float = 2.0) -> Dict[str, Any]:
        """
        Truy vấn Tuổi tên miền & Ngày đăng ký qua giao thức chuẩn quốc tế RDAP (IETF RFC 7482).
        Hỗ trợ tính tuổi tên miền theo số ngày (age_days) để phát hiện tên miền lừa đảo mới lập.
        """
        result = {
            "registered_date": None,
            "age_days": -1,
            "is_new_domain": False,
            "is_established": False,
            "status": "UNKNOWN",
        }
        if not registered_domain:
            return result

        domain_clean = registered_domain.lower().strip()
        if domain_clean in self._rdap_cache:
            return self._rdap_cache[domain_clean]

        # Bỏ qua truy vấn RDAP cho các domain nội bộ hoặc IP
        if domain_clean.endswith(".local") or re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_clean):
            return result

        try:
            rdap_url = f"https://rdap.org/domain/{domain_clean}"
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(rdap_url)
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    reg_date_str = None
                    for ev in events:
                        action = ev.get("eventAction", "").lower()
                        if action in ("registration", "created"):
                            reg_date_str = ev.get("eventDate")
                            break

                    if reg_date_str:
                        # Chuẩn hóa thời gian ISO
                        clean_date_str = reg_date_str.replace("Z", "+00:00")
                        reg_dt = datetime.fromisoformat(clean_date_str)
                        now_dt = datetime.now(timezone.utc)
                        age_days = (now_dt - reg_dt).days

                        result["registered_date"] = reg_dt.strftime("%Y-%m-%d")
                        result["age_days"] = max(0, age_days)
                        # Tên miền mới đăng ký dưới 30 ngày là dấu hiệu nguy cơ cao của web phishing
                        result["is_new_domain"] = age_days < 30
                        result["is_established"] = age_days > 365
                        result["status"] = "ACTIVE"
                        self._rdap_cache[domain_clean] = result
                        return result
        except Exception as e:
            logger.debug(f"RDAP query failed for {domain_clean}: {e}")

        self._rdap_cache[domain_clean] = result
        return result

    def inspect_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Giám định toàn diện tình báo tên miền của một URL:
        1. Bóc tách cấu trúc Public Suffix.
        2. Giải mã chuyển hướng rút gọn nếu có.
        3. Truy vấn tuổi tên miền và phát hiện tên miền 'dùng một lần'.
        """
        parts = self.extract_domain_parts(raw_url)
        registered_domain = parts["registered_domain"]
        suffix = parts["suffix"]
        subdomain = parts["subdomain"]

        is_shortened = registered_domain in self.known_shorteners
        final_url = raw_url
        redirect_chain = []

        if is_shortened:
            final_url, redirect_chain = self.resolve_multi_hop_redirects(raw_url)
            if final_url != raw_url:
                parts = self.extract_domain_parts(final_url)
                registered_domain = parts["registered_domain"]
                suffix = parts["suffix"]
                subdomain = parts["subdomain"]

        is_suspicious_tld = suffix in self.high_risk_tlds

        # Truy vấn tuổi tên miền nếu là TLD phổ biến
        domain_age_info = {"age_days": -1, "is_new_domain": False}
        if suffix in ("com", "net", "org", "top", "vip", "xyz", "site", "online", "cc", "link"):
            domain_age_info = self.query_domain_age(registered_domain, timeout=1.5)

        return {
            "original_url": raw_url,
            "final_url": final_url,
            "is_redirected": len(redirect_chain) > 1,
            "redirect_chain": redirect_chain,
            "subdomain": subdomain,
            "domain": parts["domain"],
            "suffix": suffix,
            "registered_domain": registered_domain,
            "is_suspicious_tld": is_suspicious_tld,
            "domain_age_days": domain_age_info.get("age_days", -1),
            "is_new_disposable_domain": domain_age_info.get("is_new_domain", False),
            "registered_date": domain_age_info.get("registered_date"),
        }


domain_intel = DomainIntelligenceEngine()
