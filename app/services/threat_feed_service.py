# File: app/services/threat_feed_service.py
"""
Dịch vụ Tự động Đồng bộ Tình báo Mối đe dọa Toàn cầu & Việt Nam (Threat Intelligence Feeds Service)
Nguồn cấp thời gian thực:
- URLhaus (Abuse.ch): Máy chủ phát tán mã độc & liên kết tấn công độc hại mới nhất
- OpenPhish: Nguồn cấp phishing URL cộng đồng cập nhật theo thời gian thực
- P-Sieve Community & National Feeds: Danh sách đen quốc gia và phản ánh cộng đồng

Cung cấp khả năng:
1. Thu thập và chuẩn hóa hàng nghìn tên miền độc hại mới mỗi chu kỳ.
2. Nạp trực tiếp vào Bộ nhớ đệm RAM (In-Memory Set O(1) < 0.01ms) của ThreatIntelligenceService.
3. Đồng bộ lưu trữ bền vững vào cơ sở dữ liệu SQLite (bảng Blacklist).
4. Khả năng tự phục hồi (Fault Tolerance / Offline Resilience) nếu mạng ngoài gián đoạn.
"""
import io
import csv
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Set, Optional

import requests
from sqlalchemy.orm import Session

from app.models.enums import ContentType
from app.models.blacklist import Blacklist
from app.services.blacklist_service import threat_intel

logger = logging.getLogger(__name__)

URLHAUS_TEXT_FEED = "https://urlhaus.abuse.ch/downloads/text/"
URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_FEED_TXT = "https://openphish.com/feed.txt"

# Fallback seeds phòng trường hợp chạy offline hoàn toàn không có internet
OFFLINE_SEED_DOMAINS = [
    ("musictoyourhome.com", "Trang web bị chiếm quyền điều khiển chèn mã độc lừa đảo (Compromised WordPress)", "ThreatIntel/OfflineSeed"),
    ("www.musictoyourhome.com", "Trang web bị chiếm quyền điều khiển chèn mã độc lừa đảo (Compromised WordPress)", "ThreatIntel/OfflineSeed"),
    ("pruisturin.com", "Tên miền phát tán mã độc & bẫy lừa đảo", "URLhaus/OfflineSeed"),
    ("shoptrendr.top", "Website thương mại điện tử giả mạo chiếm đoạt thẻ tín dụng", "OpenPhish/OfflineSeed"),
    ("evn-cskh.vn", "Mạo danh Điện lực Việt Nam EVN bẫy nộp phạt", "P-Sieve/OfflineSeed"),
    ("vcb-digibank-login.xyz", "Mạo danh ngân hàng Vietcombank Digibank", "OpenPhish/OfflineSeed"),
    ("vietcornbank-ebank.xyz", "Typosquatting Vietcombank lừa đảo Smart OTP", "OpenPhish/OfflineSeed"),
    ("quatang-triandacbiet.xyz", "Bẫy trúng thưởng xe SH trộm dữ liệu", "P-Sieve/OfflineSeed"),
    ("vieclam-tainha.site", "Bẫy tuyển dụng CTV giật đơn ảo Shopee", "P-Sieve/OfflineSeed"),
]

_LAST_SYNC_METADATA: Dict[str, Any] = {
    "last_synced_at": None,
    "last_status": "Chưa đồng bộ",
    "total_added": 0,
    "sources_synced": []
}


def clean_domain(raw_url_or_domain: str) -> Optional[str]:
    """
    Chuẩn hóa tên miền từ URL hoặc domain thô:
    - Bỏ giao thức http/https, bỏ cổng port, bỏ www (nếu cần giữ thì trả domain chuẩn)
    - Loại bỏ IP nội bộ và tên miền whitelist an toàn
    """
    if not raw_url_or_domain:
        return None
    raw = str(raw_url_or_domain).strip().lower()
    if not raw or raw.startswith("#"):
        return None

    if "://" not in raw:
        raw = "http://" + raw

    try:
        parsed = urllib.parse.urlparse(raw)
        hostname = (parsed.hostname or "").strip().lower()
    except Exception:
        hostname = ""

    if not hostname or len(hostname) < 3 or "." not in hostname:
        return None

    # Bỏ qua localhost và IP nội bộ
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0") or hostname.startswith("192.168.") or hostname.startswith("10."):
        return None

    # Không bao giờ đưa tên miền whitelist chính thống vào blacklist
    if hostname in threat_intel._whitelist_domains:
        return None

    return hostname


class ThreatFeedService:
    def __init__(self, timeout_sec: int = 12):
        self.timeout = timeout_sec

    def fetch_urlhaus_domains(self, limit: int = 500) -> List[Dict[str, str]]:
        """
        Tải và bóc tách các tên miền độc hại mới nhất từ URLhaus (Abuse.ch).
        Ưu tiên nguồn plain-text siêu tốc.
        """
        results: List[Dict[str, str]] = []
        try:
            headers = {"User-Agent": "P-Sieve-CyberShield/2.0 (Security Intelligence Scanner)"}
            resp = requests.get(URLHAUS_TEXT_FEED, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                seen: Set[str] = set()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    domain = clean_domain(line)
                    if domain and domain not in seen:
                        seen.add(domain)
                        results.append({
                            "domain": domain,
                            "note": "Phát tán mã độc / URLhaus threat feed",
                            "source": "URLhaus (Abuse.ch)"
                        })
                        if len(results) >= limit:
                            break
                logger.info(f"URLhaus text feed successfully fetched {len(results)} domains.")
                return results

            # Fallback sang CSV nếu plain-text không khả dụng
            resp = requests.get(URLHAUS_RECENT_CSV, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                lines = [l for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                reader = csv.reader(io.StringIO("\n".join(lines)))
                seen: Set[str] = set()
                for row in reader:
                    if len(row) >= 6:
                        url = row[2]
                        threat = row[5] or "malware_download"
                        domain = clean_domain(url)
                        if domain and domain not in seen:
                            seen.add(domain)
                            results.append({
                                "domain": domain,
                                "note": f"Phát tán mã độc / URLhaus threat: {threat}",
                                "source": "URLhaus (Abuse.ch)"
                            })
                            if len(results) >= limit:
                                break
                logger.info(f"URLhaus CSV feed successfully fetched {len(results)} domains.")
        except Exception as e:
            logger.warning(f"Không thể kết nối đến nguồn cấp URLhaus: {e}")

        return results

    def fetch_openphish_domains(self, limit: int = 500) -> List[Dict[str, str]]:
        """
        Tải và bóc tách các tên miền phishing đang hoạt động từ OpenPhish.
        """
        results: List[Dict[str, str]] = []
        try:
            headers = {"User-Agent": "P-Sieve-CyberShield/2.0 (Security Intelligence Scanner)"}
            resp = requests.get(OPENPHISH_FEED_TXT, headers=headers, timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning(f"OpenPhish feed responded with status {resp.status_code}")
                return results

            seen: Set[str] = set()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                domain = clean_domain(line)
                if domain and domain not in seen:
                    seen.add(domain)
                    results.append({
                        "domain": domain,
                        "note": "Trang web giả mạo / Phishing URL phát hiện bởi OpenPhish Community",
                        "source": "OpenPhish"
                    })
                    if len(results) >= limit:
                        break

            logger.info(f"OpenPhish feed successfully fetched {len(results)} domains.")
        except Exception as e:
            logger.warning(f"Không thể kết nối đến nguồn cấp OpenPhish: {e}")

        return results

    def sync_all_feeds(
        self,
        db: Session,
        limit_per_feed: int = 500,
        include_offline_seeds: bool = True
    ) -> Dict[str, Any]:
        """
        Đồng bộ toàn bộ các nguồn cấp Threat Intel:
        1. Thu thập dữ liệu từ URLhaus và OpenPhish
        2. Bổ sung các hạt giống ngoại tuyến (Offline Seeds)
        3. Cập nhật In-Memory Cache của ThreatIntelligenceService
        4. Lưu trữ vào bảng Blacklist (SQLite) nếu chưa tồn tại
        """
        global _LAST_SYNC_METADATA
        synced_sources = []
        collected_entries: List[Dict[str, str]] = []

        # 1. Thu thập từ URLhaus
        urlhaus_entries = self.fetch_urlhaus_domains(limit=limit_per_feed)
        if urlhaus_entries:
            synced_sources.append(f"URLhaus ({len(urlhaus_entries)})")
            collected_entries.extend(urlhaus_entries)

        # 2. Thu thập từ OpenPhish
        openphish_entries = self.fetch_openphish_domains(limit=limit_per_feed)
        if openphish_entries:
            synced_sources.append(f"OpenPhish ({len(openphish_entries)})")
            collected_entries.extend(openphish_entries)

        # 3. Bổ sung Offline Seeds
        if include_offline_seeds:
            for seed_domain, seed_note, seed_src in OFFLINE_SEED_DOMAINS:
                collected_entries.append({
                    "domain": seed_domain.lower().strip(),
                    "note": seed_note,
                    "source": seed_src
                })
            synced_sources.append(f"P-Sieve Core Seeds ({len(OFFLINE_SEED_DOMAINS)})")

        # 4. Cập nhật ngay vào In-Memory Threat Intel Cache (0ms latency)
        new_memory_count = 0
        for item in collected_entries:
            dom = item["domain"]
            if dom not in threat_intel._blacklist_domains:
                threat_intel.add_blacklist_domain(dom)
                new_memory_count += 1

        # 5. Lưu trữ / Upsert vào cơ sở dữ liệu SQLite Blacklist
        new_db_inserted = 0
        try:
            # Lấy tập hợp các domain đã có trong DB
            existing_db_values = {
                val[0].lower() for val in db.query(Blacklist.value)
                .filter(Blacklist.content_type == ContentType.URL)
                .all()
            }

            entries_to_add: List[Blacklist] = []
            seen_in_batch: Set[str] = set()

            for item in collected_entries:
                dom = item["domain"]
                if dom not in existing_db_values and dom not in seen_in_batch:
                    seen_in_batch.add(dom)
                    entries_to_add.append(
                        Blacklist(
                            content_type=ContentType.URL,
                            value=dom,
                            note=item["note"],
                            source=item["source"]
                        )
                    )

            if entries_to_add:
                db.bulk_save_objects(entries_to_add)
                db.commit()
                new_db_inserted = len(entries_to_add)
                logger.info(f"Đã lưu thành công {new_db_inserted} tên miền độc hại mới vào SQLite Blacklist.")

        except Exception as e:
            db.rollback()
            logger.error(f"Lỗi khi lưu Threat Feeds vào cơ sở dữ liệu: {e}")

        # 6. Cập nhật Metadata lần đồng bộ
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        _LAST_SYNC_METADATA = {
            "last_synced_at": now_str,
            "last_status": "Thành công",
            "total_added": new_db_inserted,
            "sources_synced": synced_sources
        }

        return {
            "success": True,
            "timestamp": now_str,
            "total_domains_in_memory": len(threat_intel._blacklist_domains),
            "new_db_domains_inserted": new_db_inserted,
            "new_memory_domains_added": new_memory_count,
            "sources": synced_sources,
            "message": f"Đồng bộ thành công! Hiện đang bảo vệ {len(threat_intel._blacklist_domains)} tên miền độc hại trong bộ nhớ đệm an ninh."
        }

    def get_stats(self, db: Session) -> Dict[str, Any]:
        """
        Lấy thống kê chi tiết về cơ sở dữ liệu Tình báo Mối đe dọa.
        """
        try:
            total_db_urls = db.query(Blacklist).filter(Blacklist.content_type == ContentType.URL).count()
            urlhaus_count = db.query(Blacklist).filter(
                Blacklist.content_type == ContentType.URL,
                Blacklist.source.ilike("%URLhaus%")
            ).count()
            openphish_count = db.query(Blacklist).filter(
                Blacklist.content_type == ContentType.URL,
                Blacklist.source.ilike("%OpenPhish%")
            ).count()
            custom_count = total_db_urls - urlhaus_count - openphish_count
        except Exception:
            total_db_urls = len(threat_intel._blacklist_domains)
            urlhaus_count = 0
            openphish_count = 0
            custom_count = total_db_urls

        return {
            "total_domains_in_memory": len(threat_intel._blacklist_domains),
            "total_domains_in_database": total_db_urls,
            "source_distribution": {
                "urlhaus": urlhaus_count,
                "openphish": openphish_count,
                "community_and_seeds": max(0, custom_count)
            },
            "last_sync": _LAST_SYNC_METADATA
        }


threat_feed_service = ThreatFeedService()
