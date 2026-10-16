import re
import logging
import urllib.parse
from typing import Set, Tuple, List, Optional

from sqlalchemy.orm import Session

from app.detector.base import RuleMatch
from app.detector.phone_utils import extract_phone_candidates
from app.models.enums import ContentType
from app.models.blacklist import Blacklist

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    def __init__(self):
        self._blacklist_domains: Set[str] = set()
        self._whitelist_domains: Set[str] = set()
        self._blacklist_phones: Set[str] = set()
        self._whitelist_phones: Set[str] = set()
        self._initialize_core_whitelists()
        self._initialize_core_blacklists()

    def _initialize_core_whitelists(self):
        core_safe_domains = {
            "google.com", "apple.com", "microsoft.com", 
            "shopee.vn", "tiki.vn", "lazada.vn",
            "vietcombank.com.vn", "bidv.com.vn", "techcombank.com.vn"
        }
        self._whitelist_domains.update(core_safe_domains)

    def _initialize_core_blacklists(self):
        core_blacklisted = {
            "musictoyourhome.com",
            "www.musictoyourhome.com",
            "pruisturin.com",
            "shoptrendr.top",
            "evn-cskh.vn",
            "vcb-digibank-login.xyz",
            "vietcornbank-ebank.xyz",
            "quatang-triandacbiet.xyz",
            "vieclam-tainha.site",
        }
        self._blacklist_domains.update(core_blacklisted)

    def add_blacklist_domain(self, domain: str):
        if domain:
            self._blacklist_domains.add(domain.lower().strip())

    def load_from_database(self, db: Session):
        """
        Nạp toàn bộ tên miền trong bảng Blacklist (SQLite) vào bộ nhớ đệm RAM để tra cứu tức thì < 0.01ms.
        """
        try:
            entries = db.query(Blacklist.value).filter(Blacklist.content_type == ContentType.URL).all()
            count = 0
            for (val,) in entries:
                if val:
                    self._blacklist_domains.add(val.lower().strip())
                    count += 1
            logger.info(f"Đã nạp {count} tên miền từ database vào bộ nhớ đệm Threat Intelligence (Tổng cộng: {len(self._blacklist_domains)}).")
        except Exception as e:
            logger.error(f"Lỗi khi nạp danh sách đen tên miền từ DB: {e}")

    def check_domain_risk(self, netloc: str) -> Tuple[bool, bool]:
        if not netloc:
            return False, False
        try:
            domain = netloc.lower().strip()
            # Bỏ tiền tố cổng (port) nếu có
            if ":" in domain:
                domain = domain.split(":")[0]

            if domain in self._whitelist_domains:
                return True, False
            if domain in self._blacklist_domains:
                logger.info(f"Blacklist hit for domain: {domain}")
                return False, True

            # Kiểm tra trường hợp tên miền phụ của tên miền trong blacklist
            if "." in domain:
                parts = domain.split(".")
                if len(parts) > 2:
                    root_domain = ".".join(parts[-2:])
                    if root_domain in self._blacklist_domains:
                        logger.info(f"Blacklist root domain hit: {root_domain} for {domain}")
                        return False, True

            return False, False
        except Exception as e:
            logger.error(f"Error checking domain risk: {str(e)}")
            return False, False


threat_intel = ThreatIntelligenceService()


def check_blacklist_phone(text: str, db: Session) -> list[RuleMatch]:
    """
    Tra cứu danh sách số điện thoại trong nội dung với bảng Blacklist (database).
    Trả về danh sách RuleMatch nếu phát hiện số điện thoại nằm trong danh sách đen.
    """
    if not text or not text.strip():
        return []

    candidates = extract_phone_candidates(text)
    if not candidates:
        return []

    entries = (
        db.query(Blacklist)
        .filter(Blacklist.content_type == ContentType.PHONE, Blacklist.value.in_(candidates))
        .all()
    )

    matches: list[RuleMatch] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.value in seen:
            continue
        seen.add(entry.value)
        explanation = f"Số điện thoại '{entry.value}' nằm trong danh sách đen cảnh báo lừa đảo."
        if entry.note:
            explanation += f" Ghi chú: {entry.note}."
        if entry.source:
            explanation += f" Nguồn: {entry.source}."

        matches.append(
            RuleMatch(
                rule_id="blacklist_phone",
                category="Số điện thoại trong danh sách đen (Đã xác minh)",
                snippet=entry.value,
                score=90,
                explanation=explanation,
            )
        )

    return matches


def check_blacklist_url(text: str, db: Optional[Session] = None) -> list[RuleMatch]:
    """
    Tra cứu tên miền / URL trong nội dung với Threat Intelligence và bảng Blacklist (database).
    Trả về danh sách RuleMatch nếu phát hiện tên miền nằm trong danh sách đen độc hại.
    """
    if not text or not text.strip():
        return []

    from app.detector.patterns.url_patterns import url_extractor
    extracted_urls = url_extractor.extract_urls(text)

    clean = text.strip().lower()
    targets = list(extracted_urls)
    if not targets:
        if re.match(r'^[a-zA-Z0-9\.\-]+$', clean) and "." in clean:
            targets.append(clean)
        elif "http://" in clean or "https://" in clean:
            targets.append(clean)

    matches: list[RuleMatch] = []
    seen: set[str] = set()

    for item in targets:
        netloc = url_extractor.extract_features(item).get("netloc", "").lower()
        if not netloc:
            clean_item = item if item.startswith(("http://", "https://")) else "http://" + item
            try:
                parsed = urllib.parse.urlparse(clean_item)
                netloc = (parsed.hostname or "").lower()
            except Exception:
                netloc = item.lower()

        if not netloc or netloc in seen:
            continue

        # 1. Đối soát Threat Intelligence Cache
        _, is_bl = threat_intel.check_domain_risk(netloc)
        if is_bl:
            seen.add(netloc)
            matches.append(
                RuleMatch(
                    rule_id="blacklist_threat_intel_domain",
                    category="Tên miền trong danh sách đen độc hại (Threat Intelligence)",
                    snippet=netloc,
                    score=95,
                    explanation=f"Tên miền '{netloc}' nằm trong cơ sở dữ liệu mối đe dọa an ninh / trang web bị chiếm quyền điều khiển (compromised) chèn mã độc lừa đảo.",
                )
            )
            continue

        # 2. Đối soát Cơ sở dữ liệu SQLite Blacklist
        if db:
            try:
                db_entry = (
                    db.query(Blacklist)
                    .filter(
                        Blacklist.content_type == ContentType.URL,
                        (Blacklist.value == netloc) | (Blacklist.value.ilike(f"%{netloc}%"))
                    )
                    .first()
                )
                if db_entry:
                    seen.add(netloc)
                    explanation = f"Tên miền/URL '{netloc}' nằm trong danh sách đen cảnh báo lừa đảo P-Sieve."
                    if db_entry.note:
                        explanation += f" Ghi chú: {db_entry.note}."
                    if db_entry.source:
                        explanation += f" Nguồn: {db_entry.source}."
                    matches.append(
                        RuleMatch(
                            rule_id="blacklist_database_url",
                            category="Liên kết / Tên miền trong danh sách đen P-Sieve",
                            snippet=netloc,
                            score=95,
                            explanation=explanation,
                        )
                    )
            except Exception as e:
                logger.error(f"Lỗi truy vấn cơ sở dữ liệu Blacklist URL: {e}")

    return matches